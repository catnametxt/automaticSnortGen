# Run via 
    # 1. pcap-s.py pickle --pcap example-01.pcap --out example-01.dat
    # 2. pcap-s.py analyze --in example-01.dat


# WARNING
# It is possible to construct malicious pickle data which will execute arbitrary code during unpickling. Never unpickle data that could have come from an untrusted source, or that could have been tampered with.

# Consider signing data with hmac if you need to ensure that it has not been tampered with.

# Safer serialisation: json

from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
import time

def printable_timestamp(ts, resol):
    ts_sec = ts // resol
    ts_subsec = ts % resol
    ts_sec_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts_sec))
    return '{}.{}'.format(ts_sec_str, ts_subsec)

class PktDirection(Enum):
    not_defined = 0
    client_to_server = 1
    server_to_client = 2

def pickle_pcap(pcap_file_in, pickle_file_out):
    print('Processing {}...'.format(pcap_file_in))

    client = '192.168.1.137:57080'
    server = '152.19.134.43:80'

    (client_ip, client_port) = client.split(':')
    (server_ip, server_port) = server.split(':')
    
    count = 0
    interesting_packet_count = 0
    
    server_sequence_offset = None
    client_sequence_offset = None

    # List of interesting packets, will finally be pickled.
    # Each element of the list is a dictionary that contains fields of interest
    # from the packet.
    packets_for_analysis = []

    client_recv_window_scale = 0
    server_recv_window_scale = 0

    for (pkt_data, pkt_metadata,) in RawPcapReader(pcap_file_in):
        count += 1

        ether_pkt = Ether(pkt_data)
        if 'type' not in ether_pkt.fields:
            # LLC frames will have 'len' instead of 'type'.
            # We disregard those
            continue

        if ether_pkt.type != 0x0800:
            # disregard non-IPv4 packets
            continue

        ip_pkt = ether_pkt[IP]
        
        if ip_pkt.proto != 6:
            # Ignore non-TCP packet
            continue
        
        tcp_pkt = ip_pkt[TCP]

        direction = PktDirection.not_defined
        
        if ip_pkt.src == client_ip:
            if tcp_pkt.sport != int(client_port):
                continue
            if ip_pkt.dst != server_ip:
                continue
            if tcp_pkt.dport != int(server_port):
                continue
            direction = PktDirection.client_to_server
        elif ip_pkt.src == server_ip:
            if tcp_pkt.sport != int(server_port):
                continue
            if ip_pkt.dst != client_ip:
                continue
            if tcp_pkt.dport != int(client_port):
                continue
            direction = PktDirection.server_to_client
        else:
            continue
        
        interesting_packet_count += 1
        if interesting_packet_count == 1:
            first_pkt_timestamp = (pkt_metadata.tshigh << 32) | pkt_metadata.tslow
            first_pkt_timestamp_resolution = pkt_metadata.tsresol
            first_pkt_ordinal = count

        last_pkt_timestamp = (pkt_metadata.tshigh << 32) | pkt_metadata.tslow
        last_pkt_timestamp_resolution = pkt_metadata.tsresol
        last_pkt_ordinal = count

        this_pkt_relative_timestamp = last_pkt_timestamp - first_pkt_timestamp

        if direction == PktDirection.client_to_server:
            if client_sequence_offset is None:
                client_sequence_offset = tcp_pkt.seq
            relative_offset_seq = tcp_pkt.seq - client_sequence_offset
        else:
            assert direction == PktDirection.server_to_client
            if server_sequence_offset is None:
                server_sequence_offset = tcp_pkt.seq
            relative_offset_seq = tcp_pkt.seq - server_sequence_offset

        # If this TCP packet has the Ack bit set, then it must carry an ack
        # number.
        if 'A' not in str(tcp_pkt.flags):
            relative_offset_ack = 0
        else:
            if direction == PktDirection.client_to_server:
                relative_offset_ack = tcp_pkt.ack - server_sequence_offset
            else:
                relative_offset_ack = tcp_pkt.ack - client_sequence_offset

        # Determine the TCP payload length. IP fragmentation will mess up this
        # logic, so first check that this is an unfragmented packet
        if (ip_pkt.flags == 'MF') or (ip_pkt.frag != 0):
            print('No support for fragmented IP packets')
            return False
        
        tcp_payload_len = ip_pkt.len - (ip_pkt.ihl * 4) - (tcp_pkt.dataofs * 4)

        # Look for the 'Window Scale' TCP option if this is a SYN or SYN-ACK
        # packet.
        if 'S' in str(tcp_pkt.flags):
            for (opt_name, opt_value,) in tcp_pkt.options:
                if opt_name == 'WScale':
                    if direction == PktDirection.client_to_server:
                        client_recv_window_scale = opt_value
                    else:
                        server_recv_window_scale = opt_value
                    break

        # Create a dictionary and populate it with data that we'll need in the
        # analysis phase.
        
        pkt_data = {}
        pkt_data['direction'] = direction
        pkt_data['ordinal'] = last_pkt_ordinal
        pkt_data['relative_timestamp'] = this_pkt_relative_timestamp / \
                                         pkt_metadata.tsresol
        pkt_data['tcp_flags'] = str(tcp_pkt.flags)
        pkt_data['seqno'] = relative_offset_seq
        pkt_data['ackno'] = relative_offset_ack
        pkt_data['tcp_payload_len'] = tcp_payload_len
        if direction == PktDirection.client_to_server:
            pkt_data['window'] = tcp_pkt.window << client_recv_window_scale
        else:
            pkt_data['window'] = tcp_pkt.window << server_recv_window_scale

        packets_for_analysis.append(pkt_data)
    #---

    print('{} contains {} packets ({} interesting)'.
          format(pcap_file_in, count, interesting_packet_count))
    
    print('First packet in connection: Packet #{} {}'.
          format(first_pkt_ordinal,
                 printable_timestamp(first_pkt_timestamp,
                                     first_pkt_timestamp_resolution)))
    print(' Last packet in connection: Packet #{} {}'.
          format(last_pkt_ordinal,
                 printable_timestamp(last_pkt_timestamp,
                                     last_pkt_timestamp_resolution)))

    print('Writing pickle file {}...'.format(pickle_file_out), end='')
    with open(pickle_file_out, 'wb') as pickle_fd:
        pickle.dump(client, pickle_fd)
        pickle.dump(server, pickle_fd)
        pickle.dump(packets_for_analysis, pickle_fd)
    print('done.')
        
#---

def analyze_pickle(pickle_file_in):

    packets_for_analysis = []
    
    with open(pickle_file_in, 'rb') as pickle_fd:
        client_ip_addr_port = pickle.load(pickle_fd)
        server_ip_addr_port = pickle.load(pickle_fd)
        packets_for_analysis = pickle.load(pickle_fd)

    # Print a header
    print('##################################################################')
    print('TCP session between client {} and server {}'.
          format(client_ip_addr_port, server_ip_addr_port))
    print('##################################################################')
        
    # Print format string
    fmt = ('[{ordnl:>5}]{ts:>10.6f}s {flag:<3s} seq={seq:<8d} '
           'ack={ack:<8d} len={len:<6d} win={win:<9d}')

    for pkt_data in packets_for_analysis:

        direction = pkt_data['direction']

        if direction == PktDirection.client_to_server:
            print('{}'.format('-->'), end='')
        else:
            print('{:>60}'.format('<--'), end='')

        print(fmt.format(ordnl = pkt_data['ordinal'],
                         ts = pkt_data['relative_timestamp'],
                         flag = pkt_data['tcp_flags'],
                         seq = pkt_data['seqno'],
                         ack = pkt_data['ackno'],
                         len = pkt_data['tcp_payload_len'],
                         win = pkt_data['window']))