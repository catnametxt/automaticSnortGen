# This program should look at a PCAP and identify packet numbers to be converted into SNORT rules

# USAGE: python3 identify_suspicious_packets.py --pcap example-01.pcap

### RESOURCES ###
# https://github.com/nccgroup/IP-reputation-snort-rule-generator - WRITTEN IN PERL
# https://vnetman.github.io/pcap/python/pyshark/scapy/libpcap/2018/10/25/analyzing-packet-captures-with-python-part-1.html - FOR PARSING IN PCAP - HTTP/TCP IDENTIFY

# Elements to parse include
# 1. DNS-Query for a Domain (NCC: uses LOCAL_FILE, storing malicious domains, IPs, and URLs - https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist)
# 2. HTTP request to a specific domain (NCC: uses txt file of bad domains - http://doc.emergingthreats.net/pub/Main/RussianBusinessNetwork/Storm_2_domain_objects_3-11-2011.txt)

# creates statically based on domains in that list - could do if domain traffic includes one off this list, then flag packet

# CURRENT PROGRESS: PARSES PCAP INTO...
# [DIR FLAG] [ORDINAL NUMBER] [TIMESTAMP] [TCP FLAG] [RELATIVE ACK] [TCP PAYLOAD LENGTH]

# THEREFORE, CURRENT CAPABILITY...
# Identify IPv4/HTTP Connections  ->  GET ORDINAL NUMBER    ->   SNORT RULE (Only REQUESTS supported)
# Identify TCP  Connections       ->  GET ORDINAL NUMBER    ->   SNORT RULE 

# CAPABILITY TO IMPLEMENT...
# TCP
# DNS
# DNSQR (query)
# DNSRR (response)
# UDP
# ICMP

import argparse
import os
import sys
import time
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP

class PktDirection(Enum):
    not_defined = 0
    client_to_server = 1
    server_to_client = 2

def printable_timestamp(ts, resol):
    ts_sec = ts // resol
    ts_subsec = ts % resol
    ts_sec_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts_sec))
    return '{}.{}'.format(ts_sec_str, ts_subsec)
    
def apply_server_client_filter_IPv4_TCP(file_name):
    client = '192.168.1.137:57080'
    server = '152.19.134.43:80'

    (client_ip, client_port) = client.split(':')
    (server_ip, server_port) = server.split(':')
    
    count = 0
    interesting_packet_count = 0
    
    server_sequence_offset = None
    client_sequence_offset = None

    for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):
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
            break
        
        tcp_payload_len = ip_pkt.len - (ip_pkt.ihl * 4) - (tcp_pkt.dataofs * 4)

        # Print
        fmt = '[{ordnl:>5}]{ts:>10.6f}s flag={flag:<3s} seq={seq:<9d} \
        ack={ack:<9d} len={len:<6d}'
        if direction == PktDirection.client_to_server:
            fmt = '{arrow}' + fmt
            arr = '-->'
        else:
            fmt = '{arrow:>69}' + fmt
            arr = '<--'

        print(fmt.format(arrow = arr,
                         ordnl = last_pkt_ordinal,
                         ts = this_pkt_relative_timestamp / pkt_metadata.tsresol,
                         flag = str(tcp_pkt.flags),
                         seq = relative_offset_seq,
                         ack = relative_offset_ack,
                         len = tcp_payload_len))
    #---

    print('{} contains {} packets ({} interesting)'.
          format(file_name, count, interesting_packet_count))
    
    print('First packet in connection: Packet #{} {}'.
          format(first_pkt_ordinal,
                 printable_timestamp(first_pkt_timestamp,
                                     first_pkt_timestamp_resolution)))
    print(' Last packet in connection: Packet #{} {}'.
          format(last_pkt_ordinal,
                 printable_timestamp(last_pkt_timestamp,
                                     last_pkt_timestamp_resolution)))
#---

def apply_IPv4_TCP_filter(file_name):

    count = 0
    interesting_packet_count = 0
    
    for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):
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

        interesting_packet_count += 1

    print('{} contains {} packets ({} interesting)'.
          format(file_name, count, interesting_packet_count))

def count_number_of_packets(file_name):

    count = 0
    for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):
        count += 1

    print('{} contains {} packets'.format(file_name, count))

def process_pcap(file_name):
    print('Opening {}...'.format(file_name))

# main takes PCAP and calls process_pcap 
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PCAP reader')
    parser.add_argument('--pcap', metavar='<pcap file name>',
                        help='pcap file to parse', required=True)
    args = parser.parse_args()
    
    file_name = args.pcap
    if not os.path.isfile(file_name):
        print('"{}" does not exist'.format(file_name), file=sys.stderr)
        sys.exit(-1)

    process_pcap(file_name)
    sys.exit(0)