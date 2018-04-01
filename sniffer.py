from scapy.all import *
from odl_flow_service import ODLFlowService
from random import randint
from datetime import datetime, timedelta

HOST_IP = '192.168.56.10'
#Attack sends 10 SYN/second
SYN_SEGMENT_THRESHOLD = 6
# Only care about the packets that arrived a second ago
DETECTION_WINDOW = 1

# EXPERIMENTING DS FOR CHECKING HALF-OPEN CONNECTION
# {
#     '192.168....': {
#         'syn_packet_count': 1,
#         'packet_arrival_times' = [
#             pkt1,
#             pkt2
#         ]
#     }
# }

packets = {}

def check_packet(packet):
    ip = packet.src
    current_time = datetime.now()

    if not ip in packets.keys():
        packets[ip] = {
            'syn_packet_count': 0,
            'packet_arrival_times': []
        }

    remove_old_packets(now = current_time, ip_address = ip)

    #increment syn packet count and set last packet at
    packets[ip]['syn_packet_count'] += 1

    #add packet to list of packet_arrival_times
    packets[ip]['packet_arrival_times'].append(current_time)

    if packets[ip]['syn_packet_count'] >= SYN_SEGMENT_THRESHOLD:
        ODLFlowService.create_block_flow(odl_ip = HOST_IP, ip_to_block = ip, flow_id = randint(1,100))

def remove_old_packets(now, ip_address):
    time_diff = now - timedelta(seconds=DETECTION_WINDOW)

    valid_packets = list(filter(lambda packet_arrival: packet_arrival >= time_diff, packets[ip_address]['packet_arrival_times']))

    packets[ip_address]['syn_packet_count'] = len(valid_packets)
    packets[ip_address]['packet_arrival_times'] = valid_packets

if __name__ == "__main__":
    sniff(iface="enp0s8", filter="tcp[tcpflags] & tcp-syn != 0", prn=check_packet)
