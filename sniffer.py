from scapy.all import *
from odl_flow_service import ODLFlowService
from random import randint
from datetime import datetime, timedelta

#Attack sends 10 SYN/second
SYN_SEGMENT_THRESHOLD = 6
# Only care about the packets that arrived over this detection window
DETECTION_WINDOW = 1

packets = {}

def check_packet(packet):
    ip = packet.getlayer(IP).src
    current_time = datetime.now()

    if not ip in packets.keys():
        packets[ip] = {
            'syn_packet_count': 0,
            'packet_arrival_times': []
        }

    packet_dict = packets[ip]

    remove_old_packets(now = current_time, ip_address = ip)

    new_packets = packet_dict['packet_arrival_times'] + [current_time]

    set_count_and_packets(
        ip_address = ip,
        count = packet_dict['syn_packet_count'] + 1,
        new_packets = new_packets
    )

    if packet_dict['syn_packet_count'] >= SYN_SEGMENT_THRESHOLD:
        print("Detected SYN-flood attack coming from " + ip)
        print("Starting attack mitigation process...\n")
        ODLFlowService.create_block_flow(ip_to_block = ip, flow_id = str(randint(1,100)))

def remove_old_packets(now, ip_address):
    time_diff = now - timedelta(seconds = DETECTION_WINDOW)
    valid_packets = list(filter(lambda packet_arrival: packet_arrival >= time_diff, packets[ip_address]['packet_arrival_times']))

    set_count_and_packets(
        ip_address = ip_address,
        count = len(valid_packets),
        new_packets = valid_packets
    )

def set_count_and_packets(ip_address, count, new_packets):
    packets[ip_address]['syn_packet_count'] = count
    packets[ip_address]['packet_arrival_times'] = new_packets

if __name__ == '__main__':
    print("Sniffing for SYN packets...\n")
    sniff(iface = 'enp0s8', filter = 'tcp[tcpflags] & tcp-syn != 0', prn = check_packet)
