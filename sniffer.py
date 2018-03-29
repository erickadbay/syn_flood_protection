from scapy.all import *
from odl_flow_service import ODLFlowService
from random import randint

HOST_IP = '192.168.56.10'

"""
EXPERIMENTING DS FOR CHECKING HALF-OPEN CONNECTION
{
    '192.168....': {
        'half_open_connection_count': 1,
        'syn_packets':,
        'syn_ack_packets':,
        'ack_packets':
    }
}
"""

def check_packet(packet):
    ip = 'something'

    if(attacked):
        ODLFlowService.create_block_flow(odl_ip = HOST_IP, ip_address = ip, flow_id = randint(1,100))
    else:
        # add to data structure or do nothing


if __name__ == "__main__":
    sniff(iface="eth1", filter="tcp and tcp.flags.syn==1 and tcp.flags.ack==0", prn=check_packet)
