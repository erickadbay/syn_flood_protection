from scapy.all import *

sniff(iface="eth1", filter="tcp and tcp.flags.syn==1 and tcp.flags.ack==0")
