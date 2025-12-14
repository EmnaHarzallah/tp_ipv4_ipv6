
from scapy.all import *
import datetime

ipv4_dst = "8.8.8.8"                 # IPv4 Google DNS
ipv6_dst = "2001:4860:4860::8888"    # IPv6 Google DNS

ipv4_packet = IP(dst=ipv4_dst)/ICMP()
ipv6_packet = IPv6(dst=ipv6_dst)/ICMPv6EchoRequest()

print("===== IPv4 Packet =====")
ipv4_packet.show()
print("\n===== IPv6 Packet =====")
ipv6_packet.show()

print("\nEnvoi des paquets...")
send(ipv4_packet)
send(ipv6_packet)

print("\nCapture de paquets...")
capture_ipv4 = sniff(filter="ip", count=5, timeout=10)
capture_ipv6 = sniff(filter="ip6", count=5, timeout=10)

timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
ipv4_file = f"capture_ipv4_{timestamp}.pcap"
ipv6_file = f"capture_ipv6_{timestamp}.pcap"

wrpcap(ipv4_file, capture_ipv4)
wrpcap(ipv6_file, capture_ipv6)

print(f"\nCaptures sauvegardées : {ipv4_file}, {ipv6_file}")

print("\nAnalyse rapide des paquets capturés (IPv4) :")
for pkt in capture_ipv4:
    if IP in pkt:
        print(f"Source: {pkt[IP].src}, Destination: {pkt[IP].dst}, TTL: {pkt[IP].ttl}, Protocol: {pkt[IP].proto}")

print("\nAnalyse rapide des paquets capturés (IPv6) :")
for pkt in capture_ipv6:
    if IPv6 in pkt:
        print(f"Source: {pkt[IPv6].src}, Destination: {pkt[IPv6].dst}, Hop Limit: {pkt[IPv6].hlim}, Next Header: {pkt[IPv6].nh}")
