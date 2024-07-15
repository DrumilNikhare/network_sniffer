import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP

def scan_network(ip_range):
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    devices = []
    for sent, received in answered_list:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    
    return devices

def packet_sniffer(packet):
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        print(f"Source IP: {ip_layer.src} -> Destination IP: {ip_layer.dst}")
    if packet.haslayer(TCP):
        tcp_layer = packet.getlayer(TCP)
        print(f"Source Port: {tcp_layer.sport} -> Destination Port: {tcp_layer.dport}")
    elif packet.haslayer(UDP):
        udp_layer = packet.getlayer(UDP)
        print(f"Source Port: {udp_layer.sport} -> Destination Port: {udp_layer.dport}")

if __name__ == "__main__":
    # Replace with your network range
    ip_range = "192.168.1.1/24"
    devices = scan_network(ip_range)
    for device in devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}")
    
    # List available network interfaces
    interfaces = scapy.get_if_list()
    print("Available network interfaces:")
    for iface in interfaces:
        print(iface)
    
    # Use the correct network interface
    interface = "Ethernet"  # Replace with your actual interface name from the list above
    
    print("\nStarting packet sniffer on interface:", interface)
    scapy.sniff(iface=interface, prn=packet_sniffer, count=10)
