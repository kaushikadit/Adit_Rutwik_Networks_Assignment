import dpkt
import socket

def get_connection_ports(pcap_file, target_ip):
    connection_ports = set()  # Use a set to store unique port numbers

    with open(pcap_file, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)

        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data

            # Check if the packet contains IP data and the source or destination IP matches the target IP
            if isinstance(ip, dpkt.ip.IP) and (socket.inet_ntoa(ip.src) == target_ip or socket.inet_ntoa(ip.dst) == target_ip):
                if isinstance(ip.data, dpkt.tcp.TCP):
                    connection_ports.add(ip.data.dport)
                    connection_ports.add(ip.data.sport)

    return connection_ports

if __name__ == "__main__":
    pcap_file = "3.pcap"  # Replace with the path to your pcap file
    target_ip = "131.144.126.118"     # The IP address of the device
    ports = get_connection_ports(pcap_file, target_ip)
    print(ports)
