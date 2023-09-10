import socket
import struct

def parse_ethernet_header(data):
    dest_mac, src_mac, eth_proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(eth_proto), data[14:]

def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

def parse_ip_header(data):
    version_and_header_length = data[0]
    version = version_and_header_length >> 4
    header_length = (version_and_header_length & 0xF) * 4 
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, get_ip(src), get_ip(target), data[header_length:]

def get_ip(ip_bytes):
    return '.'.join(map(str, ip_bytes))

def parse_tcp_header(data):
    src_port, dest_port, sequence, ack, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4 
    flags = offset_reserved_flags & 0x1FF
    return src_port, dest_port, sequence, ack, flags, data[offset:]

def convert_to_english(data):
    try:
        # Attempt to decode the binary data as ASCII
        english_text = data.decode('ascii')
        return english_text
    except UnicodeDecodeError:
        # If decoding as ASCII fails, return a placeholder or handle the error as needed
        return "Unable to decode as ASCII"

def write_to_file(packet_info, english_text, output_file):
    with open(output_file, 'a') as file:
        file.write(packet_info + '\n')  # Write packet info (connection ports and IP addresses)
        file.write(english_text + '\n')  # Write data to the file

def sniff_packets(interface, output_file):
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))  # ETH_P_ALL
    sock.bind((interface, 0)) 

    try:
        while True:
            raw_data, _ = sock.recvfrom(65535)
            dest_mac, src_mac, eth_proto, data = parse_ethernet_header(raw_data)
    
            if eth_proto == 8:  # IPv4
                version, header_length, ttl, proto, src_ip, dest_ip, data = parse_ip_header(data)

                if proto == 6:  # TCP
                    src_port, dest_port, sequence, ack, flags, data = parse_tcp_header(data)
                    
                    # Convert binary data to English assuming it's ASCII
                    english_text = convert_to_english(data)
                    
                    # Create packet info string
                    packet_info = f"Source IP: {src_ip}, Destination IP: {dest_ip}, Source Port: {src_port}, Destination Port: {dest_port}"
                    
                    # Write packet info and English text to the output file
                    write_to_file(packet_info, english_text, output_file)

    except KeyboardInterrupt:
        print("Packet sniffer stopped.")

if __name__ == "__main__":
    interface = "enp0s1"  # Change this to your network interface
    output_file = "output.txt"  # Change this to the desired output file
    sniff_packets(interface, output_file)

