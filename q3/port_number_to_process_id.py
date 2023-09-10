import socket
import struct
import subprocess
import time

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

def get_process_id_by_port(port):
    try:
        # Use the 'lsof' command to list open files and processes associated with the given port
        lsof_output = subprocess.check_output(["lsof", "-i", f"TCP:{port}"]).decode("utf-8")
        lines = lsof_output.strip().split("\n")[1:]

        for line in lines:
            parts = line.split()
            if len(parts) >= 2:
                process_info = parts[1]
                return process_info
    except subprocess.CalledProcessError:
        pass

    return None

def sniff_packets(interface, duration=30):
    start_time = time.time()
    end_time = start_time + duration
    ports = set()

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))  # ETH_P_ALL
    sock.bind((interface, 0))

    try:
        while time.time() < end_time:
            raw_data, _ = sock.recvfrom(65535)
            dest_mac, src_mac, eth_proto, data = parse_ethernet_header(raw_data)

            if eth_proto == 8:  # IPv4
                version, header_length, ttl, proto, src_ip, dest_ip, data = parse_ip_header(data)

                if proto == 6:  # TCP
                    src_port, dest_port, sequence, ack, flags, data = parse_tcp_header(data)
                    ports.add(dest_port)

        print("Available ports:")
        for port in ports:
            print(port)

        while True:
            user_port = input("Enter a port number (Ctrl+C to exit): ")
            if not user_port:
                continue

            try:
                user_port = int(user_port)
            except ValueError:
                print("Invalid port number. Please enter a valid port number.")
                continue

            process_info = get_process_id_by_port(user_port)
            if process_info:
                print(f"Process info for port {user_port}: {process_info}")
            else:
                print(f"No process found for port {user_port}.")

    except KeyboardInterrupt:
        print("\nPacket sniffer stopped.")

if __name__ == "__main__":
    interface = "enp0s1"  # Change this to your network interface
    sniff_packets(interface)

