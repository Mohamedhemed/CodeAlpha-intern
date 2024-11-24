###############################################################################################################

#                                          Created Mohamed Ahmed Hamed

###############################################################################################################

import socket
import struct
import textwrap

def format_data(data):
    """Format raw binary data into readable hex format."""
    return '\n'.join(textwrap.wrap(data.hex(), width=32))

def unpack_ipv4_packet(data):
    """Unpack an IPv4 packet."""
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('!8xBB2x4s4s', data[:20])
    src = get_ip_addr(src)
    target = get_ip_addr(target)
    payload = data[header_length:]
    return version, header_length, ttl, proto, src, target, payload

def get_ip_addr(addr):
    """Convert a packed IPv4 address to a readable string."""
    return '.'.join(map(str, addr))

def unpack_tcp_segment(data):
    """Unpack a TCP segment."""
    src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack('!HHLLH', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    return src_port, dest_port, sequence, acknowledgment, offset, data[offset:]

def main():
    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        conn.bind(("0.0.0.0", 0))  # Listen to all incoming traffic
        conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        # Enable promiscuous mode (Windows only, use different approach for Linux)
        if hasattr(socket, 'SIO_RCVALL'):
            conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

        while True:
            raw_data, addr = conn.recvfrom(65536)
            print(f"\nRaw Data:\n{format_data(raw_data)}")
            version, header_length, ttl, proto, src, target, payload = unpack_ipv4_packet(raw_data)
            print(f"IPv4 Packet:\nVersion: {version}, Header Length: {header_length}, TTL: {ttl}")
            print(f"Protocol: {proto}, Source: {src}, Target: {target}")
            
            if proto == 6:  # TCP Protocol
                src_port, dest_port, sequence, acknowledgment, offset, data = unpack_tcp_segment(payload)
                print(f"TCP Segment:\nSource Port: {src_port}, Destination Port: {dest_port}")
                print(f"Sequence: {sequence}, Acknowledgment: {acknowledgment}")

    except PermissionError:
        print("[Error] Permission denied: Run the script as an Administrator or with root privileges.")
    except KeyboardInterrupt:
        print("\nStopping packet sniffing...")
    finally:
        try:
            if 'conn' in locals():
                if hasattr(socket, 'SIO_RCVALL'):
                    conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        except Exception as e:
            print(f"Error while disabling promiscuous mode: {e}")

if __name__ == "__main__":
    main()
