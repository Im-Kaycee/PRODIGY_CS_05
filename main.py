import socket
import struct

# Create a raw socket
conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
conn.bind(("192.168.33.115", 0))  # Replace with your actual IP address
conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# For Windows, enable promiscuous mode
import os
if os.name == 'nt':
    conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

def ip_unpack(data):
    """Unpack the IP packet."""
    ip_header = data[:20]
    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
    
    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = (version_ihl & 0xF) * 4
    ttl = iph[5]
    proto = iph[6]
    src_ip = socket.inet_ntoa(iph[8])
    dst_ip = socket.inet_ntoa(iph[9])
    
    return version, ihl, ttl, proto, src_ip, dst_ip, data[ihl:]

def tcp_unpack(data):
    """Unpack the TCP segment."""
    tcp_header = data[:20]
    tcph = struct.unpack('!HHLLBBHHH', tcp_header)
    
    src_port = tcph[0]
    dst_port = tcph[1]
    sequence = tcph[2]
    acknowledgment = tcph[3]
    doff_reserved = tcph[4]
    tcph_length = doff_reserved >> 4
    
    return src_port, dst_port, sequence, acknowledgment, data[tcph_length * 4:]

def udp_unpack(data):
    """Unpack the UDP datagram."""
    udp_header = data[:8]
    udph = struct.unpack('!HHHH', udp_header)
    
    src_port = udph[0]
    dst_port = udph[1]
    length = udph[2]
    
    return src_port, dst_port, length, data[8:]
def format_payload(payload):
    """Attempt to decode the payload to a human-readable string."""
    try:
        return payload.decode('utf-8')
    except UnicodeDecodeError:
        # If decoding fails, return a hex representation
        return payload.hex()


while True:
    # Capture a packet
    raw_data, addr = conn.recvfrom(65536)
    
    # Unpack IP packet
    version, ihl, ttl, proto, src_ip, dst_ip, data = ip_unpack(raw_data)
    
    print(f"\nIP Packet - Version: {version}, Header Length: {ihl}, TTL: {ttl}")
    print(f"Protocol: {proto}, Source IP: {src_ip}, Destination IP: {dst_ip}")

    # Check the protocol
    if proto == 6:  # TCP
        src_port, dst_port, sequence, acknowledgment, data = tcp_unpack(data)
        print(f"TCP Segment - Source Port: {src_port}, Destination Port: {dst_port}")
        print(f"Sequence: {sequence}, Acknowledgment: {acknowledgment}")
        print(f"Payload: {data[:20]}")  # Show first 20 bytes of the payload

    elif proto == 17:  # UDP
        src_port, dst_port, length, data = udp_unpack(data)
        print(f"UDP Datagram - Source Port: {src_port}, Destination Port: {dst_port}, Length: {length}")
        readable_payload = format_payload(data)
        print(f"Payload: {readable_payload}")  # Show first 20 bytes of the payload

    else:
        print(f"Other Protocol {proto} - Data: {data[:20]}")  # For protocols other than TCP/UDP
