import socket
import struct
import io

def packet_sniffer(interface):
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)) as sock:
        sock.bind(interface)
        while True:
            packet = sock.recvfrom(65535)
            data = packet[0]
            eth_header = data[:14]
            ip_header = data[14:34]
            tcp_header = data[34:48]

            src_mac = struct.unpack("!6B", eth_header[:6])
            dst_mac = struct.unpack("!6B", eth_header[6:])
            src_ip = struct.unpack("!4B", ip_header[:4])
            dst_ip = struct.unpack("!4B", ip_header[4:])
            src_port = struct.unpack("!H", tcp_header[:2])
            dst_port = struct.unpack("!H", tcp_header[2:])

            print("Source MAC: %s" % src_mac)
            print("Destination MAC: %s" % dst_mac)
            print("Source IP: %s" % src_ip)
            print("Destination IP: %s" % dst_ip)
            print("Source Port: %d" % src_port)
            print("Destination Port: %d" % dst_port)

if __name__ == "__main__":
    interface = "eth0"
    packet_sniffer(interface)
