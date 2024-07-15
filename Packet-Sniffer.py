from scapy.all import sniff, IP, TCP, UDP  # type: ignore # Import necessary functions and classes from scapy for packet capturing and analysis
from datetime import datetime  # Import datetime module to get current timestamps

def packet_callback(packet):
    timestp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')  # Get the current timestamp in a readable format
    if IP in packet:  # Check if the packet contains an IP layer
        ip_src = packet[IP].src  # Extract the source IP address
        ip_dst = packet[IP].dst  # Extract the destination IP address

        prot = ''  # Initialize the protocol string
        ports = ''  # Initialize the ports string

        if TCP in packet:  # Check if the packet contains a TCP layer
            tcp_src_port = packet[TCP].sport  # Extract the TCP source port
            tcp_dst_port = packet[TCP].dport  # Extract the TCP destination port
            if tcp_dst_port == 80 or tcp_src_port == 80:  # Check if the port is HTTP (port 80)
                prot = "HTTP"
            elif tcp_dst_port == 443 or tcp_src_port == 443:  # Check if the port is HTTPS (port 443)
                prot = "HTTPS"
            elif tcp_dst_port == 21 or tcp_src_port == 21:  # Check if the port is FTP (port 21)
                prot = "FTP"
            ports = f"src port: {tcp_src_port} -> dest port: {tcp_dst_port}"  # Format the ports string for TCP

        elif UDP in packet:  # Check if the packet contains a UDP layer
            udp_src_port = packet[UDP].sport  # Extract the UDP source port
            udp_dst_port = packet[UDP].dport  # Extract the UDP destination port
            if udp_dst_port == 53 or udp_src_port == 53:  # Check if the port is DNS (port 53)
                prot = 'DNS'
            ports = f"src port: {udp_src_port} -> dst port: {udp_dst_port}"  # Format the ports string for UDP
        
        if prot:  # If a protocol was identified
            print(f"[{timestp}] {prot} IP src {ip_src} -> dst {ip_dst} ({ports})")  # Print the packet details with protocol
        else:
            print(f"[{timestp}] IP src {ip_src} -> dst {ip_dst}")  # Print the packet details without protocol

def main():
    print("Starting network sniffer...")  # Print a starting message
    sniff(filter="ip", prn=packet_callback, store=0)  # Start sniffing packets with a filter for IP packets and call packet_callback for each packet

if __name__ == "__main__":
    main()  # Call the main function to start the sniffer if this script is run directly
