from scapy.all import sniff, IP, TCP, UDP, Raw, wrpcap
import os
import threading
from pynput import keyboard 

# List to store captured packets for logging
captured_packets = []
stop_sniffer = False  # Flag to control the sniffer

# Function to process packets
def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto
        
        # Determine if the packet is TCP or UDP and get additional information
        if packet.haslayer(TCP):
            protocol_name = "TCP"
            payload = packet[TCP].payload
        elif packet.haslayer(UDP):
            protocol_name = "UDP"
            payload = packet[UDP].payload
        else:
            protocol_name = "Other"
            payload = None
        
        # Display captured packet information
        print(f"Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {protocol_name}")
        
        # Print payload data if available
        if payload and Raw in payload:
            print(f"Payload Data: {payload[Raw].load.decode(errors='ignore')}")
        print("-" * 50)
        
        # Append packet to the list for saving later
        captured_packets.append(packet)

# Function to run the sniffer in a thread
def sniff_packets(interface=None):
    global stop_sniffer
    while not stop_sniffer:
        sniff(iface=interface, prn=packet_callback, filter="ip", store=0, timeout=1)  # Timeout to check for stop flag

# Function to monitor keyboard input for stopping the sniffer
def on_press(key):
    global stop_sniffer
    try:
        if key == keyboard.Key.esc:  # Check if 'Esc' key is pressed
            print("Esc key pressed, stopping the sniffer...")
            stop_sniffer = True
            return False  # Stop the listener
    except AttributeError:
        pass

# Main function to start the sniffer and handle stopping with Esc
def start_sniffer(interface=None, output_file="captured_traffic.pcap"):
    global stop_sniffer
    stop_sniffer = False

    # Start packet sniffer in a separate thread
    sniffer_thread = threading.Thread(target=sniff_packets, args=(interface,))
    sniffer_thread.start()

    # Start monitoring the keyboard for 'Esc' key press
    with keyboard.Listener(on_press=on_press) as listener:
        listener.join()  # Wait until the 'Esc' key is pressed

    # Wait for the sniffer thread to finish
    sniffer_thread.join()

    # Log captured packets into a PCAP file after sniffing
    if captured_packets:
        print(f"Saving captured packets to {output_file}")
        wrpcap(output_file, captured_packets)
    else:
        print("No packets captured to save.")

if __name__ == "__main__":
    # You can specify the network interface if needed
    network_interface = None  # e.g., 'eth0' or 'wlan0'
    output_pcap_file = "captured_traffic.pcap"  # Specify the output PCAP file name
    
    # Ensure the script runs with sufficient privileges
    if os.geteuid() != 0:
        print("This script requires root privileges. Please run it with sudo.")
    else:
        start_sniffer(network_interface, output_pcap_file)
