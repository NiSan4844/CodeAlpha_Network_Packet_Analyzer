
# Network Packet Analyzer

A simple packet sniffer tool built using Python and the Scapy library. This tool captures and analyzes network packets, displaying relevant information such as source and destination IP addresses, protocols, and payload data. The tool is intended for educational purposes and should be used ethically.

## Table of Contents

- [Overview](#overview)
- [Usage](#usage)
- [Features](#features)
- [Future Improvements](#future-improvements)

## Overview

The Packet Sniffer Tool is designed to help users understand network traffic by capturing packets that pass through a specified network interface. It utilizes the Scapy library to sniff packets and extract information such as:

- Source IP address
- Destination IP address
- Protocol type (TCP, UDP, etc.)
- Payload data (if available)

This tool is useful for educational purposes, including learning about network protocols and analyzing network behavior.

## Usage

1. **Run as Administrator**: To capture packets, run the script with administrative privileges. For Windows system, right-click on your command prompt or terminal and select "Run as administrator." For Linux system, run the python script using `sudo` command.

2. **Specify Network Interface**: You can capture packets on a specific interface by modifying the `network_interface` variable in the script. List available interfaces using Scapy with the following command:

   ```python
   from scapy.all import get_if_list
   print(get_if_list())
   ```

3. **Execute the Script**: Run the packet sniffer script using Python:

   ```bash
   python packet_sniffer.py
   ```
4. **Stop the Sniffer**: Press the `Esc` key to stop the packet sniffer.

5. **Captured PCAP File**: After stopping, the captured traffic will be saved into a `captured_traffic.pcap` file in the same directory.

6. **View Output**: The tool will display captured packet information in the console.

## Features

- Capture and analyze network packets in real time.
- Display source and destination IP addresses.
- Identify protocol types (TCP, UDP, etc.).
- Preview payload data when available.
- Save captured traffic to a PCAP file for later analysis.
- Stop packet capturing using the `Esc` key.

## Future Improvements

- **Logging**: Implement more advanced logging functionality to save and organize captured packets for easier analysis.
- **GUI**: Develop a graphical user interface (GUI) for better usability.
- **Advanced Filtering**: Add options for advanced filtering based on specific protocols, ports, or IP addresses.
- **Multi-threading**: Optimize the packet capturing process by implementing multi-threading for improved performance.
- **Visualization**: Integrate data visualization tools to graphically represent captured traffic.
