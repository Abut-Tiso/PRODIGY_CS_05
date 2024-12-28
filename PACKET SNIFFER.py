#!/usr/bin/env python
# coding: utf-8

# In[1]:


# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.

def print_hi(name):
    # Use a breakpoint in the code line below to debug your script.
    print(f'Hi, {name}') .


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    print_hi('PyCharm')

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP


def packet_callback(packet):
    """
    Callback function to process captured packets.
    Displays source and destination IPs, protocol, and payload.
    """
    if IP in packet:
        ip_layer = packet[IP]
        src_ip_addr = ip_layer.src
        dst_ip_addr = ip_layer.dst
        TCP_protocol = ip_layer.proto

        print(f"Source IP: {src_ip_addr} -> Destination IP: {dst_ip_addr}")

        # Check for TCP/UDP protocols
        if TCP_protocol == 6 and TCP in packet:  # TCP Protocol
            print(f"Protocol: TCP")vcs
            print(f"Payload: {bytes(packet[TCP].payload)}")

        elif TCP_protocol == 17 and UDP in packet:  # UDP Protocol
            print(f"Protocol: UDP")
            print(f"Payload: {bytes(packet[UDP].payload)}")

        else:
            print(f"Protocol: Other ({TCP_protocol})")

        print("-" * 50)


# Start sniffing packets
print("Packet sniffer is running... Press Ctrl+C to stop.")
sniff(prn=packet_callback, store=False)


# In[ ]:




