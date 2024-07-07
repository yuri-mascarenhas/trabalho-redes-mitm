from scapy.all import *
from datetime import datetime

def packet_callback_https(packet):
    """ Callback function to process captured HTTPS packets """
    try:
        if packet.haslayer(TCP) and packet[TCP].dport == 443:
            # Log the HTTPS packet details into a text file
            with open(f"../sniffer-logs/https/https_sniffer_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt", 'a') as file:
                file.write(f"[*] HTTPS Packet - {datetime.now()}\n")
                if packet.haslayer(IP):
                    file.write(f"Source IP: {packet[IP].src}\n")
                    file.write(f"Destination IP: {packet[IP].dst}\n")
                file.write(f"Source Port: {packet[TCP].sport}\n")
                file.write(f"Destination Port: {packet[TCP].dport}\n")
                file.write(f"Sequence Number: {packet[TCP].seq}\n")
                file.write(f"Acknowledgment Number: {packet[TCP].ack}\n")
                file.write(f"Flags: {packet[TCP].flags}\n")
                # Log the payload if it exists
                if Raw in packet:
                    file.write(f"Payload: {packet[Raw].load}\n")
                else:
                    file.write("Payload: No Payload\n")
                file.write("\n")
    except Exception as e:
        print(f"Error processing packet: {e}")

if __name__ == "__main__":
    print("Starting packet sniffer for HTTPS...")
    try:
        sniff(filter="tcp port 443", prn=packet_callback_https, store=0)
    except PermissionError:
        print("Permission denied: Please run the script as an administrator.")
    except Exception as e:
        print(f"An error occurred: {e}")
    except KeyboardInterrupt:
        print("Stopped http sniffing")
