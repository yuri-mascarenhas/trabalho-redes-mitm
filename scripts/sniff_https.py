from scapy.all import sniff, TCP, Raw

def packet_callback_https(packet):
    """ Callback function to process captured HTTPS packets """
    try:
        if packet.haslayer(TCP) and packet.haslayer(Raw):
            payload = packet[Raw].load
            if b'GET' in payload or b'POST' in payload:
                print(f"[*] HTTPS Request: {payload}")
            else:
                print(f"[*] Encrypted HTTPS Data: {payload}")
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
