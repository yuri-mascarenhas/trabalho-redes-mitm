from scapy.all import sniff, TCP, Raw, IP

def packet_callback_http(packet):
    """ Callback function to process captured HTTP packets """
    try:
        if packet.haslayer(TCP) and packet.haslayer(Raw):
            payload = packet[Raw].load
            if b'GET' in payload or b'POST' in payload:
                http_payload = payload.decode('utf-8', errors='ignore')
                if 'httpforever.com' in http_payload or 'neverssl.com' in http_payload:
                    print(f"[*] HTTP Request: {http_payload}")
                else:
                    print(f"[*] Other HTTP Request: {http_payload}")
            else:
                print("[*] Non-HTTP TCP packet")
        else:
            print("[*] Non-TCP or Non-Raw packet")
    except Exception as e:
        print(f"Error processing packet: {e}")

if __name__ == "__main__":
    print("Starting packet sniffer for HTTP...")
    try:
        sniff(filter="tcp port 80", prn=packet_callback_http, store=0)
    except PermissionError:
        print("Permission denied: Please run the script as an administrator.")
    except Exception as e:
        print(f"An error occurred: {e}")
