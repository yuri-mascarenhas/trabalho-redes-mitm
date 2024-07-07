from scapy.all import sniff, TCP, Raw
from datetime import datetime

def packet_callback_http(packet):
    """ Callback function to process captured HTTP packets """
    try:
        if packet.haslayer(TCP) and packet.haslayer(Raw):
            payload = packet[Raw].load
            if b'GET' in payload or b'POST' in payload:
                http_payload = payload.decode('utf-8', errors='ignore')
                log_data = f"[*] HTTP Request: {http_payload}\n"
                with open(f"../sniffer-logs/http/http_sniffer_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt", 'a') as file:
                    file.write(log_data)
            else:
                log_data = "[*] Other HTTP Request\n" + packet
                with open(f"../sniffer-logs/http/http_sniffer_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt", 'a') as file:
                    file.write(log_data)
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
    except KeyboardInterrupt:
        print("Stopped http sniffing")
