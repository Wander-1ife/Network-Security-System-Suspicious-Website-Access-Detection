import asyncio
import threading
import datetime
import os
import pyshark
from scapy.all import sniff
from scapy.layers.http import HTTPRequest
from collections import deque

# Define Suspicious Websites
SUSPICIOUS_WEBSITES = {"flexstudent.nu.edu.pk", "phishing-site.net", "badwebsite.org"}

# Define Network Interface (Change as needed)
NETWORK_INTERFACE = "Wi-Fi"  # Change this to match your network adapter

# Log file management
LOG_FILE = "network_traffic.log"
SUSPICIOUS_LOG_FILE = "suspicious_access.log"
LOG_HISTORY_LIMIT = 500  # Keep last 500 entries in logs

log_entries = deque(maxlen=LOG_HISTORY_LIMIT)


def log_traffic(domain, src_ip, dst_ip, is_suspicious=False):
    #Logs network traffic with timestamps, IPs, and domain information.
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {src_ip} -> {dst_ip} | {domain} {'(SUSPICIOUS)' if is_suspicious else ''}"

    log_entries.append(log_entry)
    with open(LOG_FILE, "a") as log_file:
        log_file.write(log_entry + "\n")

    if is_suspicious:
        print(f"[ALERT] Suspicious Access: {domain} from {src_ip} to {dst_ip} at {timestamp}")
        with open(SUSPICIOUS_LOG_FILE, "a") as alert_file:
            alert_file.write(log_entry + "\n")


def extract_http_domain(packet):
    #Extracts and logs HTTP domains.
    if packet.haslayer(HTTPRequest):
        try:
            host = packet[HTTPRequest].Host.decode() if packet[HTTPRequest].Host else None
            src_ip = packet["IP"].src if packet.haslayer("IP") else "Unknown"
            dst_ip = packet["IP"].dst if packet.haslayer("IP") else "Unknown"
            if host:
                is_suspicious = host in SUSPICIOUS_WEBSITES
                log_traffic(host, src_ip, dst_ip, is_suspicious)
        except Exception as e:
            print(f"Error extracting HTTP domain: {e}")


def start_http_sniffing():
    #Starts HTTP traffic sniffing asynchronously.
    try:
        sniff(filter="tcp port 80", prn=extract_http_domain, store=False)
    except KeyboardInterrupt:
        print("HTTP Sniffing Stopped.")


def extract_https_domain(packet):
    #Extracts and logs HTTPS domains (TLS SNI)
    try:
        domain = getattr(packet.tls, "handshake_extensions_server_name", None)
        src_ip = packet.ip.src if hasattr(packet, "ip") else "Unknown"
        dst_ip = packet.ip.dst if hasattr(packet, "ip") else "Unknown"
        if domain:
            is_suspicious = domain in SUSPICIOUS_WEBSITES
            log_traffic(domain, src_ip, dst_ip, is_suspicious)
    except AttributeError:
        pass  # Ignore packets without the required field
    except Exception as e:
        print(f"Error extracting HTTPS domain: {e}")


def start_https_sniffing():
    #Starts HTTPS traffic sniffing with a new asyncio event loop
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        capture = pyshark.LiveCapture(interface=NETWORK_INTERFACE, display_filter="tls.handshake.extensions_server_name")
        for packet in capture.sniff_continuously():
            extract_https_domain(packet)
    except KeyboardInterrupt:
        print("HTTPS Sniffing Stopped.")
    except Exception as e:
        print(f"HTTPS Sniffing Error: {e}")


if __name__ == "__main__":
    print("Starting Network Traffic Monitoring...")
    print(f"Monitoring on interface: {NETWORK_INTERFACE}")
    
    http_thread = threading.Thread(target=start_http_sniffing, daemon=True)
    https_thread = threading.Thread(target=start_https_sniffing, daemon=True)

    http_thread.start()
    https_thread.start()

    try:
        http_thread.join()
        https_thread.join()
    except KeyboardInterrupt:
        print("Stopping Network Traffic Monitoring...")
