import asyncio
import threading
import datetime
from scapy.all import sniff
from scapy.layers.http import HTTPRequest
import pyshark

SUSPICIOUS_WEBSITES = {"flexstudent.nu.edu.pk", "phishing-site.net", "badwebsite.org"}

def log_traffic(domain, is_suspicious=False):
    """Logs all accessed websites with timestamps"""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {domain} {'(SUSPICIOUS)' if is_suspicious else ''}"
    
    with open("network_traffic.log", "a") as log_file:
        log_file.write(log_entry + "\n")
    
    if is_suspicious:
        print(f"[ALERT] Suspicious Access: {domain} at {timestamp}")
        with open("suspicious_access.log", "a") as alert_file:
            alert_file.write(log_entry + "\n")

def extract_http_domain(packet):
    """Extracts domain from HTTP request packets and logs"""
    if packet.haslayer(HTTPRequest):
        host = packet[HTTPRequest].Host.decode() if packet[HTTPRequest].Host else None
        if host:
            is_suspicious = host in SUSPICIOUS_WEBSITES
            log_traffic(host, is_suspicious)

def start_http_sniffing():
    """Starts monitoring HTTP traffic"""
    sniff(filter="tcp port 80", prn=extract_http_domain, store=False)

def extract_https_domain(packet):
    """Extracts domain from HTTPS (TLS handshake) and logs"""
    if "TLS" in packet:
        for field in packet.tls.field_names:
            if "handshake_extensions_server_name" in field:
                domain = packet.tls.handshake_extensions_server_name
                if domain:
                    is_suspicious = domain in SUSPICIOUS_WEBSITES
                    log_traffic(domain, is_suspicious)

def start_https_sniffing():
    """Starts monitoring HTTPS traffic with a new asyncio event loop"""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    capture = pyshark.LiveCapture(interface="Wi-Fi", display_filter="tls.handshake.extensions_server_name")

    for packet in capture.sniff_continuously():
        extract_https_domain(packet)

if __name__ == "__main__":
    
    http_thread = threading.Thread(target=start_http_sniffing)
    https_thread = threading.Thread(target=start_https_sniffing)

    http_thread.start()
    https_thread.start()

    http_thread.join()
    https_thread.join()
