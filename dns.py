#!/usr/bin/env python3
import sys
import os
import socket
import argparse
import requests
import subprocess
import threading
import logging
from pathlib import Path
from dnslib import DNSRecord, DNSHeader, RR, A, QTYPE, DNSError
from socketserver import ThreadingUDPServer, ThreadingTCPServer, BaseRequestHandler

# Global constants
INSTALL_DIR = "/opt/dns"
SERVICE_NAME = "custom-dns"
SERVICE_FILE = f"/etc/systemd/system/{SERVICE_NAME}.service"
LOG_FILE = "/var/log/custom-dns.log"
ERROR_LOG_FILE = "/var/log/custom-dns.error.log"

def setup_logging():
    """Set up logging configuration"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(LOG_FILE),
            logging.StreamHandler()
        ]
    )
    # Set up error logging
    error_handler = logging.FileHandler(ERROR_LOG_FILE)
    error_handler.setLevel(logging.ERROR)
    logging.getLogger().addHandler(error_handler)

def get_public_ip():
    """Get public IP address using ipconfig.io"""
    try:
        response = requests.get('https://ipconfig.io/ip', timeout=5)
        if response.status_code == 200:
            return response.text.strip()
    except Exception as e:
        logging.error(f"Error getting public IP: {e}")
        logging.info("Falling back to local IP detection...")
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception as e:
        logging.error(f"Error getting local IP: {e}")
        sys.exit(1)

def remove_existing_service():
    """Remove existing DNS service if it exists"""
    try:
        if os.path.exists(SERVICE_FILE):
            logging.info("Removing existing service...")
            subprocess.run(["systemctl", "stop", SERVICE_NAME], check=True)
            subprocess.run(["systemctl", "disable", SERVICE_NAME], check=True)
            os.remove(SERVICE_FILE)
            subprocess.run(["systemctl", "daemon-reload"], check=True)
            logging.info("Existing service removed successfully")
        return True
    except subprocess.CalledProcessError as e:
        logging.error(f"Error removing existing service: {e}")
        return False
    except Exception as e:
        logging.error(f"Error: {e}")
        return False

def create_service(args):
    """Create and start systemd service"""
    service_content = f"""[Unit]
Description=Custom DNS Server
After=network.target

[Service]
ExecStart=/usr/bin/python3 {os.path.join(INSTALL_DIR, 'dns.py')} {f'--ip {args.ip}' if args.ip else ''} --port {args.port} --whitelist-file {args.whitelist_file} --forward-dns "{args.forward_dns}"
Type=simple
Restart=on-failure
RestartSec=5
WorkingDirectory={INSTALL_DIR}
User=root
StandardOutput=append:{LOG_FILE}
StandardError=append:{ERROR_LOG_FILE}
LimitNOFILE=65535
TimeoutStartSec=0
RemainAfterExit=no

[Install]
WantedBy=multi-user.target
"""
    
    try:
        # First remove any existing service
        if not remove_existing_service():
            return False

        # Create new service file
        logging.info("Creating new service...")
        with open(SERVICE_FILE, 'w') as f:
            f.write(service_content)

        # Start new service
        logging.info("Starting new service...")
        subprocess.run(["systemctl", "daemon-reload"], check=True)
        subprocess.run(["systemctl", "enable", SERVICE_NAME], check=True)
        subprocess.run(["systemctl", "start", SERVICE_NAME], check=True)
        
        print(f"\nDNS Service installed and started successfully!")
        print(f"Service IP: {args.server_ip}")
        print(f"Service Port: {args.port}")
        print(f"Forward DNS: {args.forward_dns}")
        print("\nYou can manage the service using:")
        print(f"  systemctl status {SERVICE_NAME}")
        print(f"  systemctl stop {SERVICE_NAME}")
        print(f"  systemctl start {SERVICE_NAME}")
        print(f"  journalctl -u {SERVICE_NAME} -f")
        print("\nService logs are available at:")
        print(f"  {LOG_FILE}")
        print(f"  {ERROR_LOG_FILE}")
        
        return True
    except Exception as e:
        logging.error(f"Error creating service: {e}")
        return False

class DNSHandler:
    def __init__(self, data, socket, address, server_ip, whitelist, forward_dns_servers):
        self.data = data
        self.socket = socket
        self.address = address
        self.server_ip = server_ip
        self.whitelist = whitelist
        self.forward_dns_servers = [dns.strip() for dns in forward_dns_servers.split(',')]

    def handle(self):
        try:
            packet = DNSRecord.parse(self.data)
            requested_domain = str(packet.questions[0].qname).rstrip('.')

            if self.is_whitelisted(requested_domain):
                return self.handle_whitelist(packet)
            else:
                return self.forward_request(self.data)

        except DNSError as err:
            logging.error(f"DNS Error: {err}")
            return None

    def is_whitelisted(self, domain):
        domain_parts = domain.split('.')
        for i in range(len(domain_parts)):
            check_domain = '.'.join(domain_parts[i:])
            for whitelist_domain in self.whitelist:
                if whitelist_domain.startswith('.') and whitelist_domain.endswith('.'):
                    if check_domain.endswith(whitelist_domain[1:-1]) or check_domain.startswith(whitelist_domain[1:-1]):
                        return True
                elif whitelist_domain.startswith('.'):
                    if check_domain.endswith(whitelist_domain[1:]):
                        return True
                else:
                    if check_domain == whitelist_domain:
                        return True
        return False

    def handle_whitelist(self, packet):
        reply_packet = packet.reply()
        for question in packet.questions:
            requested_domain_name = question.get_qname()
            reply_packet.add_answer(RR(requested_domain_name, rdata=A(self.server_ip), ttl=60))
            logging.info(f"Whitelist Request: {requested_domain_name.idna()} --> {self.server_ip}")
        return reply_packet.pack()

    def forward_request(self, data):
        for dns_server in self.forward_dns_servers:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(5)
                sock.sendto(data, (dns_server.strip(), 53))
                response, _ = sock.recvfrom(1024)
                logging.info(f"Forwarded Request: {DNSRecord.parse(data).questions[0].qname} --> {dns_server}")
                return response
            except socket.error as e:
                logging.error(f"Error forwarding to {dns_server}: {e}")
            finally:
                sock.close()
        return None

class UDPHandler(BaseRequestHandler):
    def handle(self):
        data, socket = self.request
        handler = DNSHandler(data, socket, self.client_address, args.server_ip, args.whitelist, args.forward_dns)
        response = handler.handle()
        if response:
            socket.sendto(response, self.client_address)

class TCPHandler(BaseRequestHandler):
    def handle(self):
        data = self.request.recv(8192)
        length = int.from_bytes(data[:2], byteorder='big')
        if len(data) - 2 != length:
            return
        handler = DNSHandler(data[2:], self.request, self.client_address, args.server_ip, args.whitelist, args.forward_dns)
        response = handler.handle()
        if response:
            self.request.sendall(len(response).to_bytes(2, byteorder='big') + response)

def read_whitelist(filename):
    try:
        with open(filename, 'r') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except Exception as e:
        logging.error(f"Error reading whitelist file: {e}")
        sys.exit(1)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='DNS Server with service management')
    parser.add_argument("--ip", help="set server IP address (optional)", type=str, default=None)
    parser.add_argument("--port", help="set listen port", type=int, default=53)
    parser.add_argument("--whitelist-file", help="file containing whitelisted domains", type=str, required=True)
    parser.add_argument("--forward-dns", help="comma-separated list of forwarding DNS servers", type=str, required=True)
    args = parser.parse_args()

    # Check if running as root
    if os.geteuid() != 0:
        print("This script must be run as root (sudo)")
        sys.exit(1)

    # Set up logging
    setup_logging()

    # Get IP address (manual or auto-detected)
    if args.ip:
        args.server_ip = args.ip
        logging.info(f"Using provided IP: {args.server_ip}")
    else:
        args.server_ip = get_public_ip()
        logging.info(f"Using auto-detected IP: {args.server_ip}")

    try:
        # Check if script is being run directly by systemd
        if os.getenv('INVOCATION_ID') is not None:
            args.whitelist = read_whitelist(args.whitelist_file)
            logging.info(f"Starting DNS Server in service mode...")
            logging.info(f"Server IP: {args.server_ip}")
            logging.info(f"Port: {args.port}")
            logging.info(f"Forward DNS: {args.forward_dns}")
            logging.info(f"Whitelist entries: {len(args.whitelist)}")
            
            try:
                udp_server = ThreadingUDPServer(("0.0.0.0", args.port), UDPHandler)
                tcp_server = ThreadingTCPServer(("0.0.0.0", args.port), TCPHandler)
            except Exception as e:
                logging.error(f"Failed to bind to port {args.port}: {e}")
                sys.exit(1)
            
            udp_thread = threading.Thread(target=udp_server.serve_forever)
            tcp_thread = threading.Thread(target=tcp_server.serve_forever)
            
            udp_thread.daemon = True
            tcp_thread.daemon = True
            
            udp_thread.start()
            tcp_thread.start()
            
            logging.info("DNS Server started successfully")
            
            # Keep the main thread alive
            while True:
                try:
                    udp_thread.join(1)
                    tcp_thread.join(1)
                except KeyboardInterrupt:
                    logging.info("Shutting down the server...")
                    udp_server.shutdown()
                    tcp_server.shutdown()
                    break
        else:
            # Running as command 'dns', create/update service
            create_service(args)
            
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        sys.exit(1)
