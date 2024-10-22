#!/usr/bin/env python3
import sys
import os
import socket
import argparse
import requests
import subprocess
from pathlib import Path
from dnslib import DNSRecord, DNSHeader, RR, A, QTYPE, DNSError
from socketserver import ThreadingUDPServer, ThreadingTCPServer, BaseRequestHandler

INSTALL_DIR = "/opt/dns"
SERVICE_NAME = "custom-dns"
SERVICE_FILE = f"/etc/systemd/system/{SERVICE_NAME}.service"

def get_public_ip():
    """Get public IP address using ipconfig.io"""
    try:
        response = requests.get('https://ipconfig.io/ip', timeout=5)
        if response.status_code == 200:
            return response.text.strip()
    except Exception as e:
        print(f"Error getting public IP: {e}")
        print("Falling back to local IP detection...")
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception as e:
        print(f"Error getting local IP: {e}")
        sys.exit(1)

def remove_existing_service():
    """Remove existing DNS service if it exists"""
    try:
        if os.path.exists(SERVICE_FILE):
            print("Removing existing service...")
            subprocess.run(["systemctl", "stop", SERVICE_NAME], check=True)
            subprocess.run(["systemctl", "disable", SERVICE_NAME], check=True)
            os.remove(SERVICE_FILE)
            subprocess.run(["systemctl", "daemon-reload"], check=True)
            print("Existing service removed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error removing existing service: {e}")
        return False
    except Exception as e:
        print(f"Error: {e}")
        return False

def create_service(args, server_ip):
    """Create and start systemd service"""
    service_content = f"""[Unit]
Description=Custom DNS Server
After=network.target

[Service]
ExecStart={sys.executable} {os.path.join(INSTALL_DIR, 'dns.py')} --port {args.port} --whitelist-file {os.path.join(INSTALL_DIR, args.whitelist_file)} --forward-dns "{args.forward_dns}"
Type=simple
Restart=always
WorkingDirectory={INSTALL_DIR}
User=root

[Install]
WantedBy=multi-user.target
"""
    
    try:
        # First remove any existing service
        if not remove_existing_service():
            return False

        # Create new service file
        print("Creating new service...")
        with open(SERVICE_FILE, 'w') as f:
            f.write(service_content)

        # Start new service
        print("Starting new service...")
        subprocess.run(["systemctl", "daemon-reload"], check=True)
        subprocess.run(["systemctl", "enable", SERVICE_NAME], check=True)
        subprocess.run(["systemctl", "start", SERVICE_NAME], check=True)
        
        print(f"\nDNS Service installed and started successfully!")
        print(f"Service IP: {server_ip}")
        print(f"Service Port: {args.port}")
        print(f"Forward DNS: {args.forward_dns}")
        print("\nYou can manage the service using:")
        print(f"  systemctl status {SERVICE_NAME}")
        print(f"  systemctl stop {SERVICE_NAME}")
        print(f"  systemctl start {SERVICE_NAME}")
        print(f"  journalctl -u {SERVICE_NAME} -f")
        
        return True
    except Exception as e:
        print(f"Error creating service: {e}")
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
            print(f"DNS Error: {err}")
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
            print(f"Whitelist Request: {requested_domain_name.idna()} --> {self.server_ip}")
        return reply_packet.pack()

    def forward_request(self, data):
        for dns_server in self.forward_dns_servers:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(5)
                sock.sendto(data, (dns_server.strip(), 53))
                response, _ = sock.recvfrom(1024)
                print(f"Forwarded Request: {DNSRecord.parse(data).questions[0].qname} --> {dns_server}")
                return response
            except socket.error as e:
                print(f"Error forwarding to {dns_server}: {e}")
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

def run_server(server_class, handler_class):
    server = server_class(("0.0.0.0", args.port), handler_class)
    print(f"Starting {server_class.__name__} on port {args.port}...")
    server.serve_forever()

def read_whitelist(filename):
    try:
        with open(filename, 'r') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except Exception as e:
        print(f"Error reading whitelist file: {e}")
        sys.exit(1)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='DNS Server with service management')
    parser.add_argument("--port", help="set listen port", type=int, default=53)
    parser.add_argument("--whitelist-file", help="file containing whitelisted domains", type=str, required=True)
    parser.add_argument("--forward-dns", help="comma-separated list of forwarding DNS servers", type=str, required=True)
    args = parser.parse_args()

    # Check if running as root
    if os.geteuid() != 0:
        print("This script must be run as root (sudo)")
        sys.exit(1)

    # Get public IP
    args.server_ip = get_public_ip()

    try:
        # Check if running as a direct command
        if os.path.basename(sys.argv[0]) == 'dns' or os.path.basename(sys.argv[0]) == 'dns.py':
            create_service(args, args.server_ip)
        else:
            # Running as a service
            args.whitelist = read_whitelist(args.whitelist_file)
            print(f"Starting DNS Server...")
            print(f"Server IP: {args.server_ip}")
            print(f"Port: {args.port}")
            print(f"Forward DNS: {args.forward_dns}")
            print(f"Whitelist entries: {len(args.whitelist)}")
            
            udp_server = ThreadingUDPServer(("0.0.0.0", args.port), UDPHandler)
            tcp_server = ThreadingTCPServer(("0.0.0.0", args.port), TCPHandler)
            
            import threading
            udp_thread = threading.Thread(target=udp_server.serve_forever)
            tcp_thread = threading.Thread(target=tcp_server.serve_forever)
            
            udp_thread.start()
            tcp_thread.start()
            
            udp_thread.join()
            tcp_thread.join()
            
    except KeyboardInterrupt:
        print("\nShutting down the server...")
    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)
