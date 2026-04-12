import socket

# Set this to your REMnux IP
IP = '192.168.100.135'
PORT = 53

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('0.0.0.0', PORT))

print(f"DNS Trap active on port {PORT}. Redirecting all traffic to {IP}...")

while True:
    data, addr = sock.recvfrom(512)
    # Simple DNS response header: Transaction ID + Flags (Standard Response, No Error)
    packet = data[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
    # Question Section
    packet += data[12:]
    # Answer Section: Name (pointer to offset 12) + Type (A) + Class (IN) + TTL (60s) + Data Length (4)
    packet += b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04"
    # The fake IP address
    packet += bytes(map(int, IP.split('.')))

    sock.sendto(packet, addr)
    print(f"Captured request from {addr[0]} - Sent redirection to {IP}")
