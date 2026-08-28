import socket as s

sock = s.socket(s.AF_INET, s.SOCK_DGRAM)
sock.bind(('127.0.0.1', 1111))

print('Host listening on port 1111....')
data, addr = sock.recvfrom(4096)
print(f'Connection request received... {data} {addr}')

sock.sendto(b'got it', addr)