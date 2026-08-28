import socket as s

sock = s.socket(s.AF_INET, s.SOCK_DGRAM)
sock.bind(('127.0.0.1', 2222))

sock.sendto(b'Hello', ('127.0.0.1', 1111))
print('Connection request sent...')

data, addr = sock.recvfrom(4096)

print(f'Data sent.... {data} {addr}')