import socket as s
import os
import json as j
import base64 as b64
import hashlib as hl
from Crypto.PublicKey import RSA as rsa
from Crypto.Cipher import PKCS1_OAEP as pkcs1_oaep
import threading as tdg


def rc4(key, data):
	S = list(range(256))
	jj = 0
	for i in range(256):
		jj = (jj + S[i] + key[i % len(key)]) % 256
		S[i], S[jj] = S[jj], S[i]


	i = 0
	jj = 0
	out = bytearray()
	for byte in data:
		i = (i + 1) % 256
		jj = (jj + S[i]) % 256
		S[i], S[jj] = S[jj], S[i]
		ks = S[(S[i] + S[jj]) % 256]
		out.append(byte ^ ks)
	return bytes(out)


def send_msg(sock, ssk, m, to_addr):
    h = hl.sha1(ssk + m.encode()).digest()
    c = rc4(ssk, m.encode() + h)
    sock.sendto(b64.b64encode(c), to_addr)

def recv_msg(sock, ssk):
    data, a = sock.recvfrom(4096)
    blob = rc4(ssk, b64.b64decode(data))
    m, h = blob[:-20], blob[-20:]
    if hl.sha1(ssk + m).digest() == h:
        return m.decode()
    return None



def receiver(sock, ssk):
    while True:
        r = recv_msg(sock, ssk)
        if r is None:
            print('Decryption Error')
        else:
        	print('\n[Bob]', r)
        	if r == 'exit':
        		print('Connection closed by Bob')
        		os._exit(0)


sock = s.socket(s.AF_INET, s.SOCK_DGRAM)
sock.bind(('127.0.0.1', 1111))

print('Host listening on port 1111....')
data, addr = sock.recvfrom(4096)
print(f'Connection request received... {data} {addr}')


m = j.loads(data.decode())
nb = b64.b64decode(m['nb'])
print(f'User: {m["user"]}, NB length: {len(nb)}')


pk_bytes = open('Alice/alice_public_key.pem','rb').read()
na = os.urandom(16)
reply = j.dumps({'msg':2,'user':'alice',
                 'pk': b64.b64encode(pk_bytes).decode(),
                 'na': b64.b64encode(na).decode()}).encode()
sock.sendto(reply, addr)



data, addr = sock.recvfrom(4096)
m3 = j.loads(data.decode())
c1 = b64.b64decode(m3['c1'])
sk = rsa.import_key(open('Alice/alice_private_key.pem','rb').read())
blob = pkcs1_oaep.new(sk).decrypt(c1)
pw_recv, k = blob[:8], blob[8:]


rec = open('Alice/passwords.txt').read().strip().split(':')
if hl.sha1(pw_recv).hexdigest() == rec[1]:
    print('Password verified')
    sock.sendto(b'Connection Okay', addr)
    ssk = hl.sha1(k + nb + na).digest()
    print('Session key established')
else:
    print('Password incorrect')
    sock.sendto(b'Connection Failed', addr)
    exit()


t = tdg.Thread(target=receiver, args=(sock, ssk), daemon=True)
t.start()



while True:
    send_msg(sock, ssk, input(), addr)
