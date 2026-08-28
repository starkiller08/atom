import socket as s
import os
import json as j
import base64 as b64
import hashlib as hl
from Crypto.PublicKey import RSA as rsa
from Crypto.Cipher import PKCS1_OAEP as pkcs1_oaep
import threading as tdg


running = {'ok': True}


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


def receiver(sock, ssk):
	while running['ok']:
		r = recv_msg(sock, ssk)
		if r == 'TIMEOUT':
			continue
		if r is None:
			print('Decryption Error')
		else:
			print('\n[Alice]', r)




def send_msg(sock, ssk, m, to_addr):
	h = hl.sha1(ssk + m.encode()).digest()
	nonce = os.urandom(16)
	mk = hl.sha1(ssk + nonce).digest()
	c = rc4(mk, m.encode() + h)
	sock.sendto(b64.b64encode(nonce + c), to_addr)

def recv_msg(sock, ssk):
	try:
		data, a = sock.recvfrom(4096)
	except s.timeout:
		return 'TIMEOUT'
	raw = b64.b64decode(data)
	nonce, c = raw[:16], raw[16:]
	mk = hl.sha1(ssk + nonce).digest()
	blob = rc4(mk, c)
	m, h = blob[:-20], blob[-20:]
	if hl.sha1(ssk + m).digest() == h:
		return m.decode()
	return None



sock = s.socket(s.AF_INET, s.SOCK_DGRAM)
sock.bind(('127.0.0.1', 2222))
sock.settimeout(10.0)


nb = os.urandom(16)
sock.sendto(j.dumps({'msg':1,'user':input('Username: '),'nb':b64.b64encode(nb).decode()}).encode(), ('127.0.0.1', 1111))
print('Connection request sent...')

try:
	data, addr = sock.recvfrom(4096)
except s.timeout:
	print('No response from Host - terminating')
	exit()
print(f'Data sent.... {data} {addr}')



m2 = j.loads(data.decode())
pk_bytes = b64.b64decode(m2['pk'])
na = b64.b64decode(m2['na'])
fp = open('Bob/alice_public_key_fingerprint.txt').read().strip()
if hl.sha1(pk_bytes).hexdigest() != fp:
	print('Fingerprint mismatch - terminating')
	exit()
print('Host public key verified')


pw = input('Password: ')
k = os.urandom(16)
cipher = pkcs1_oaep.new(rsa.import_key(pk_bytes))
c1 = cipher.encrypt(pw.encode() + k)
sock.sendto(j.dumps({'msg':3,'c1':b64.b64encode(c1).decode()}).encode(), ('127.0.0.1',1111))


try:
	data, addr = sock.recvfrom(4096)
except s.timeout:
	print('No response from Host --> terminating')
	exit()
result = data.decode()
print(result)
if result != 'Connection Okay':
	exit()
ssk = hl.sha1(k + nb + na).digest()
print('Session key established')


t = tdg.Thread(target=receiver, args=(sock, ssk), daemon=True)
t.start()



while True:
	m = input()
	send_msg(sock, ssk, m, ('127.0.0.1', 1111))
	if m == 'exit':
		break
