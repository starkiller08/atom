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



def receiver(sock, ssk):
	while running['ok']:
		r = recv_msg(sock, ssk)
		if r == 'TIMEOUT':
			continue
		if r is None:
			print('Decryption Error')
		else:
			print('\n[Bob]', r)
			if r == 'exit':
				print('Bob disconnected. Press Enter to return to listening.')
				running['ok'] = False



sock = s.socket(s.AF_INET, s.SOCK_DGRAM)
sock.bind(('127.0.0.1', 1111))
sock.settimeout(10.0)

print('Host listening on port 1111....')



while True:
	running['ok'] = True
	try:
		data, addr = sock.recvfrom(4096)
	except s.timeout:
		continue
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



	try:
		data, addr = sock.recvfrom(4096)
	except s.timeout:
		print('No response from Client --> waiting for a new connection')
		continue
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
		print('Waiting for a new connection...')
		continue


	t = tdg.Thread(target=receiver, args=(sock, ssk), daemon=True)
	t.start()



	while running['ok']:
		send_msg(sock, ssk, input(), addr)
