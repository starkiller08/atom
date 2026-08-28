import socket as s
import os
import json as j
import base64 as b64
import hashlib as hl
from Crypto.PublicKey import RSA as rsa
from Crypto.Cipher import PKCS1_OAEP as pkcs1_oaep


sock = s.socket(s.AF_INET, s.SOCK_DGRAM)
sock.bind(('127.0.0.1', 2222))

nb = os.urandom(16)
sock.sendto(j.dumps({'msg':1,'user':input('Username: '),'nb':b64.b64encode(nb).decode()}).encode(), ('127.0.0.1', 1111))
print('Connection request sent...')

data, addr = sock.recvfrom(4096)

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


data, addr = sock.recvfrom(4096)
result = data.decode()
print(result)
if result != 'Connection Okay':
    exit()
ssk = hl.sha1(k + nb + na).digest()
print('Session key established')
