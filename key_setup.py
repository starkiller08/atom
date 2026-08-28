# Importing the necessary libraries

from Crypto.PublicKey import RSA as rsa
import hashlib as hl
import os


# Generate the pair of private and public keys in bytes format

print('Generating Private Key')
alice_private_key = rsa.generate(2048)
alice_private_key_bytes = alice_private_key.export_key()

print('Generating Public Key')
alice_public_key = alice_private_key.publickey()
alice_public_key_bytes = alice_public_key.export_key()


with open('Alice/alice_private_key.pem', 'wb') as f:
	print('Saving file "alice_private_key.pem" to folder "Alice"')
	f.write(alice_private_key_bytes)


with open('Alice/alice_public_key.pem', 'wb') as f:
	print('Saving file "alice_public_key.pem" to folder "Alice"')
	f.write(alice_public_key_bytes)


alice_public_key_hash = hl.sha1(alice_public_key_bytes).hexdigest()

with open('Bob/alice_public_key_fingerprint.txt', 'w') as f:
	print('Saving file "alice_public_key_fingerprint" to folder "Bob"')
	f.write(alice_public_key_hash)


while True:
	password = input('Please enter your password (8 alphanumeric characters exactly): ')
	if len(password) == 8 and password.isalnum():
		break

	elif len(password) < 8:
		print(f'Password too short. Add {8 - len(password)} characters.')
	elif len(password) > 8:
		print(f'Password too long. Remove {len(password) - 8} characters.')

pass_hash = hl.sha1(password.encode()).hexdigest()

with open('Alice/passwords.txt', 'w') as f:
	print('Saving file "passwords.txt" to folder Alice')
	f.write(f'bob:{pass_hash}')