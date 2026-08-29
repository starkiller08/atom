CSCI368 Network Security - Assignment 1

-------------------------------------------------------------------------------

Requirements


Python 3.10 or later
pycryptodome library

Install with:
	pip install pycryptodome

-------------------------------------------------------------------------------

Files

assignment1/			The folder where the below listed files are stored

key_setup.py 			Generate Alice's RSA key pair, stores the public key fingerprint in Bob's directory, and creates the password file in Alice's directory.

Alice/host.py 			The Host program, run by Alice.

Bob/client.py 			The Client program, run by Bob.

--------------------------------------------------------------------------------

How To Run


All commands must be run from the assignment1 directory
(the directory containing this readme).

Step 1 - Switch to the assignment 1 folder and Run the key setup once:

    python3 key_setup.py

    When prompted, enter the password: {your_password}
    (Must be exactly 8 alphanumeric characters.)

Step 2 - Open a terminal and start the Host:

    python3 Alice/host.py

Step 3 - Open a second terminal and start the Client:

    python3 Bob/client.py

    Username: {username}
    Password: {password_entered_during_key_setup}

Step 4 - Once "Session key established" appears on both
terminals, either party can type a message and press Enter.
Messages appear on the other terminal prefixed with the
sender's name.

Step 5 - Bob types "exit" to close the connection. Alice
typing "exit" is treated as an ordinary message.

-------------------------------------------------------------------------------

PORTS

-------------------------------------------------------------------------------
Host:   127.0.0.1 port 1111
Client: 127.0.0.1 port 2222

-------------------------------------------------------------------------------

IMPLEMENTATION NOTES

-------------------------------------------------------------------------------
Protocol messages are sent as JSON. Binary values (nonces,
keys, ciphertexts) are base64 encoded for transport and
converted back to raw bytes before any cryptographic
operation.

RSA:   2048-bit keys with OAEP padding (pycryptodome).
SHA-1: Python standard library hashlib.
RC4:   Implemented from scratch in both programs
       (key scheduling algorithm and pseudo-random
       generation algorithm). No external library used.
UDP:   Python standard library socket module.

Session key:  ssk = SHA-1(K || NB || NA)
Message form: C = RC4(mk, m || SHA-1(ssk || m))
              where mk = SHA-1(ssk || nonce) and a fresh
              16-byte nonce is sent in the clear with each
              message so that no two messages share a
              keystream.

Each program runs a receiver thread so that messages can be
sent and received at any time rather than in strict turns.

-------------------------------------------------------------------------------

KNOWN LIMITATIONS

-------------------------------------------------------------------------------
- The programs must be run from the assignment1 directory
  as file paths are relative to it.