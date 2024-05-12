import random
import time
import secrets
from datetime import datetime

def encode_current_time():
    return datetime.utcnow().isoformat()

# # Function to generate current time nonce
# def generate_nonce():
#     return str(time.time())

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def mod_inv(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def generate_keypair(p, q):
    n = p * q
    phi = (p - 1) * (q - 1)
    e = random.randrange(1, phi)
    g = gcd(e, phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = gcd(e, phi)
    d = mod_inv(e, phi)
    return ((e, n), (d, n))

def encrypt_with_session_key(message, session_key):
    cipher_text = []
    for i in range(len(message)):
        char = message[i]
        key_index = i % len(session_key)
        enc_char = ord(char) ^ ord(session_key[key_index])
        cipher_text.append(enc_char)
    return cipher_text

def decrypt_with_session_key(ciphertext, session_key):
    plain_text = []
    for i in range(len(ciphertext)):
        char = ciphertext[i]
        key_index = i % len(session_key)
        dec_char = chr(char ^ ord(session_key[key_index]))
        plain_text.append(dec_char)
    return ''.join(plain_text)

def encrypt(message, key):
    if isinstance(key, str):  # Check if key is a session key
        return encrypt_with_session_key(message, key)  # Call a function for session key encryption
    else:
        e, n = key  # Unpack public key as usual
        cipher_text = [pow(ord(char), e, n) for char in message]
        return cipher_text

def decrypt(ciphertext, key):
    if isinstance(key, str):  # Check if key is a session key
        return decrypt_with_session_key(ciphertext, key)  # Call a function for session key decryption
    else:
        d, n = key  # Unpack private key
        plain_text = [chr(pow(char, d, n)) for char in ciphertext]
        return ''.join(plain_text)

# Public Key Distribution Authority (PKDA)    
class PKDA:
    def __init__(self, p, q):
        self.public_key, self.private_key = generate_keypair(p, q)
        self.clients = {}  # Store clients' public keys

    def register_client(self, client_id, public_key):
        self.clients[client_id] = public_key

    def get_public_key(self, client_id):
        return self.clients.get(client_id)

    def encrypt_message(self, message, public_key):
        return encrypt(message, public_key)

    def decrypt_message(self, cipher_text):
        return decrypt(cipher_text, self.private_key)
    
    def generate_nonce(self, length=16):
        return secrets.token_hex(length)
    
    def generate_session_key(self):
        session_key = self.generate_nonce()
        return session_key

    def generate_session_key_request_timestamp(self):
        return encode_current_time()

# Test the system
p = 61
q = 53

# Creating PKDA
pkda = PKDA(p, q)

# Registering clients
client_A_public_key, client_A_private_key = generate_keypair(p, q)
client_B_public_key, client_B_private_key = generate_keypair(p, q)
pkda.register_client("A", client_A_public_key)
pkda.register_client("B", client_B_public_key)

# Simulate PKDA's session key generation and distribution
def generate_session_key():
    session_key = random.randint(100000, 999999)  # Generate a random session key
    return str(session_key)

def distribute_session_key(client_id, session_key):
    # Encrypt session key with client's public key (replace with actual encryption)
    encrypted_session_key = encrypt(session_key, pkda.get_public_key(client_id))
    return encrypted_session_key

# Initiator A requests a session key from PKDA
session_key_request_nonce = pkda.generate_nonce()
session_key_request_timestamp = pkda.generate_session_key_request_timestamp()
print(session_key_request_timestamp)
encrypted_session_key_request = pkda.encrypt_message(f"{client_A_public_key[0]}||{session_key_request_nonce}||{session_key_request_timestamp}", pkda.public_key)

# Simulate PKDA receiving and processing the request (not shown for brevity)
session_key = generate_session_key()  # Generate a session key
encrypted_session_key_for_A = distribute_session_key("A", session_key)

# PKDA sends the encrypted session key to Initiator A
print(f"PKDA sends encrypted session key to Initiator A: {encrypted_session_key_for_A}")

# Initiator A sends a request to Responder B with its identity and nonce
initiator_identity = "InitiatorA"
nonce1 = pkda.generate_nonce()
encrypted_initiator_request = encrypt(f"{initiator_identity}||{nonce1}", client_B_public_key)

# Responder B requests a session key from PKDA
session_key_request_nonce2 = pkda.generate_nonce()
session_key_request_timestamp2 = pkda.generate_session_key_request_timestamp()
print(session_key_request_timestamp2)
encrypted_session_key_request2 = pkda.encrypt_message(f"{client_B_public_key[0]}||{session_key_request_nonce2}||{session_key_request_timestamp2}", pkda.public_key)

# Simulate PKDA receiving and processing the request (not shown for brevity)
encrypted_session_key_for_B = distribute_session_key("B", session_key)  # Generate and distribute key for B

# PKDA sends the encrypted session key to Responder B
print(f"PKDA sends encrypted session key to Responder B: {encrypted_session_key_for_B}")

# Responder B sends a response to Initiator A with nonce2
nonce2 = pkda.generate_nonce()
encrypted_response_to_A = encrypt(f"{nonce1}||{nonce2}", client_A_public_key)
print("The nonce sent is: ",nonce2)

# Initiator A decrypts the response and verifies nonce2 (assuming possession of session key)
decrypted_response_to_A = decrypt(encrypted_response_to_A, client_A_private_key)
received_nonce1, received_nonce2 = decrypted_response_to_A.split('||')
if received_nonce1 == nonce1:
    print(f"Initiator A successfully verified Responder B's response (nonce2: {received_nonce2})")
else:
    print("Error: Invalid nonce received from Responder B")

# Initiator A sends a message to Responder B using the session key (simulated)
messages = ["Hi1", "Hi2", "Hi3"]
for message in messages:
    encrypted_message_to_B = encrypt(message, session_key)  # Assume session key is decrypted and used

    # Responder B decrypts the message and sends a response (simulated)
    decrypted_message_from_A = decrypt(encrypted_message_to_B, session_key)  # Assume session key is decrypted and used
    print(f"Responder B decrypts message from Initiator A: {decrypted_message_from_A}")

    # message_to_A = f"Got-it{messages.index(message) + 1} ({decrypted_message_from_A})"
    message_to_A = f"Got-it{messages.index(message) + 1}"
    encrypted_message_to_A = encrypt(message_to_A, client_A_public_key)

    # Printing encrypted messages for demonstration
    print(f"Responder B sends response to Initiator A: {encrypted_message_to_A}")

    # Initiator A decrypts the response from Responder B
    decrypted_response_from_B = decrypt(encrypted_message_to_A, client_A_private_key)
    print(f"Initiator A decrypts response from Responder B: {decrypted_response_from_B}")
