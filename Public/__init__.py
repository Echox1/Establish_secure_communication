
import socket
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from cryptography.x509.oid import NameOID
import datetime
import os
import struct
#author: escape

separator = "|||".encode('utf-8')  # Define a separator for message parts

# Function to generate RSA key pairs
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Function to generate a self-signed certificate
def generate_cert(username):
    # Define certificate subject and issuer
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"CN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Shanghai"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Shanghai"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Test Org"),
        x509.NameAttribute(NameOID.COMMON_NAME, username),
    ])
    private_key, public_key = generate_keys()
    # Build certificate
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(public_key).serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.utcnow()).not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=10)).sign(private_key, hashes.SHA256())
    # Serialize certificate to PEM format
    cert_pem = cert.public_bytes(Encoding.PEM)
    cert = x509.load_pem_x509_certificate(cert_pem)
    # Sign the certificate
    message = cert_pem
    signature = private_key.sign(message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
    return message, signature, private_key, public_key

# Function to authenticate received data
def Authentication(data):
    # Extract certificate and signature
    cert_pem, signature = data.split(separator)
    # Load certificate and get public key
    cert = x509.load_pem_x509_certificate(cert_pem)
    public_key = cert.public_key()
    # Verify signature
    try:
        public_key.verify(signature, cert_pem, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        return cert_pem
    except Exception as e:
        print("Signature is invalid.", e)
        return False

# Function to extract public key from certificate
def extract_public_key(cert_pem):
    cert = x509.load_pem_x509_certificate(cert_pem)
    return cert.public_key()

# Function to extract the common name from a certificate
def extract_username_from_cert(cert_pem):
    cert = x509.load_pem_x509_certificate(cert_pem)
    common_name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    return common_name

# Function to sign data using a private key
def sign_data(private_key, data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    signature = private_key.sign(data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
    return signature

# Function to encrypt data using a public key
def encrypt_data(public_key, data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    step = len(data) // 4
    encrypted_data = b''
    for i in range(4):
        start = i * step
        end = (i + 1) * step if i != 3 else None
        segment = data[start:end]
        encrypted_segment = public_key.encrypt(segment, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        encrypted_data += struct.pack('!I', len(encrypted_segment)) + encrypted_segment
    return encrypted_data

# Function to encrypt data into multiple segments using a public key
def encrypt_data_20(public_key, data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    step = len(data) // 20
    encrypted_data = b''
    for i in range(20):
        start = i * step
        if i == 19:  # Handle the last segment
            end = None
        else:
            end = start + step
        segment = data[start:end]
        if len(segment) < 11:  # Check if segment is too short for OAEP padding
            raise ValueError(f"Segment too short: {len(segment)} bytes.")
        encrypted_segment = public_key.encrypt(segment, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        encrypted_data += struct.pack('!I', len(encrypted_segment)) + encrypted_segment
    return encrypted_data

# Function to decrypt data using a private key
def decrypt_data(private_key, encrypted_data):
    decrypted_data = b''
    offset = 0
    while offset < len(encrypted_data):
        segment_length = struct.unpack('!I', encrypted_data[offset:offset + 4])[0]
        offset += 4
        segment = encrypted_data[offset:offset + segment_length]
        decrypted_segment = private_key.decrypt(segment, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        decrypted_data += decrypted_segment
        offset += segment_length
    return decrypted_data

# Function to verify a signature using a public key
def verify_signature(public_key, signature, data):
    try:
        public_key.verify(signature, data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        return True
    except Exception as e:
        print(f"verify failed: {e}")
        return False


def generate_key_fragment():
    return os.urandom(32)  # 32 bytes for strong security

def xor_bytes(*args):
    from functools import reduce
    return reduce(lambda x, y: bytes(a ^ b for a, b in zip(x, y)), args)

# Function to combine multiple key fragments using XOR operation and hash the result
def combine_key_fragments(fragments_dict):
    fragments = list(fragments_dict.values())
    if not fragments:
        raise ValueError("No fragments to combine")
    first_len = len(fragments[0])
    if any(len(f) != first_len for f in fragments):
        raise ValueError("Not all fragments are of equal length")
    xor_result = xor_bytes(*fragments)
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(xor_result)
    return digest.finalize()

# Functions to encrypt and decrypt data using AES
def encrypt_data_with_aes(key, data):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    return cipher.iv + ciphertext

def decrypt_data_with_aes(key, encrypted_data):
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext
