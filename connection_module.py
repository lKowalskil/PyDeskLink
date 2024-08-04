import socket
import logging
import struct
import base64
import os
import sys
import struct
import time
import hashlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

DEFAULT_BUFFER_SIZE = 1024
DEFAULT_KEY_SIZE = 2048

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.FileHandler("connection_module.log"),
                        logging.StreamHandler(sys.stdout)
                    ])

def recv_all(sock, length):
    data = b''
    while len(data) < length:
        more_data = sock.recv(length - len(data))
        if not more_data:
            raise Exception("Less data received than expected")
        data += more_data
    return data

class SecureConnectionFramework:
    def __init__(self):
        self.my_private_key_RSA, self.my_public_key_RSA, self.my_private_key_pem, self.my_public_key_pem = self.generate_rsa_keys()
        self.my_symmetric_key_AES = self.generate_aes_key()
        self.socket = None
        self.connected = False
        self.other_public_key_RSA = None
        self.conn = None
        self.initialize_socket()

    def generate_rsa_keys(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return private_key, public_key, private_key_pem, public_key_pem

    def generate_aes_key(self):
        return os.urandom(32)

    def initialize_socket(self):
        try:
            logging.info("Initializing socket")
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            logging.info("Socket created successfully")
        except Exception as e:
            logging.error(f"Error initializing TCP socket: {e}")
            raise e

    def start_connection(self, server_ip: str, server_port: int):
        try:
            logging.info(f"Connecting to server {server_ip}:{server_port}")
            self.socket.connect((server_ip, server_port))
            logging.info("Socket connected successfully")

            logging.info(f"Transferring public key to server")
            self.other_public_key_RSA = self.exchange_keys_RSA(self.socket, self.my_public_key_pem)
            if self.other_public_key_RSA is None:
                raise Exception("Failed to receive server's public RSA key.")
            logging.info(f"Received server's public RSA key: {self.other_public_key_RSA}")
            self.receive_AES_key(self.socket)
            logging.info("AES key exchange successful")
            self.connected = True
        except Exception as e:
            logging.error(f"Error during key exchange: {e}")
            raise e

    def exchange_keys_RSA(self, sock, public_key_pem):
        try:
            sock.sendall(public_key_pem)
            received_public_key_pem = sock.recv(DEFAULT_BUFFER_SIZE)
            logging.info(f"Received RSA public key PEM: {received_public_key_pem}")
            if not received_public_key_pem:
                logging.error("Received an empty RSA public key PEM")
                return None
            public_key = serialization.load_pem_public_key(received_public_key_pem, backend=default_backend())
            logging.info(f"Deserialized RSA public key: {public_key}")
            return public_key
        except Exception as e:
            logging.error(f"Error while exchanging RSA keys: {e}")
            raise e

    def send_AES_key(self, sock, key):
        logging.info("Encrypting AES key for sending")
        encrypted_key = self.other_public_key_RSA.encrypt(
            key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        logging.info(f"Encrypted AES key length: {len(encrypted_key)}")
        logging.info("Sending AES key")
        sock.sendall(encrypted_key)
        logging.info("AES key sent successfully")

    def receive_AES_key(self, sock):
        received_encrypted_key = sock.recv(256)
        logging.info(f"Received encrypted AES key: {received_encrypted_key}")
        if not received_encrypted_key:
            logging.error("Received an empty encrypted AES key")
            return None
        decrypted_key = self.my_private_key_RSA.decrypt(
            received_encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        self.my_symmetric_key_AES = decrypted_key

    def send_data_AES(self, data: bytes):
        try:
            iv = os.urandom(16)
            padder = PKCS7(algorithms.AES.block_size).padder()
            padded_data = padder.update(data) + padder.finalize()
            logging.info(f"Padded data size (before encryption): {len(padded_data)}")

            cipher = Cipher(algorithms.AES(self.my_symmetric_key_AES), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

            logging.info(f"Encrypted data sending with size: {len(encrypted_data)}")
            size = len(encrypted_data)
            packed_size = struct.pack('!I', size)
            message = iv + packed_size + encrypted_data
            logging.info(f"Sending message of size: {len(message)}")
                
            logging.debug(f"Sent IV: {iv}")
            logging.debug(f"Sent data: {encrypted_data}")
            if self.conn:
                self.conn.sendall(message)
            elif self.socket:
                self.socket.sendall(message)

            logging.info(f"Encrypted data sent")
        except Exception as e:
            logging.error(f"Error while sending data: {e}")
            raise e

    def receive_data_AES(self):
        try:
            if self.conn:
                iv = recv_all(self.conn, 16)
                packed_size = recv_all(self.conn, 4)
                size = struct.unpack('!I', packed_size)[0]
                encrypted_data = recv_all(self.conn, size)
            elif self.socket:
                iv = recv_all(self.socket, 16)
                packed_size = recv_all(self.socket, 4)
                size = struct.unpack('!I', packed_size)[0]
                encrypted_data = recv_all(self.socket, size)
            else:
                raise Exception("No valid socket connection available")

            logging.debug(f"IV: {iv}")
            logging.debug(f"Packed size: {packed_size}")
            logging.info(f"Unpacked size: {size}")
            logging.info(f"Encrypted data size: {len(encrypted_data)}")
            logging.debug(f"Encrypted data: {encrypted_data}")
            
            cipher = Cipher(algorithms.AES(self.my_symmetric_key_AES), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()

            padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
            logging.info(f"Padded data size: {len(padded_data)}")

            unpadder = PKCS7(algorithms.AES.block_size).unpadder()
            data = unpadder.update(padded_data) + unpadder.finalize()

            logging.info(f"Data size after unpadding: {len(data)}")

            return data
        except Exception as e:
            logging.error(f"Error while receiving data: {e}")
            raise e

    def close(self):
        if self.socket:
            self.socket.close()
        if self.conn:
            self.conn.close()

class SecureConnectionClient(SecureConnectionFramework):
    def __init__(self, server_ip: str, server_port: int, key_size: int = DEFAULT_KEY_SIZE):
        logging.info("Initializing SecureConnectionClient")
        super().__init__()

        try:
            logging.info(f"Starting connection to server {server_ip}:{server_port}")
            self.start_connection(server_ip, server_port)
            logging.info("SecureConnectionClient initialized successfully")
        except Exception as e:
            logging.error(f"Error initializing SecureConnectionClient: {e}")
            raise e

class SecureConnectionServer(SecureConnectionFramework):
    def __init__(self, ip: str, port: int, key_size: int = DEFAULT_KEY_SIZE):
        logging.info("Initializing SecureConnectionServer")
        super().__init__()

        try:
            logging.info(f"Listening for clients on {ip}:{port}")
            self.listen_for_clients(ip, port)
            logging.info("SecureConnectionServer initialized successfully")
        except Exception as e:
            logging.error(f"Error initializing SecureConnectionServer: {e}")
            raise e

    def listen_for_clients(self, ip, port):
        try:
            self.socket.bind((ip, port))
            self.socket.listen(5)
            logging.info(f"Server listening on {ip}:{port}")
            while not self.conn:
                client_socket, addr = self.socket.accept()
                logging.info(f"Accepted connection from {addr}")
                self.conn = client_socket
                print(self.conn)
                self.other_public_key_RSA = self.exchange_keys_RSA(client_socket, self.my_public_key_pem)
                if self.other_public_key_RSA is None:
                    raise Exception("Failed to receive client's public RSA key.")
                logging.info("RSA public key exchange successful")
                self.send_AES_key(client_socket, self.my_symmetric_key_AES)
                logging.info("AES key exchange successful")
        except Exception as e:
            logging.error(f"Error while listening for clients: {e}")
            raise e
