import socket
import logging
import struct
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

DEFAULT_BUFFER_SIZE = 1024
DEFAULT_SOCKET_TIMEOUT = 5
DEFAULT_KEY_SIZE = 1024

logging.basicConfig(level=logging.INFO)
class SecureConnectionFramework:
    def __init__(self):
        self.private_key_pem, self.public_key_pem = self.generate_keys()
        self.socket = None
        self.connected = False
        self.client_public_key = None
        self.server_public_key = None
        self.conn = None
        self.initialize_socket()

    def initialize_socket(self):
        try:
            logging.info("Initializing socket")

            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            logging.info("Socket created successfully")

            #self.socket.settimeout(self.DEFAULT_SOCKET_TIMEOUT)
            #logging.info(f"Socket timeout set to {self.DEFAULT_SOCKET_TIMEOUT} seconds")

        except Exception as e:
            logging.error(f"Error initializing TCP socket: {e}")
            raise e


    def start_connection(self, server_ip: str, server_port: int):
        try:
            logging.info(f"Connecting to server {server_ip}:{server_port}")

            self.socket.connect((server_ip, server_port))
            logging.info("Socket connected successfully")

            logging.info(f"Transferring public key to server: {self.public_key_pem}")
            self.server_public_key = self.exchange_keys(self.socket, self.public_key_pem)
            logging.info("Key exchange successful")

            self.connected = True
            logging.info("Connection established successfully")

        except socket.timeout as e:
            logging.error(f"Connection to {server_ip}:{server_port} timed out: {e}")
            raise e

        except (socket.error, ConnectionError) as e:
            logging.error(f"Error while starting connection: {e}")
            raise e
    
    def listen_for_clients(self, ip: str, port: int):
        if ip and port:
            try:
                logging.info(f"Listening for clients on {ip}:{port}")
                
                self.socket.bind((ip, port))
                logging.info(f"Socket bound to {ip}:{port}")
                
                self.socket.listen()
                logging.info("Socket listening for incoming connections")

                self.conn, self.addr = self.socket.accept()
                logging.info(f"Accepted connection from {self.addr}")
                
                logging.info(f"Transferring public key to client: {self.public_key_pem}")
                self.client_public_key = self.exchange_keys(self.conn, self.public_key_pem)
                logging.info("Key exchange successful")
                
                self.connected = True
                logging.info("Connection established successfully")
                
            except Exception as e:
                logging.error(f"Error while listening for clients: {e}")
                raise e
        else: 
            logging.error(f"Error while listening for clients: ip or port is None. ip:{ip}, port:{port}")
            raise ValueError(f"Error while listening for clients: ip or port is None. ip:{ip}, port:{port}")
        
    def send_data(self, data):
        try:
            if not data:
                raise ValueError("Data cannot be empty.")

            if self.socket:
                logging.info(f"Sending data: {data}")

                if self.client_public_key:
                    if isinstance(data, str):
                        data_bytes = data.encode('utf-8')
                    elif isinstance(data, bytes):
                        data_bytes = data
                    else:
                        raise ValueError("Unsupported data type. Supported types: str, bytes.")

                    key_size_bytes = (self.client_public_key.key_size + 7) // 8

                    max_encryption_size = key_size_bytes - 2 * hashes.SHA256.digest_size - 2
                    chunk_size = max_encryption_size if max_encryption_size < len(data_bytes) else len(data_bytes)

                    chunks = [data_bytes[i:i + chunk_size] for i in range(0, len(data_bytes), chunk_size)]
                    
                    num_chunks = len(chunks)
                    if self.conn:
                        self.conn.sendall(struct.pack('!I', num_chunks))
                    elif self.socket:
                        self.socket.sendall(struct.pack('!I', num_chunks))
                    else:
                        raise Exception("Neither socket nor conn is present, unable to send data")
                    
                    for chunk in chunks:
                        bytes_encrypted = self.encrypt_bytes(chunk, self.client_public_key)

                        data_size_packed = struct.pack('!I', len(bytes_encrypted))

                        if self.conn:
                            self.conn.sendall(data_size_packed)
                            self.conn.sendall(bytes_encrypted)
                        elif self.socket:
                            self.socket.sendall(data_size_packed)
                            self.socket.sendall(bytes_encrypted)
                        else:
                            raise Exception("Neither socket nor conn is present, unable to send data")
                elif self.server_public_key:
                    if isinstance(data, str):
                        data_bytes = data.encode('utf-8')
                    elif isinstance(data, bytes):
                        data_bytes = data
                    else:
                        raise ValueError("Unsupported data type. Supported types: str, bytes.")

                    key_size_bytes = (self.server_public_key.key_size + 7) // 8

                    max_encryption_size = key_size_bytes - 2 * hashes.SHA256.digest_size - 2
                    chunk_size = max_encryption_size if max_encryption_size < len(data_bytes) else len(data_bytes)

                    chunks = [data_bytes[i:i + chunk_size] for i in range(0, len(data_bytes), chunk_size)]

                    num_chunks = len(chunks)
                    if self.conn:
                        self.conn.sendall(struct.pack('!I', num_chunks))
                    elif self.socket:
                        self.socket.sendall(struct.pack('!I', num_chunks))
                    else:
                        raise Exception("Neither socket nor conn is present, unable to send data")

                    for chunk in chunks:
                        bytes_encrypted = self.encrypt_bytes(chunk, self.server_public_key)

                        data_size_packed = struct.pack('!I', len(bytes_encrypted))
                        if self.conn:
                            self.conn.sendall(data_size_packed)
                            self.conn.sendall(bytes_encrypted)
                        elif self.socket:
                            self.socket.sendall(data_size_packed)
                            self.socket.sendall(bytes_encrypted)
                        else:
                            raise Exception("Neither socket nor conn is present, unable to send data")
                else:
                    raise ValueError("Cannot send data: public key is not provided")

                logging.info("Data sent successfully")
            else:
                logging.error("Socket is not open.")

        except ValueError as ve:
            logging.error(f"ValueError while sending data: {ve}")
            raise ve

        except Exception as e:
            logging.error(f"Error while sending data: {e}")
            raise e

    def receive_data(self, size: int = DEFAULT_BUFFER_SIZE):
        try:
            if self.conn:
                received_chunks = []

                # Receiving the number of chunks
                num_chunks_packed = self.conn.recv(4)
                num_chunks = struct.unpack('!I', num_chunks_packed)[0]

                for _ in range(num_chunks):
                    data_size_packed = self.conn.recv(4)
                    data_size = struct.unpack('!I', data_size_packed)[0]
                    chunk_size = min(data_size, size)

                    received_chunk = self.conn.recv(chunk_size)
                    received_chunks.append(self.decrypt_message(received_chunk, self.private_key_pem))

                received_bytes = b''.join(received_chunks)
            elif self.socket:
                received_chunks = []

                # Receiving the number of chunks
                num_chunks_packed = self.socket.recv(4)
                num_chunks = struct.unpack('!I', num_chunks_packed)[0]

                for _ in range(num_chunks):
                    data_size_packed = self.socket.recv(4)
                    data_size = struct.unpack('!I', data_size_packed)[0]
                    chunk_size = min(data_size, size)

                    received_chunk = self.socket.recv(chunk_size)
                    received_chunks.append(self.decrypt_message(received_chunk, self.private_key_pem))

                received_bytes = b''.join(received_chunks)
            else:
                raise Exception("Cannot receive data: neither conn nor socket is present")

            if received_bytes:
                logging.info(f"Decrypted data: {received_bytes}")
                return received_bytes
            else:
                logging.warning("Received empty data")

        except Exception as e:
            logging.error(f"Error while receiving data: {e}")
            raise e

    def encrypt_bytes(self, data_bytes, public_key_pem):
        try:
            if not isinstance(data_bytes, bytes):
                data_bytes = data_bytes.encode('utf-8')

            if isinstance(public_key_pem, rsa.RSAPublicKey):
                public_key = public_key_pem
            else:
                public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())

            logging.info(f"Length of data before encryption: {len(data_bytes)}")

            encrypted = public_key.encrypt(
                data_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            logging.info(f"Data after encryption {encrypted}")
            return encrypted
        except Exception as e:
            logging.error(f"Error while encrypting bytes: {e}")
            raise e

    def decrypt_message(self, encrypted_message, private_key_pem):
        try:
            logging.info(f"Length of encrypted message: {len(encrypted_message)}")
            logging.info(f"Decrypting message: {encrypted_message}")

            private_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())

            logging.info(f"Key size used for decryption: {private_key.key_size}")

            original_message = private_key.decrypt(
                encrypted_message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            logging.info(f"Message decrypted successfully: {original_message}")
            return original_message

        except Exception as e:
            logging.error(f"Error while decrypting bytes: {e}")
            raise e

    
    def generate_keys(self, key_size: int = DEFAULT_KEY_SIZE):
        try:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=default_backend()
            )
            public_key = private_key.public_key()

            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )

            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            return private_pem, public_pem
        except Exception as e:
            
            logging.error(f"Error while generating keys: {e}")
            raise e

    def exchange_keys(self, socket_to_use, public_key_pem=None):
        try:
            if public_key_pem is not None:
                key_size_packed = struct.pack('!I', len(public_key_pem))
                socket_to_use.sendall(key_size_packed)
                socket_to_use.sendall(public_key_pem)

            key_size_packed = socket_to_use.recv(4)
            print(f"Received key size packed: {key_size_packed}")

            if len(key_size_packed) < 4:
                raise ValueError("Insufficient data received for key size.")

            key_size = struct.unpack('!I', key_size_packed)[0]
            print(f"Expecting key size: {key_size}")

            key_pem = socket_to_use.recv(key_size)
            print(f"Received key pem: {key_pem}")

            if len(key_pem) < key_size:
                raise ValueError("Insufficient data received for public key.")

            key = serialization.load_pem_public_key(key_pem, backend=default_backend())
            return key
        except Exception as e:
            
            logging.error(f"Error during key exchange: {e}")
            raise e

    def close(self):
        if self.socket:
            self.socket.close()

class SecureConnectionClient(SecureConnectionFramework):
    def __init__(self, server_ip: str = None, server_port: int = None, key_size: int = DEFAULT_KEY_SIZE):
        logging.info("Initializing SecureConnectionClient")
        super().__init__()

        try:
            logging.info(f"Generating keys with key size: {key_size}")
            self.key_size = key_size

            logging.info(f"Starting connection to server {server_ip}:{server_port}")
            self.start_connection(server_ip, server_port)
            
            logging.info("SecureConnectionClient initialized successfully")

        except Exception as e:
            
            logging.error(f"Error initializing SecureConnectionClient: {e}")
            raise e

            
class SecureConnectionServer(SecureConnectionFramework):
    def __init__(self, ip: str = None, port: int = None, key_size: int = DEFAULT_KEY_SIZE):
        logging.info("Initializing SecureConnectionServer")
        super().__init__()

        try:
            logging.info(f"Generating keys with key size: {key_size}")
            self.key_size = key_size

            self.address = ip
            self.port = port

            logging.info(f"Listening for clients on {ip}:{port}")
            self.listen_for_clients(ip, port)

            logging.info("SecureConnectionServer initialized successfully")

        except Exception as e:
            
            logging.error(f"Error initializing SecureConnectionServer: {e}")
            raise e
