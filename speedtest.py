import time
import logging
import threading
import os
from connection_module import SecureConnectionClient, SecureConnectionServer

logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.FileHandler("speed_test.log"),
                        logging.StreamHandler()
                    ])

SERVER_IP = "127.0.0.1"
SERVER_PORT = 686

def generate_large_test_data(size_in_mb):
    return os.urandom(size_in_mb * 1024 * 1024)

TEST_DATA = generate_large_test_data(1) 

def server_task():
    try:
        server = SecureConnectionServer(SERVER_IP, SERVER_PORT)
        logging.info(f"Server initialized, waiting for connection...")
        start_time = time.time()
        server.send_data_AES(TEST_DATA)
        end_time = time.time()
        logging.info(f"Data sent")
        elapsed_time = end_time - start_time
        data_size_mb = len(TEST_DATA) / (1024 * 1024)
        speed = data_size_mb / elapsed_time

        logging.info(f"Data AES sent in {elapsed_time:.4f} seconds at a speed of {speed:.4f} MB/s")
    except Exception as e:
        logging.error(f"Server encountered an error: {e}")

def client_task():
    try:
        time.sleep(1)
        client = SecureConnectionClient(SERVER_IP, SERVER_PORT)
        logging.info(f"Client connected")
        time.sleep(2)
        start_time = time.time()
        data = client.receive_data_AES()
        end_time = time.time()
        logging.info(f"Data received")
        elapsed_time = end_time - start_time
        data_size_mb = len(TEST_DATA) / (1024 * 1024)
        speed = data_size_mb / elapsed_time 
        
        logging.info(f"Data AES received in {elapsed_time:.4f} seconds at a speed of {speed:.4f} MB/s")
    except Exception as e:
        logging.error(f"Client encountered an error: {e}")

def main():
    try:
        server_thread = threading.Thread(target=server_task)
        client_thread = threading.Thread(target=client_task)

        server_thread.start()
        client_thread.start()

        client_thread.join()
        server_thread.join()

        logging.info("AES data transfer speed test completed.")
    except Exception as e:
        logging.error(f"Main encountered an error: {e}")

if __name__ == "__main__":
    main()
