import socket
import struct
import os
import numpy as np
import cv2
from PIL import Image
import io

def read_from_connection(connection, size):
    buffer = b''
    while len(buffer) < size:
        try:
            data = connection.recv(size - len(buffer))
            if not data:
                raise ConnectionError("Connection closed by peer")
            buffer += data
        except socket.error as e:
            raise ConnectionError(f"Socket error: {e}")
    return buffer

def wait_for_connection(port):
    s = socket.create_server(("", port))
    conn, addr = s.accept()
    return conn, addr

def get_file_and_write(connection, filename):
    with open(filename, "wb+") as file:
        size_data = read_from_connection(connection, 4)
        size = struct.unpack("I", size_data)[0]
        data = read_from_connection(connection, size)
        file.write(data)
    
def send_file(connection, filename):
    with open(filename, "rb") as file:
        size = os.path.getsize(filename)
        connection.send(struct.pack("I", size))
        while data := file.read(4096):
            connection.send(data)

def send_string_into_connection(connection, string):
    string_encoded = string.encode()
    length = len(string)
    connection.send(length.to_bytes(length=4, byteorder='little'))
    connection.send(string_encoded)

def read_string_from_connection(connection):
    length = connection.recv(4)
    length = struct.unpack("I", length)[0]
    string = connection.recv(length)
    return string.decode()

def get_bytes_from_connection(connection):
    length = connection.recv(4)
    length = struct.unpack("I", length)[0]
    bts = connection.recv(length)
    return bts

def send_image(connection, image):
    if not isinstance(image, np.ndarray):
        image = np.array(image)
    ret, encoded_image = cv2.imencode(".jpg", image)
    if not ret:
        raise ValueError("Image encoding failed")
    image_bytes = encoded_image.tobytes()
    connection.sendall(struct.pack("!I", len(image_bytes)))
    connection.sendall(image_bytes)

def receive_image(connection):
    image_size_data = read_from_connection(connection, 4)
    image_size = struct.unpack('!I', image_size_data)[0]
    image_data = read_from_connection(connection, image_size)
    image = Image.open(io.BytesIO(image_data))
    frame = np.array(image)
    return frame