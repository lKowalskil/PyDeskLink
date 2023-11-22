import socket
import struct
import os

def read_from_connection(connection, size):
    buffer = b''
    while len(buffer) < size:
        buffer += connection.recv(size - len(buffer))
    return buffer

def wait_for_connection(port):
    s = socket.create_server(("", port))
    conn, addr = s.accept()
    return conn, addr

def get_file_and_write(connection, filename):
    file = open(filename, "wb+")
    size = connection.recv(4)
    size = struct.unpack("I", size)[0]
    data = connection.recv(size)
    file.write(data)
    file.close()
    
def send_file(connection, filename):
    file = open(filename, "rb")
    size = os.path.getsize(filename)
    data = file.read(size)
    size = size.to_bytes(length=4, byteorder='little')
    connection.send(size)
    connection.send(data)
    file.close()

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