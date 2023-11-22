import sys
from PyQt5.QtWidgets import QApplication
from modules.server_RDP import Server

if __name__ == "__main__":
    try:
        app = QApplication([])
        server = Server()
        sys.exit(app.exec_())
    except Exception as e:
        print(f"An error occurred: {e}")