import sys
import requests
from PyQt5.QtWidgets import QApplication, QMainWindow, QLabel, QLineEdit, QPushButton, QVBoxLayout, QWidget, QTextEdit

class ClickjackingTesterApp(QMainWindow):
    def __init__(self):
        super().__init__()

        self.initUI()

    def initUI(self):
        self.setWindowTitle('Clickjacking Tester')
        self.setGeometry(100, 100, 800, 600)

        self.url_label = QLabel('Enter the URL to test for clickjacking vulnerability:')
        self.url_input = QLineEdit()
        self.result_output = QTextEdit()
        self.result_output.setReadOnly(True)

        test_button = QPushButton('Test Clickjacking Vulnerability')
        test_button.clicked.connect(self.start_testing)

        layout = QVBoxLayout()
        layout.addWidget(self.url_label)
        layout.addWidget(self.url_input)
        layout.addWidget(test_button)
        layout.addWidget(self.result_output)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

    def start_testing(self):
        url = self.url_input.text()
        if not url.startswith(("http://", "https://")):
            url = "http://" + url  # Add http:// if not provided

        headers = requests.get(url).headers
        if 'X-Frame-Options' in headers:
            result = f"{url} is NOT VULNERABLE TO CLICKJACKING"
        else:
            result = f"{url} is VULNERABLE TO CLICKJACKING"

        self.result_output.setPlainText(result)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = ClickjackingTesterApp()
    window.show()
    sys.exit(app.exec_())
