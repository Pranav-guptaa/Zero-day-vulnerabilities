import sys
import requests
from PyQt5.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget, QLabel, QTextBrowser, QPushButton, QFileDialog

class InsecureFileUploadCheckerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.websites_file_path = None
        self.file_to_upload_path = None

    def initUI(self):
        self.setWindowTitle("Insecure File Upload Checker")
        self.setGeometry(100, 100, 800, 600)

        self.websites_file_label = QLabel("Select a file containing website URLs:")
        self.file_to_upload_label = QLabel("Select a file to upload:")
        self.browse_websites_button = QPushButton("Browse Websites File")
        self.browse_upload_button = QPushButton("Browse File to Upload")
        self.check_button = QPushButton("Check Insecure File Upload Vulnerabilities")
        self.results_text = QTextBrowser()
        self.results_text.setPlainText("Results will be displayed here.")

        self.browse_websites_button.clicked.connect(self.browse_websites_file)
        self.browse_upload_button.clicked.connect(self.browse_upload_file)
        self.check_button.clicked.connect(self.check_insecure_file_upload)

        layout = QVBoxLayout()
        layout.addWidget(self.websites_file_label)
        layout.addWidget(self.browse_websites_button)
        layout.addWidget(self.file_to_upload_label)
        layout.addWidget(self.browse_upload_button)
        layout.addWidget(self.check_button)
        layout.addWidget(self.results_text)

        central_widget = QWidget()
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

    def browse_websites_file(self):
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File", "", "Text Files (*.txt);;All Files (*)", options=options)
        if file_path:
            self.websites_file_path = file_path
            self.websites_file_label.setText(f"Selected Websites File: {self.websites_file_path}")

    def browse_upload_file(self):
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File", "", "All Files (*)", options=options)
        if file_path:
            self.file_to_upload_path = file_path
            self.file_to_upload_label.setText(f"Selected File to Upload: {self.file_to_upload_path}")

    def append_result(self, result):
        current_text = self.results_text.toPlainText()
        self.results_text.setPlainText(current_text + "\n" + result)

    def upload_file(self, url, file_path):
        try:
            files = {'file': open(file_path, 'rb')}
            response = requests.post(url, files=files)
            return response
        except requests.exceptions.RequestException as err:
            self.append_result(f"Error while uploading file to {url}: {err}")
            return None

    def check_insecure_file_upload(self):
        if self.websites_file_path and self.file_to_upload_path:
            with open(self.websites_file_path, 'r') as websites_file:
                for line in websites_file:
                    website_url = line.strip()
                    self.append_result(f"Checking {website_url} for insecure file upload...")
                    original_response = self.upload_file(website_url, self.file_to_upload_path)
                    if original_response is not None and original_response.status_code == 200:
                        malicious_file_path = "malicious_file.php"
                        malicious_file_content = "<?php echo 'Malicious File Uploaded!'; ?>"
                        with open(malicious_file_path, 'w') as malicious_file:
                            malicious_file.write(malicious_file_content)

                        malicious_response = self.upload_file(website_url, malicious_file_path)
                        if malicious_response is not None and malicious_response.status_code == 200:
                            response = requests.get(f"{website_url}/{malicious_file_path}")
                            if "Malicious File Uploaded!" in response.text:
                                self.append_result(f"The website {website_url} has an insecure file upload vulnerability.")
                            else:
                                self.append_result(f"The website {website_url} does not have an insecure file upload vulnerability.")
                        else:
                            self.append_result(f"The website {website_url} does not have an insecure file upload vulnerability.")
                    else:
                        self.append_result(f"The website {website_url} does not have an insecure file upload vulnerability.")
        else:
            self.append_result("Please select both the websites file and the file to upload.")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = InsecureFileUploadCheckerApp()
    window.show()
    sys.exit(app.exec_())
