import sys
import requests
from PyQt5.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget, QLabel, QTextBrowser, QPushButton, QFileDialog

class WebsiteVulnerabilityCheckerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Website Vulnerability Checker")
        self.setGeometry(100, 100, 800, 600)

        self.file_label = QLabel("Select a file containing website URLs:")
        self.file_path = None
        self.browse_button = QPushButton("Browse")
        self.check_button = QPushButton("Check Vulnerabilities")
        self.results_text = QTextBrowser()
        self.results_text.setPlainText("Results will be displayed here.")

        self.browse_button.clicked.connect(self.browse_file)
        self.check_button.clicked.connect(self.check_vulnerabilities)

        layout = QVBoxLayout()
        layout.addWidget(self.file_label)
        layout.addWidget(self.browse_button)
        layout.addWidget(self.check_button)
        layout.addWidget(self.results_text)

        central_widget = QWidget()
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

    def browse_file(self):
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File", "", "Text Files (*.txt);;All Files (*)", options=options)
        if file_path:
            self.file_path = file_path
            self.file_label.setText(f"Selected File: {self.file_path}")

    def append_result(self, result):
        current_text = self.results_text.toPlainText()
        self.results_text.setPlainText(current_text + "\n" + result)

    def check_website_vulnerability(self, url):
        try:
            headers = requests.get(url).headers
            vulnerable_headers = []

            if 'Content-Security-Policy' not in headers:
                vulnerable_headers.append('Content-Security-Policy')

            if 'X-Content-Type-Options' not in headers or headers.get('X-Content-Type-Options') != 'nosniff':
                vulnerable_headers.append('X-Content-Type-Options')

            if 'X-Frame-Options' not in headers or headers.get('X-Frame-Options') not in ['DENY', 'SAMEORIGIN']:
                vulnerable_headers.append('X-Frame-Options')

            if 'Strict-Transport-Security' not in headers or 'max-age' not in headers.get('Strict-Transport-Security'):
                vulnerable_headers.append('Strict-Transport-Security')

            if 'X-XSS-Protection' not in headers or headers.get('X-XSS-Protection') not in ['1; mode=block', '1']:
                vulnerable_headers.append('X-XSS-Protection')

            if vulnerable_headers:
                self.append_result(f"The website {url} is vulnerable to information disclosure due to missing or misconfigured security headers:")
                for header in vulnerable_headers:
                    self.append_result(f" - {header}")
            else:
                self.append_result(f"The website {url} is not vulnerable to information disclosure.")
        except requests.exceptions.RequestException as err:
            self.append_result(f"Error while checking website {url}: {err}")

    def check_vulnerabilities(self):
        if self.file_path:
            with open(self.file_path, 'r') as file:
                for line in file:
                    website_url = line.strip()
                    self.check_website_vulnerability(website_url)
        else:
            self.append_result("Please select a file containing website URLs.")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = WebsiteVulnerabilityCheckerApp()
    window.show()
    sys.exit(app.exec_())
