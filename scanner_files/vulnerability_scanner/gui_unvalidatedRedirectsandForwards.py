import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QLabel, QFileDialog, QTextEdit, QVBoxLayout, QWidget
import requests
from urllib.parse import urlparse

def validate_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

def is_safe_url(url, safe_domains):
    try:
        result = urlparse(url)
        return result.netloc in safe_domains
    except ValueError:
        return False

def unvalidated_redirect_and_forward_check(target_url, user_agent='your user agent'):
    session = requests.Session()
    session.headers.update({'User-Agent': user_agent})
    response = session.get(target_url)

    safe_domains = ['google.com', 'yahoo.com', 'example.com']  # add more trusted domains here

    found_vulnerability = False

    for url in response.history:
        if not is_safe_url(url.url, safe_domains):
            results_text.append(f"Potential Unvalidated Redirect found at: {url.url}")
            found_vulnerability = True

    # For Forwards, we check if the initial response is a redirect and then validate if it's safe
    if response.is_redirect:
        if not is_safe_url(response.url, safe_domains):
            results_text.append(f"Potential Unvalidated Forward found at: {response.url}")
            found_vulnerability = True

    if not found_vulnerability:
        results_text.append("No potential vulnerabilities found in the provided URL.")

class VulnerabilityScannerApp(QMainWindow):
    def __init__(self):
        super().__init__()

        self.init_ui()

    def init_ui(self):
        self.setWindowTitle('Vulnerability Scanner')
        self.setGeometry(100, 100, 800, 600)

        self.central_widget = QWidget(self)
        self.setCentralWidget(self.central_widget)

        self.layout = QVBoxLayout()

        self.file_label = QLabel('Select a file to scan websites:')
        self.layout.addWidget(self.file_label)

        self.results_text_edit = QTextEdit()
        self.results_text_edit.setStyleSheet("QTextEdit { background-color: lightgray; }")
        self.layout.addWidget(self.results_text_edit)

        self.browse_button = QPushButton('Browse File')
        self.browse_button.clicked.connect(self.browse_file)
        self.layout.addWidget(self.browse_button)

        self.scan_button = QPushButton('Scan Websites')
        self.scan_button.clicked.connect(self.scan_websites)
        self.layout.addWidget(self.scan_button)

        self.central_widget.setLayout(self.layout)

        self.file_path = None

    def browse_file(self):
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getOpenFileName(self, "Select a file", "", "Text Files (*.txt);;All Files (*)", options=options)

        if file_path:
            self.file_path = file_path
            self.results_text_edit.clear()
            self.results_text_edit.append(f"Selected file: {self.file_path}")

    def scan_websites(self):
        if self.file_path:
            self.results_text_edit.clear()
            with open(self.file_path, 'r') as file:
                for line in file:
                    website_url = line.strip()
                    self.results_text_edit.append(f"Scanning website: {website_url}")
                    unvalidated_redirect_and_forward_check(website_url)
            
            self.results_text_edit.append("\n--- Summary of Results ---")
            for result in results_text:
                self.results_text_edit.append(result)
            self.results_text_edit.append("\n--- End of Scan ---")
        else:
            self.results_text_edit.append("Please select a file first.")

def main():
    app = QApplication(sys.argv)
    window = VulnerabilityScannerApp()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    results_text = []  # A list to store results
    main()
