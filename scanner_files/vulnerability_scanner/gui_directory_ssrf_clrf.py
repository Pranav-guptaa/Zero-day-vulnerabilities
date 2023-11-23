import sys
import requests
from bs4 import BeautifulSoup
import socket
import urllib.parse
import re
from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QVBoxLayout, QWidget, QLabel, QTextEdit, QTextBrowser

class VulnerabilityCheckerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Vulnerability Checker")
        self.setGeometry(100, 100, 800, 600)

        self.url_label = QLabel("Enter URL:")
        self.url_input = QTextEdit()
        self.check_directory_button = QPushButton("Check Directory Vulnerability")
        self.check_ssrf_button = QPushButton("Check SSRF Vulnerability")
        self.check_crlf_button = QPushButton("Check CRLF Vulnerability")
        self.results_text = QTextBrowser()
        self.results_text.setPlainText("Results will be displayed here.")

        self.check_directory_button.clicked.connect(self.check_directory_vulnerability)
        self.check_ssrf_button.clicked.connect(self.check_ssrf_vulnerability)
        self.check_crlf_button.clicked.connect(self.check_crlf_vulnerability)

        layout = QVBoxLayout()
        layout.addWidget(self.url_label)
        layout.addWidget(self.url_input)
        layout.addWidget(self.check_directory_button)
        layout.addWidget(self.check_ssrf_button)
        layout.addWidget(self.check_crlf_button)
        layout.addWidget(self.results_text)

        central_widget = QWidget()
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

    def append_result(self, result):
        current_text = self.results_text.toPlainText()
        self.results_text.setPlainText(current_text + "\n" + result)
        
    def check_directory_vulnerability(self):
        url = self.url_input.toPlainText()
        if not url:
            self.append_result("URL is required.")
            return

        try:
            print("Starting directory vulnerability check on {}".format(url))
            base_url = url.rstrip('/') + '/'
            for directory in self.find_directory(url):
                print("Checking {}".format(directory))
                status_code = self.test_directory(base_url, directory)
                if status_code == 200:
                    self.append_result("Potential directory vulnerability found at {}".format(directory))
                else:
                    self.append_result("No directory vulnerability found at {}".format(directory))
        except requests.exceptions.RequestException as e:
            self.append_result("An error occurred: {}".format(e))

    def find_directory(self, url):
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        for link in soup.find_all('a'):
            href = link.get('href')
            if href.startswith('/') and not href.startswith('//'):
                yield href

    def test_directory(self, base_url, directory):
        url = base_url + directory
        response = requests.get(url)
        return response.status_code

    def check_ssrf_vulnerability(self):
        url = self.url_input.toPlainText()
        if not url:
            self.append_result("URL is required.")
            return

        ssrf_urls = [url]
        self.check_ssrf(ssrf_urls)

    def is_valid_hostname(self, hostname):
        if len(hostname) > 255:
            return False
        if hostname[-1] == ".":
            hostname = hostname[:-1]
        allowed = set(("A", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z"))
        return all(i in allowed for i in hostname)

    def is_ssrf_url(self, url):
        try:
            parts = urllib.parse.urlparse(url)
            hostname = parts.netloc
            if self.is_valid_hostname(hostname):
                try:
                    ip_address = socket.gethostbyname(hostname)
                    if ip_address in ("127.0.0.1", "255.255.255.255", "0.0.0.0"):
                        return True
                    return False
                except socket.gaierror:
                    return True
            else:
                return True
        except ValueError:
            return True

    def check_ssrf(self, urls):
        for url in urls:
            if self.is_ssrf_url(url):
                self.append_result(f"SSRF Detected: {url}")
            else:
                self.append_result(f"No SSRF Detected: {url}")

    def check_crlf_vulnerability(self):
        url = self.url_input.toPlainText()
        if not url:
            self.append_result("URL is required.")
            return

        self.vulnerability_check_crlf(url)

    def vulnerability_check_crlf(self, url):
        session = requests.Session()
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,/;q=0.8',
            'Connection': 'close'
        }

        try:
            response = session.get(url, headers=headers, timeout=10)
        except requests.exceptions.RequestException as err:
            self.append_result("Oops: Something Else Happened", err)
            return

        content = response.text

        # Check if content is binary or text-based
        if content.strip() == "":
            return

        # Check if CRLF (CRFLF) present
        regex = r'(?:\r\n){2,}'
        matches = re.findall(regex, content)
        if matches:
            self.append_result(f"Possible CRLF vulnerability found in URL: {url}")
        else:
            self.append_result(f"No CRLF vulnerability found in URL: {url}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = VulnerabilityCheckerApp()
    window.show()
    sys.exit(app.exec_())
