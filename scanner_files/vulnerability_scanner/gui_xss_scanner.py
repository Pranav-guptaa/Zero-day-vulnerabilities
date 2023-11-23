import sys
import requests
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QVBoxLayout, QWidget, QLabel, QTextEdit, QFileDialog

class XSSScannerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()
        
    def initUI(self):
        self.setWindowTitle("XSS Scanner")
        self.setGeometry(100, 100, 800, 600)  # Increase window size

        self.url_label = QLabel("Enter URL:")
        self.url_input = QTextEdit()
        self.payload_label = QLabel("Select Payload File:")
        self.payload_input = QTextEdit()
        self.browse_button = QPushButton("Browse")
        self.scan_button = QPushButton("Scan for XSS")
        self.results_text = QTextEdit()  # Initialize results_text here
        self.results_text.setReadOnly(True)
        
        self.browse_button.clicked.connect(self.browse_payload)
        self.scan_button.clicked.connect(self.scan_xss)

        layout = QVBoxLayout()
        layout.addWidget(self.url_label)
        layout.addWidget(self.url_input)
        layout.addWidget(self.payload_label)
        layout.addWidget(self.payload_input)
        layout.addWidget(self.browse_button)
        layout.addWidget(self.scan_button)
        layout.addWidget(self.results_text)  # Add results QTextEdit

        central_widget = QWidget()
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

    def browse_payload(self):
        options = QFileDialog.Options()
        payload_file, _ = QFileDialog.getOpenFileName(self, "Select Payload File", "", "Text Files (*.txt);;All Files (*)", options=options)
        if payload_file:
            self.payload_input.setPlainText(payload_file)

    def append_result(self, result):
        self.results_text.append(result)

    def get_all_forms(self, url):
        soup = bs(requests.get(url).content, "html.parser")
        return soup.find_all("form")

    def get_form_details(self, form):
        details = {}
        action = form.attrs.get("action", "").lower()
        method = form.attrs.get("method", "get").lower()
        inputs = []
        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            inputs.append({"type": input_type, "name": input_name})
        details["action"] = action
        details["method"] = method
        details["inputs"] = inputs
        return details

    def submit_form(self, form_details, url, value):
        target_url = urljoin(url, form_details["action"])
        inputs = form_details["inputs"]
        data = {}
        for input in inputs:
            if input["type"] == "text" or input["type"] == "search":
                input["value"] = value
            input_name = input.get("name")
            input_value = input.get("value")
            if input_name and input_value:
                data[input_name] = input_value

        self.append_result(f"[+] Submitting malicious payload to {target_url}")
        self.append_result(f"[+] Data: {data}")
        if form_details["method"] == "post":
            response = requests.post(target_url, data=data)
        else:
            response = requests.get(target_url, params=data)
        self.append_result(f"[+] Response Status Code: {response.status_code}")
        return response

    def scan_xss(self):
        url = self.url_input.toPlainText()
        payload_file = self.payload_input.toPlainText()

        if not url:
            self.append_result("URL is required.")
            return

        if not payload_file:
            self.append_result("Payload file is required.")
            return

        with open(payload_file, 'r') as file:
            js_script = file.read()

        forms = self.get_all_forms(url)
        self.append_result(f"[+] Detected {len(forms)} forms on {url}.")
        is_vulnerable = False

        for form in forms:
            form_details = self.get_form_details(form)
            content = self.submit_form(form_details, url, js_script).content.decode()
            if js_script in content:
                self.append_result(f"[+] XSS Detected on {url}")
                self.append_result(f"[*] Form details:")
                self.append_result(str(form_details))
                is_vulnerable = True

        if is_vulnerable:
            self.append_result("Website is vulnerable to XSS.")
        else:
            self.append_result("No vulnerabilities found.")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = XSSScannerApp()
    window.show()
    sys.exit(app.exec_())
