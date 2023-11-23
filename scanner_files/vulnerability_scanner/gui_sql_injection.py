import sys
import requests
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QVBoxLayout, QWidget, QLabel, QTextEdit, QFileDialog, QTextBrowser

class SQLInjectionScannerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle("SQL Injection Scanner")
        self.setGeometry(100, 100, 800, 600)

        self.results_text = QTextBrowser()
        self.results_text.setPlainText("Results will be displayed here.")
        self.url_label = QLabel("Enter URL:")
        self.url_input = QTextEdit()
        self.payload_label = QLabel("Select Payload File:")
        self.payload_input = QTextEdit()
        self.browse_button = QPushButton("Browse")
        self.scan_button = QPushButton("Scan for SQL Injection")

        self.browse_button.clicked.connect(self.browse_payload)
        self.scan_button.clicked.connect(self.scan_sql_injection)

        layout = QVBoxLayout()
        layout.addWidget(self.url_label)
        layout.addWidget(self.url_input)
        layout.addWidget(self.payload_label)
        layout.addWidget(self.payload_input)
        layout.addWidget(self.browse_button)
        layout.addWidget(self.scan_button)
        layout.addWidget(self.results_text)

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
            input_value = input_tag.attrs.get("value", "")
            inputs.append({"type": input_type, "name": input_name, "value": input_value})
        details["action"] = action
        details["method"] = method
        details["inputs"] = inputs
        return details

    def is_vulnerable(self, response):
        errors = {
            "you have an error in your sql syntax;",
            "warning: mysql",
            "unclosed quotation mark after the character string",
            "quoted string not properly terminated",
        }
        for error in errors:
            if error in response.content.decode().lower():
                return True
        return False

    def scan_sql_injection(self):
        url = self.url_input.toPlainText()
        payload_file = self.payload_input.toPlainText()

        if not url:
            self.append_result("URL is required.")
            return

        if not payload_file:
            self.append_result("Payload file is required.")
            return

        with open(payload_file, 'r') as file:
            payloads = file.read().splitlines()

        for payload in payloads:
            forms = self.get_all_forms(url)
            self.append_result(f"[+] Detected {len(forms)} forms on {url}.")
            is_vulnerable = False

            for form in forms:
                form_details = self.get_form_details(form)
                for c in "\"'":
                    data = {}
                    for input_tag in form_details["inputs"]:
                        if input_tag["type"] == "hidden" or input_tag["value"]:
                            try:
                                data[input_tag["name"]] = input_tag["value"] + c
                            except:
                                pass
                        elif input_tag["type"] != "submit":
                            data[input_tag["name"]] = f"test{c}"

                    url = urljoin(url, form_details["action"])
                    if form_details["method"] == "post":
                        res = requests.post(url, data=data)
                    elif form_details["method"] == "get":
                        res = requests.get(url, params=data)

                    if self.is_vulnerable(res):
                        self.append_result("[+] SQL Injection vulnerability detected.")
                        self.append_result("[+] Form:")
                        self.append_result(str(form_details))
                        is_vulnerable = True
                        break

            if is_vulnerable:
                self.append_result("Website is vulnerable to SQL Injection.")
                break

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SQLInjectionScannerApp()
    window.show()
    sys.exit(app.exec_())
