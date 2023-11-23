import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QLabel, QFileDialog, QTextBrowser, QVBoxLayout, QWidget
from requests_html import HTMLSession

class ContentSpoofingCheckerApp(QMainWindow):
    def __init__(self):
        super().__init__()

        self.init_ui()

    def init_ui(self):
        self.setWindowTitle('Content Spoofing Checker')
        self.setGeometry(100, 100, 800, 600)

        self.central_widget = QWidget(self)
        self.setCentralWidget(self.central_widget)

        self.layout = QVBoxLayout()

        result_label = QLabel('Results:')
        self.layout.addWidget(result_label)

        self.result_text_browser = QTextBrowser()
        self.layout.addWidget(self.result_text_browser)

        file_label = QLabel('Select a file to check websites:')
        self.layout.addWidget(file_label)

        self.check_button = QPushButton('Check Websites from File')
        self.check_button.clicked.connect(self.browse_file)
        self.layout.addWidget(self.check_button)

        self.scan_button = QPushButton('Scan')
        self.scan_button.clicked.connect(self.scan_websites)
        self.layout.addWidget(self.scan_button)

        self.central_widget.setLayout(self.layout)

        self.file_path = None

    def browse_file(self):
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getOpenFileName(self, "Select a file", "", "Text Files (*.txt);;All Files (*)", options=options)

        if file_path:
            self.result_text_browser.clear()
            self.file_path = file_path
            self.result_text_browser.append(f"Selected file: {self.file_path}")

    def scan_websites(self):
        if self.file_path:
            self.result_text_browser.clear()
            self.check_content_spoofing(self.file_path)
        else:
            self.result_text_browser.append("Please select a file first.")

    def check_content_spoofing(self, file_path):
        result_found = False
        with open(file_path, 'r') as file:
            for line in file:
                parts = line.strip().split(' ')
                if len(parts) == 2:
                    website_url, website_ip = parts[0], parts[1]
                    self.result_text_browser.append(f"Checking {website_url} ({website_ip}):")
                    spoofing_result = self.do_content_spoofing_check(website_url)
                    if spoofing_result:
                        self.result_text_browser.append(spoofing_result)
                        result_found = True

        if not result_found:
            self.result_text_browser.append("No content spoofing detected in the provided websites.")

    def do_content_spoofing_check(self, url):
        session = HTMLSession()
        try:
            r = session.get(url)
            r.html.render()
        except Exception as e:
            error_message = f"An error occurred: {e}"
            self.result_text_browser.append(error_message)
            return error_message

        page_url = r.url
        page_title = r.html.xpath('//title', first=True).text

        if url == page_url:
            result = f"No Content Spoofing detected for URL: {url}\n"
            self.result_text_browser.append(result)
            return result
        else:
            result = f"Content Spoofing detected for URL: {url}\nActual URL: {page_url}\nActual Title: {page_title}\n"
            self.result_text_browser.append(result)
            return result

def main():
    app = QApplication(sys.argv)
    window = ContentSpoofingCheckerApp()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
