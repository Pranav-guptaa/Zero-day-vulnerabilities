import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from collections import deque
import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QTextEdit, QPushButton, QFileDialog

class WebCrawlerApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Web Crawler')
        self.setGeometry(100, 100, 800, 600)

        self.start_url_label = QLabel('Starting URL:')
        self.start_url_input = QLineEdit()
        self.wordlist_label = QLabel('Word List (comma-separated):')
        self.wordlist_input = QLineEdit()
        self.max_depth_label = QLabel('Maximum Depth:')
        self.max_depth_input = QLineEdit()
        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)
        self.crawl_button = QPushButton('Crawl')
        self.crawl_button.clicked.connect(self.start_crawling)

        self.browse_wordlist_button = QPushButton('Browse for Wordlist')
        self.browse_wordlist_button.clicked.connect(self.browse_wordlist)

        layout = QVBoxLayout()
        layout.addWidget(self.start_url_label)
        layout.addWidget(self.start_url_input)
        layout.addWidget(self.wordlist_label)
        layout.addWidget(self.wordlist_input)
        layout.addWidget(self.browse_wordlist_button)
        layout.addWidget(self.max_depth_label)
        layout.addWidget(self.max_depth_input)
        layout.addWidget(self.crawl_button)
        layout.addWidget(self.result_text)

        self.setLayout(layout)

    def browse_wordlist(self):
        options = QFileDialog.Options()
        options |= QFileDialog.ReadOnly
        wordlist_file, _ = QFileDialog.getOpenFileName(self, 'Select Wordlist File', '', 'Text Files (*.txt);;All Files (*)', options=options)
        if wordlist_file:
            with open(wordlist_file, 'r') as file:
                wordlist = file.read()
                self.wordlist_input.setText(wordlist)
    def is_valid_url(self, url):
        return "http://" in url  # Add custom conditions here

    def get_links(self, url, html_content):
        links = set()
        soup = BeautifulSoup(html_content, "html.parser")
        for link in soup.find_all("a", href=True):
            href = link.get("href")
            full_url = urljoin(url, href)
            links.add(full_url)
        return links

    def crawl(self, start_url, wordlist, max_depth):
        visited = set()
        queue = deque([(start_url, 0)])

        while queue:
            url, depth = queue.popleft()
            if depth > max_depth:
                return

            try:
                response = requests.get(url)
                if response.status_code == 200:
                    html_content = response.text
                    words_found = []

                    for word in wordlist:
                        if word in html_content:
                            words_found.append(word)

                    if words_found:
                        self.result_text.append(f"Found {', '.join(words_found)} at: {url}")

                    visited.add(url)
                    links = self.get_links(url, html_content)

                    for link in links:
                        if link not in visited and self.is_valid_url(link):
                            queue.append((link, depth + 1))

            except Exception as e:
                self.result_text.append(f"Error while crawling {url}: {e}")

    def start_crawling(self):
        start_url = self.start_url_input.text()
        wordlist = self.wordlist_input.text().split(',')
        max_depth = int(self.max_depth_input.text())

        if not start_url or not wordlist or max_depth <= 0:
            self.result_text.setPlainText("Please provide valid input.")
            return

        self.result_text.clear()
        self.crawl(start_url, wordlist, max_depth)

def main():
    app = QApplication(sys.argv)
    crawler_app = WebCrawlerApp()
    crawler_app.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
