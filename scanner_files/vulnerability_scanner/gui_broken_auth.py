import os
import sys
import requests
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit, QFileDialog

class BrokenAuthTester(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Broken Authentication Tester')
        self.setGeometry(100, 100, 800, 600)

        self.target_url_label = QLabel('Target URL:')
        self.target_url_input = QLineEdit()

        self.username_label = QLabel('Username File:')
        self.username_input = QLineEdit()
        self.browse_username_button = QPushButton('Browse for Username File')
        self.browse_username_button.clicked.connect(self.browse_username_file)

        self.password_label = QLabel('Password File:')
        self.password_input = QLineEdit()
        self.browse_password_button = QPushButton('Browse for Password File')
        self.browse_password_button.clicked.connect(self.browse_password_file)

        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)

        self.test_button = QPushButton('Test Authentication')
        self.test_button.clicked.connect(self.test_authentication)  # Corrected method name

        layout = QVBoxLayout()
        layout.addWidget(self.target_url_label)
        layout.addWidget(self.target_url_input)

        username_layout = QVBoxLayout()
        username_layout.addWidget(self.username_label)
        username_layout.addWidget(self.username_input)
        username_layout.addWidget(self.browse_username_button)

        password_layout = QVBoxLayout()
        password_layout.addWidget(self.password_label)
        password_layout.addWidget(self.password_input)
        password_layout.addWidget(self.browse_password_button)

        layout.addLayout(username_layout)
        layout.addLayout(password_layout)

        layout.addWidget(self.test_button)
        layout.addWidget(self.result_text)

        self.setLayout(layout)

    def browse_username_file(self):
        options = QFileDialog.Options()
        options |= QFileDialog.ReadOnly
        username_file, _ = QFileDialog.getOpenFileName(self, 'Select Username File', '', 'Text Files (*.txt);;All Files (*)', options=options)
        if username_file:
            self.username_input.setText(username_file)

    def browse_password_file(self):
        options = QFileDialog.Options()
        options |= QFileDialog.ReadOnly
        password_file, _ = QFileDialog.getOpenFileName(self, 'Select Password File', '', 'Text Files (*.txt);;All Files (*)', options=options)
        if password_file:
            self.password_input.setText(password_file)

    def test_authentication(self):  # Corrected method name
        target_url = self.target_url_input.text()
        username_file = self.username_input.text()
        password_file = self.password_input.text()

        if not target_url or not username_file or not password_file:
            self.result_text.append("Please provide valid inputs.")
            return

        self.result_text.clear()
        if not os.path.exists(username_file) or not os.path.exists(password_file):
            self.result_text.append("Username or password file not found.")
            return

        with open(username_file, 'r') as user_file, open(password_file, 'r') as pass_file:
            users = user_file.readlines()
            passwords = pass_file.readlines()

            for user in users:
                for password in passwords:
                    response = requests.post(target_url, data={"username": user.strip(), "password": password.strip()})

                    if response.status_code == 200:
                        self.result_text.append(f"Successfully authenticated with username '{user.strip()}' and password '{password.strip()}'")
                        return
                    else:
                        self.result_text.append(f"Failed to authenticate with username '{user.strip()}' and password '{password.strip()}'")

        self.result_text.append("Finished testing broken authentication.")

def main():
    app = QApplication(sys.argv)
    auth_tester = BrokenAuthTester()
    auth_tester.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
