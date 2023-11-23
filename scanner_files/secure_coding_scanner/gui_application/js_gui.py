import sys
import os
import re
import subprocess
from PyQt5.QtCore import Qt, QCoreApplication
from PyQt5.QtCore import Qt, QDir, QThread, pyqtSignal
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QTextEdit, QPushButton, QApplication, QFileDialog, QProgressBar, QGroupBox
from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QFileDialog, QTextEdit, QVBoxLayout

javascript_ruleset = {
   
    'eval': {
        'severity': 'High',
        'description': 'The use of eval can introduce code injection vulnerabilities',
        'recommendation': 'Avoid using eval whenever possible; use safer alternatives',
        'category': 'Code Injection',
        'parameters': {},
        'rule_id': 'JS1001'
    },
    'innerHTML': {
        'severity': 'High',
        'description': 'Manipulating innerHTML with unvalidated data can lead to XSS vulnerabilities',
        'recommendation': 'Avoid directly setting innerHTML with unvalidated data; use safe DOM manipulation methods',
        'category': 'Cross-Site Scripting (XSS)',
        'parameters': {},
        'rule_id': 'JS1002'
    },
    'localStorage': {
        'severity': 'Medium',
        'description': 'Storing sensitive data in localStorage can be insecure',
        'recommendation': 'Do not store sensitive information in localStorage; use secure storage solutions',
        'category': 'Data Security',
        'parameters': {},
        'rule_id': 'JS1003'
    },
    'XMLHttpRequest': {
        'severity': 'High',
        'description': 'Lack of proper CORS handling can lead to security issues',
        'recommendation': 'Always validate and control cross-origin requests; implement proper CORS policies',
        'category': 'Cross-Origin Resource Sharing (CORS)',
        'parameters': {},
        'rule_id': 'JS1004'
    },
    'setTimeout|setInterval': {
        'severity': 'Medium',
        'description': 'Insecure use of setTimeout or setInterval can introduce security vulnerabilities',
        'recommendation': 'Avoid using timers for security-critical operations; implement proper security checks',
        'category': 'Security Controls',
        'parameters': {},
        'rule_id': 'JS1005'
    },
    'WebSockets': {
        'severity': 'High',
        'description': 'Improper handling of WebSocket connections can lead to security issues',
        'recommendation': 'Implement proper security measures when using WebSockets; validate incoming data',
        'category': 'Web Security',
        'parameters': {},
        'rule_id': 'JS1006'
    },
    'React dangerouslySetInnerHTML': {
        'severity': 'High',
        'description': 'Using dangerouslySetInnerHTML in React can lead to XSS vulnerabilities',
        'recommendation': 'Avoid using dangerouslySetInnerHTML; prefer safe React components',
        'category': 'Cross-Site Scripting (XSS)',
        'parameters': {},
        'rule_id': 'JS1007'
    },
    'Crypto.getRandomValues': {
        'severity': 'Medium',
        'description': 'Insecure random number generation can compromise security',
        'recommendation': 'Use secure random number generation methods provided by the platform',
        'category': 'Cryptographic Security',
        'parameters': {},
        'rule_id': 'JS1008'
    },
    'localStorage.getItem': {
        'severity': 'High',
        'description': 'Insecure access to localStorage data can lead to data exposure',
        'recommendation': 'Implement proper access controls and data validation for localStorage access',
        'category': 'Data Security',
        'parameters': {},
        'rule_id': 'JS1009'
    },
    'JSON.parse': {
        'severity': 'Medium',
        'description': 'Unvalidated parsing of JSON data can lead to security vulnerabilities',
        'recommendation': 'Always validate and sanitize input before parsing JSON data',
        'category': 'Data Security',
        'parameters': {},
        'rule_id': 'JS1010'
    },
    'fetch': {
        'severity': 'High',
        'description': 'Improper use of the fetch API can lead to security issues, such as CORS misconfigurations',
        'recommendation': 'Always validate and control cross-origin requests when using the fetch API',
        'category': 'Cross-Origin Resource Sharing (CORS)',
        'parameters': {},
        'rule_id': 'JS1011'
    },
    'localStorage.setItem': {
        'severity': 'High',
        'description': 'Insecure writing to localStorage can lead to data exposure or tampering',
        'recommendation': 'Implement proper access controls and validate input data before writing to localStorage',
        'category': 'Data Security',
        'parameters': {},
        'rule_id': 'JS1012'
    },
    'Math.random': {
        'severity': 'Medium',
        'description': 'Insecure random number generation with Math.random can compromise security',
        'recommendation': 'Use a secure random number generation library for cryptographic purposes',
        'category': 'Cryptographic Security',
        'parameters': {},
        'rule_id': 'JS1013'
    },
    'setTimeout|setInterval with eval': {
        'severity': 'High',
        'description': 'Using setTimeout or setInterval with eval can introduce code injection vulnerabilities',
        'recommendation': 'Avoid using eval within timers; use safer alternatives',
        'category': 'Code Injection',
        'parameters': {},
        'rule_id': 'JS1014'
    },
    'localStorage.clear': {
        'severity': 'High',
        'description': 'Insecure clearing of localStorage data can lead to data exposure',
        'recommendation': 'Implement proper access controls and validation when clearing localStorage',
        'category': 'Data Security',
        'parameters': {},
        'rule_id': 'JS1015'
    },
    'JSON.stringify': {
        'severity': 'Medium',
        'description': 'Unvalidated serialization with JSON.stringify can lead to security vulnerabilities',
        'recommendation': 'Always validate and sanitize data before serializing it to JSON',
        'category': 'Data Security',
        'parameters': {},
        'rule_id': 'JS1016'
    },
    'Weak Password Validation': {
        'severity': 'High',
        'description': 'Weak password validation can lead to insecure user credentials',
        'recommendation': 'Implement strong password validation rules to enhance security',
        'category': 'Authentication',
        'parameters': {},
        'rule_id': 'JS1017'
    },
    'Cross-Site Request Forgery (CSRF)': {
        'severity': 'High',
        'description': 'Failure to protect against CSRF can lead to unauthorized actions',
        'recommendation': 'Use anti-CSRF tokens and validate requests for security-critical operations',
        'category': 'Web Security',
        'parameters': {},
        'rule_id': 'JS1018'
    },
    'Insecure Use of Regular Expressions': {
        'severity': 'Medium',
        'description': 'Insecure regular expressions can lead to security vulnerabilities, such as ReDoS',
        'recommendation': 'Use optimized and secure regular expressions; avoid using unbounded patterns',
        'category': 'Regular Expressions',
        'parameters': {},
        'rule_id': 'JS1019'
    },
    'Insecure Third-Party Library Usage': {
        'severity': 'High',
        'description': 'Using insecure or outdated third-party libraries can introduce security vulnerabilities',
        'recommendation': 'Regularly update and review third-party dependencies for security issues',
        'category': 'Dependency Security',
        'parameters': {},
        'rule_id': 'JS1020'
    }
}

cve_patterns = {
    'CVE-2021-1234': r'eval\(.+\)',  # Example: Avoid using eval
    
    'CVE-2020-5678': r'new\sFunction\(.+\)',  # Example: Avoid using the Function constructor

    'CVE-2018-24601': r'[\s\n]*document\.write\(.+\)',  # Example: Avoid using document.write

    'CVE-2017-89123': r'[\s\n]*\$\(.+\)\.html\(.+\)',  # Example: Avoid using jQuery .html() with untrusted data

    'CVE-2016-54321': r'[\s\n]*window\.open\(.+\)',  # Example: Avoid using window.open without proper validation

    'CVE-2015-98765': r'[\s\n]*Function\.constructor\(.+\)',  # Example: Avoid using the Function constructor

    'CVE-2014-13579': r'[\s\n]*eval\(.+\)',  # Example: Avoid using eval

    'CVE-2013-11111': r'[\s\n]*XMLHttpRequest\.open\(.+\)',  # Example: Ensure XMLHttpRequest.open is used securely

    'CVE-2012-22222': r'[\s\n]*\$\(\'.+\'.+\)',  # Example: Avoid using jQuery with user-inputted selectors

    'CVE-2011-33333': r'[\s\n]*\.innerHTML\s*=\s*.+',  # Example: Avoid setting innerHTML with untrusted data

    'CVE-2010-44444': r'[\s\n]*\$\(\s*document\s*\)\.ready\(.+\)',  # Example: Avoid using jQuery document.ready with untrusted code

    'CVE-2009-55555': r'[\s\n]*\$\(\'.+\'.+\)\.append\(.+\)',  # Example: Avoid using jQuery .append with untrusted data

    'CVE-2008-66666': r'[\s\n]*window\.location\(.+\)',  # Example: Ensure window.location is used securely

    'CVE-2007-77777': r'[\s\n]*cookie\s*=\s*.+',  # Example: Avoid setting cookies with untrusted data

    'CVE-2006-88888': r'[\s\n]*iframe\.src\(.+\)',  # Example: Ensure iframe.src is set securely

    'CVE-2005-99999': r'[\s\n]*localStorage\(.+\)',  # Example: Avoid using localStorage with untrusted data

    'CVE-2004-10101': r'[\s\n]*\.onload\s*=\s*.+',  # Example: Avoid setting onload with untrusted code

    'CVE-2003-11223': r'[\s\n]*\$\(\s*\'#.+\'\s*\)\.click\(.+\)',  # Example: Avoid using jQuery .click with untrusted data
    
    'CVE-2002-12121': r'[\s\n]*\.src\s*=\s*.+',  # Example: Avoid setting the src attribute with untrusted data

    'CVE-2001-13131': r'[\s\n]*location\.href\(.+\)',  # Example: Ensure location.href is set securely

    'CVE-2000-14141': r'[\s\n]*\.setAttribute\(.+\)',  # Example: Avoid using setAttribute with untrusted data

    'CVE-1999-15151': r'[\s\n]*document\.cookie\(.+\)',  # Example: Avoid using document.cookie with untrusted data

    'CVE-1998-16161': r'[\s\n]*\$\(\s*\'#.+\'\s*\)\.html\(.+\)',  # Example: Avoid using jQuery .html() with untrusted data

    'CVE-1997-17171': r'[\s\n]*\.outerHTML\s*=\s*.+',  # Example: Avoid setting outerHTML with untrusted data

    'CVE-1996-18181': r'[\s\n]*JSON\.parse\(.+\)',  # Example: Ensure safe JSON parsing with JSON.parse

    'CVE-1995-19191': r'[\s\n]*\.replace\(.+\)',  # Example: Avoid using String.prototype.replace with untrusted data
    
    'CVE-1994-20202': r'[\s\n]*\.innerHTML\(.+\)',  # Example: Avoid setting innerHTML with untrusted data

    'CVE-1993-21212': r'[\s\n]*window\.eval\(.+\)',  # Example: Avoid using window.eval

    'CVE-1992-22222': r'[\s\n]*localStorage\.removeItem\(.+\)',  # Example: Avoid removing sensitive data from localStorage without validation

    'CVE-1991-23232': r'[\s\n]*\.insertAdjacentHTML\(.+\)',  # Example: Avoid using insertAdjacentHTML with untrusted data

    'CVE-1990-24242': r'[\s\n]*setTimeout\(.+\)',  # Example: Ensure setTimeout is used securely

    'CVE-1989-25252': r'[\s\n]*setInterval\(.+\)',  # Example: Ensure setInterval is used securely

    'CVE-1988-26262': r'[\s\n]*history\.pushState\(.+\)',  # Example: Ensure history.pushState is used securely

    'CVE-1987-27272': r'[\s\n]*console\.log\(.+\)',  # Example: Avoid logging sensitive data to the console

    'CVE-1986-28282': r'[\s\n]*\$\(\'.+\'.+\)\.data\(.+\)',  # Example: Avoid using jQuery .data with untrusted data

    'CVE-1985-29292': r'[\s\n]*\.setAttributeNS\(.+\)',  # Example: Avoid using setAttributeNS with untrusted data
    
    'CVE-1984-30303': r'[\s\n]*\.outerHTML\s*=\s*.+',  # Example: Avoid setting outerHTML with untrusted data
}

def analyze_javascript_file(file_path):
    with open(file_path, 'r') as file:
        javascript_code = file.read()

    issues = []

    for rule, rule_details in javascript_ruleset.items():
        rule_pattern = re.compile(r'\b{}\b'.format(rule), re.IGNORECASE)
        if re.search(rule_pattern, javascript_code):
            issues.append({
                'file_path': file_path,
                'severity': rule_details['severity'],
                'description': rule_details['description'],
                'recommendation': rule_details['recommendation'],
                'category': rule_details.get('category', ''),
                'rule_id': rule_details.get('rule_id', '')
            })

    for cve, pattern in cve_patterns.items():
        matches = re.findall(pattern, javascript_code)
        if matches:
            issues.append({
                'file_path': file_path,
                'severity': 'High',
                'description': f'Potential CVE {cve} pattern found: {pattern}',
                'recommendation': 'Follow security best practices for this code.',
                'category': 'CVE',
                'rule_id': cve
            })

    return issues

def scan_javascript_files(directory_path):
    issues = []

    # Regular expression pattern to match JavaScript file extensions
    js_file_pattern = r'.*\.js$'

    for root, _, files in os.walk(directory_path):
        for file in files:
            if re.match(js_file_pattern, file):
                file_path = os.path.join(root, file)
                issues += analyze_javascript_file(file_path)

    return issues
class ScanWorker(QThread):
    scan_complete = pyqtSignal(list)

    def __init__(self, directory_path):
        super().__init__()
        self.directory_path = directory_path

    def run(self):
        detected_issues = scan_javascript_files(self.directory_path)
        self.scan_complete.emit(detected_issues)

class CodeScannerApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Code Scanner (JavaScript)')
        self.setGeometry(100, 100, 800, 600)
        self.setStyleSheet("background-color: lightgray;")

        self.textbox = QTextEdit(self)
        self.textbox.setReadOnly(True)
        self.textbox.setStyleSheet("background-color: rgba(187, 255, 255, 0.7); color: red; font-size: 16px; font-family: Arial, sans-serif;")

        self.progress_bar = QProgressBar(self)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)

        browse_button = QPushButton('Select Directory', self)
        browse_button.setStyleSheet("background-color: lightblue; color: black; font-size: 15px; height: 30px; width: 70px; border: 2px solid black")
        browse_button.clicked.connect(self.selectDirectory)

        scan_button = QPushButton('Scan Directory', self)
        scan_button.setStyleSheet("background-color: lightgreen; color: black; font-size: 15px; height: 30px; width: 70px; border: 2px solid black")
        scan_button.clicked.connect(self.scanDirectory)

        layout = QVBoxLayout()
        layout.addWidget(self.textbox)
        layout.addWidget(self.progress_bar)
        layout.addWidget(browse_button)
        layout.addWidget(scan_button)

        self.setLayout(layout)

    def selectDirectory(self):
        options = QFileDialog.Options()
        directory = QFileDialog.getExistingDirectory(self, 'Select Directory', options=options)
        if directory:
            self.directory_path = directory
            self.textbox.setPlainText(f"Selected directory: {self.directory_path}")

    def scanDirectory(self):
        if hasattr(self, 'directory_path'):
            self.scan_worker = ScanWorker(self.directory_path)
            self.scan_worker.scan_complete.connect(self.displayScanResult)
            self.scan_worker.start()

    def displayScanResult(self, detected_issues):
        self.progress_bar.setValue(100)
        if detected_issues:
            result_text = '\n'.join([f"<b>File:</b> {issue['file_path']}<br><b>Severity:</b> {issue['severity']}<br><b>Description:</b> {issue['description']}<br><b>Recommendation:</b> {issue['recommendation']}<br><br>" for issue in detected_issues])
            self.textbox.setHtml(result_text)
        else:
            self.textbox.setPlainText("No security issues found in the JavaScript code files.")

def main():
    app = QApplication(sys.argv)
    window = CodeScannerApp()
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
'''
class SecurityScannerApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('JavaScript Security Scanner')
        self.setGeometry(100, 100, 800, 600)
        self.setStyleSheet("background-color: lightgray;")

        self.textbox = QTextEdit(self)
        self.textbox.setReadOnly(True)
        self.textbox.setStyleSheet("background-color: rgba(255, 255, 255, 0.7); color: red; font-size: 14px; font-family: Arial, sans-serif;")

        browse_button = QPushButton('Select Directory', self)
        browse_button.setStyleSheet("background-color: lightblue; color: black; font-size: 15px; height: 30px; width: 70px; border: 2px solid black")
        browse_button.clicked.connect(self.selectDirectory)

        scan_button = QPushButton('Scan Directory', self)
        scan_button.setStyleSheet("background-color: lightgreen; color: black; font-size: 15px; height: 30px; width: 70px; border: 2px solid black")
        scan_button.clicked.connect(self.scanDirectory)

        layout = QVBoxLayout()
        layout.addWidget(self.textbox)
        layout.addWidget(browse_button)
        layout.addWidget(scan_button)

        self.setLayout(layout)

    def selectDirectory(self):
        options = QFileDialog.Options()
        directory = QFileDialog.getExistingDirectory(self, 'Select Directory', options=options)
        if directory:
            self.directory_path = directory

    def scanDirectory(self):
        if hasattr(self, 'directory_path'):
            detected_issues = scan_javascript_files(self.directory_path)
            if detected_issues:
                result_text = '\n'.join([f"<b>File:</b> {issue['file_path']}<br><b>Severity:</b> {issue['severity']}<br><b>Description:</b> {issue['description']}<br><b>Recommendation:</b> {issue['recommendation']}<br><br>" for issue in detected_issues])
                self.textbox.setHtml(result_text)
            else:
                self.textbox.setPlainText("No security issues found in the JavaScript files.")
        else:
            self.textbox.setPlainText("Please select a directory first.")

def main():
    app = QApplication(sys.argv)
    window = SecurityScannerApp()
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
'''