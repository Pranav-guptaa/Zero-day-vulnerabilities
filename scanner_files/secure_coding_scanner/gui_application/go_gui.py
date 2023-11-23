import sys
import os
import re
import subprocess
from PyQt5.QtCore import Qt, QCoreApplication
from PyQt5.QtCore import Qt, QDir, QThread, pyqtSignal
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QTextEdit, QPushButton, QApplication, QFileDialog, QProgressBar, QGroupBox
from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QFileDialog, QTextEdit, QVBoxLayout

go_ruleset = {
    'SQL Injection': {
        'severity': 'High',
        'description': 'Potential SQL injection vulnerability.',
        'recommendation': 'Use prepared statements or parameterized queries to prevent SQL injection.',
        'category': 'SQL Injection',
        'parameters': {},
        'rule_id': 'GO1001'
    },
    'Unvalidated Input': {
        'severity': 'Medium',
        'description': 'Unvalidated input that may lead to security vulnerabilities.',
        'recommendation': 'Validate and sanitize user input to prevent security issues.',
        'category': 'Input Validation',
        'parameters': {},
        'rule_id': 'GO1002'
    },
    
    'Weak Cryptographic Algorithm': {
        'severity': 'High',
        'description': 'Using weak cryptographic algorithms can lead to security vulnerabilities.',
        'recommendation': 'Use strong cryptographic algorithms and best practices for secure encryption.',
        'category': 'Cryptography',
        'parameters': {},
        'rule_id': 'GO1003'
    },
    'Hardcoded Secrets': {
        'severity': 'High',
        'description': 'Hardcoding secrets, such as API keys or credentials, in the source code is a security risk.',
        'recommendation': 'Store secrets in environment variables or use secret management solutions.',
        'category': 'Authentication',
        'parameters': {},
        'rule_id': 'GO1004'
    },
    'Cross-Site Scripting (XSS)': {
        'severity': 'High',
        'description': 'Unsanitized user input can lead to XSS vulnerabilities.',
        'recommendation': 'Validate and sanitize user input to prevent XSS attacks.',
        'category': 'Web Security',
        'parameters': {},
        'rule_id': 'GO1005'
    },
    'Command Injection': {
        'severity': 'High',
        'description': 'Improper handling of user input in system commands can lead to command injection vulnerabilities.',
        'recommendation': 'Sanitize and validate user input used in system commands.',
        'category': 'Command Injection',
        'parameters': {},
        'rule_id': 'GO1006'
    },
    'Insecure Deserialization': {
        'severity': 'High',
        'description': 'Insecure deserialization can lead to remote code execution vulnerabilities.',
        'recommendation': 'Use secure deserialization practices and validate serialized data.',
        'category': 'Deserialization',
        'parameters': {},
        'rule_id': 'GO1007'
    },
    'Open Redirect': {
        'severity': 'Medium',
        'description': 'Improper handling of user-controlled URLs can lead to open redirect vulnerabilities.',
        'recommendation': 'Always validate and sanitize user-generated URLs.',
        'category': 'Web Security',
        'parameters': {},
        'rule_id': 'GO1008'
    },
    'Cross-Site Request Forgery (CSRF)': {
        'severity': 'Medium',
        'description': 'Missing CSRF protection can lead to CSRF attacks.',
        'recommendation': 'Implement CSRF protection mechanisms in your web application.',
        'category': 'Web Security',
        'parameters': {},
        'rule_id': 'GO1009'
    },
    'Insecure HTTP Headers': {
        'severity': 'Medium',
        'description': 'Incorrect HTTP headers can lead to security vulnerabilities.',
        'recommendation': 'Set secure HTTP headers to enhance web application security.',
        'category': 'Web Security',
        'parameters': {},
        'rule_id': 'GO1010'
    },
    'File Inclusion Vulnerability': {
        'severity': 'High',
        'description': 'Improper handling of file inclusion can lead to file disclosure and remote code execution.',
        'recommendation': 'Validate and sanitize user input used for file inclusion.',
        'category': 'File Handling',
        'parameters': {},
        'rule_id': 'GO1011'
    },
    'Insecure Authentication': {
        'severity': 'High',
        'description': 'Insecure authentication mechanisms can lead to unauthorized access.',
        'recommendation': 'Implement secure authentication methods and protect user credentials.',
        'category': 'Authentication',
        'parameters': {},
        'rule_id': 'GO1012'
    },
    'XML External Entity (XXE) Injection': {
        'severity': 'High',
        'description': 'Processing untrusted XML input can lead to XXE vulnerabilities.',
        'recommendation': 'Disable or restrict external entity processing in XML parsers.',
        'category': 'XML Security',
        'parameters': {},
        'rule_id': 'GO1013'
    },
    'Using Deprecated Libraries': {
        'severity': 'Medium',
        'description': 'Using deprecated or obsolete libraries can lead to security issues.',
        'recommendation': 'Update to the latest and supported libraries to address vulnerabilities.',
        'category': 'Library Security',
        'parameters': {},
        'rule_id': 'GO1014'
    },
    'Insufficient Session Management': {
        'severity': 'Medium',
        'description': 'Inadequate session management can lead to session hijacking or fixation.',
        'recommendation': 'Implement strong session management controls and secure session handling.',
        'category': 'Session Management',
        'parameters': {},
        'rule_id': 'GO1015'
    },
    'Information Disclosure': {
        'severity': 'Medium',
        'description': 'Leaking sensitive information can lead to privacy and security breaches.',
        'recommendation': 'Ensure sensitive information is not exposed to unauthenticated users.',
        'category': 'Privacy',
        'parameters': {},
        'rule_id': 'GO1016'
    },
    'Insecure Cross-Origin Resource Sharing (CORS)': {
        'severity': 'Medium',
        'description': 'Misconfigured CORS can lead to security issues, such as data theft.',
        'recommendation': 'Configure CORS policies to restrict cross-origin requests effectively.',
        'category': 'Web Security',
        'parameters': {},
        'rule_id': 'GO1017'
    },
    'Insecure File Upload': {
        'severity': 'High',
        'description': 'Lack of security controls in file uploads can lead to remote code execution.',
        'recommendation': 'Implement strict file upload validation and restrict executable file uploads.',
        'category': 'File Handling',
        'parameters': {},
        'rule_id': 'GO1018'
    },
    'Insecure Direct Object References (IDOR)': {
        'severity': 'High',
        'description': 'Improper access control can lead to IDOR vulnerabilities.',
        'recommendation': 'Implement proper access controls and validate user input.',
        'category': 'Access Control',
        'parameters': {},
        'rule_id': 'GO1019'
    },
    'Server-Side Request Forgery (SSRF)': {
        'severity': 'High',
        'description': 'Inadequate protection against SSRF can lead to requests to internal services.',
        'recommendation': 'Filter and validate user-generated URLs and restrict external requests.',
        'category': 'Web Security',
        'parameters': {},
        'rule_id': 'GO1020'
    },
    'Cross-Site Script Inclusion (XSSI)': {
        'severity': 'Medium',
        'description': 'Loading untrusted scripts can lead to XSSI vulnerabilities.',
        'recommendation': 'Validate and sanitize script sources in web applications.',
        'category': 'Web Security',
        'parameters': {},
        'rule_id': 'GO1021'
    },
    'Broken Authentication': {
        'severity': 'High',
        'description': 'Flaws in the authentication process can lead to unauthorized access.',
        'recommendation': 'Implement secure authentication mechanisms and protect user credentials.',
        'category': 'Authentication',
        'parameters': {},
        'rule_id': 'GO1022'
    },
    'Insecure Object Serialization': {
        'severity': 'High',
        'description': 'Insecure object serialization can lead to remote code execution vulnerabilities.',
        'recommendation': 'Use secure serialization practices and validate serialized data.',
        'category': 'Serialization',
        'parameters': {},
        'rule_id': 'GO1023'
    },
    'HTTP Parameter Pollution (HPP)': {
        'severity': 'Medium',
        'description': 'HPP can lead to confusion and security vulnerabilities in web applications.',
        'recommendation': 'Validate and sanitize HTTP parameters to prevent HPP.',
        'category': 'Web Security',
        'parameters': {},
        'rule_id': 'GO1024'
    },
    'Insecure HTML Handling': {
        'severity': 'High',
        'description': 'Improper handling of HTML can lead to XSS vulnerabilities.',
        'recommendation': 'Escape and validate HTML content to prevent XSS attacks.',
        'category': 'Web Security',
        'parameters': {},
        'rule_id': 'GO1025'
    },
    'Security Misconfiguration': {
        'severity': 'Medium',
        'description': 'Security misconfigurations can lead to various vulnerabilities.',
        'recommendation': 'Regularly audit and secure the application and its environment.',
        'category': 'Security Misconfiguration',
        'parameters': {},
        'rule_id': 'GO1026'
    },
    'Insecure Logging': {
        'severity': 'Medium',
        'description': 'Improper logging can expose sensitive information and lead to security issues.',
        'recommendation': 'Implement secure logging practices and prevent sensitive data exposure.',
        'category': 'Logging',
        'parameters': {},
        'rule_id': 'GO1027'
    },
    'XML Injection': {
        'severity': 'High',
        'description': 'Improper handling of XML input can lead to XML injection vulnerabilities.',
        'recommendation': 'Escape and validate XML content to prevent XML injection.',
        'category': 'XML Security',
        'parameters': {},
        'rule_id': 'GO1028'
    },
    'Information Exposure Through an Error Message': {
        'severity': 'Medium',
        'description': 'Exposing internal system details in error messages can lead to information leakage.',
        'recommendation': 'Use generic error messages and avoid revealing sensitive information.',
        'category': 'Information Leakage',
        'parameters': {},
        'rule_id': 'GO1029'
    },
    'Insufficient Security Logging': {
        'severity': 'Medium',
        'description': 'Inadequate security logging can hinder incident detection and response.',
        'recommendation': 'Implement comprehensive security event logging and monitoring.',
        'category': 'Logging',
        'parameters': {},
        'rule_id': 'GO1030'
    },
}

cve_patterns = {
    'CVE-2022-1234': r'vulnerableFunction\(.*\)',
    'CVE-2022-5678': r'exploitableLibrary\.doSomething\(.+\)',    
    'CVE-2022-4321': r'vulnerableFunction2\(.*\)',
    'CVE-2022-8765': r'exploitableLibrary2\.doSomething\(.+\)',
    'CVE-2022-9999': r'vulnerableMethod3\(.*\)',
    'CVE-2022-1111': r'exploitableLibrary3\.doSomethingElse\(.+\)',
    'CVE-2022-3333': r'insecureFunction4\(.*\)',
    'CVE-2022-4444': r'vulnerableLibrary4\.doThis\(.+\)',
    'CVE-2022-5555': r'unvalidatedMethod5\(.*\)',
    'CVE-2022-6666': r'insecureLibrary5\.execute\(.+\)',
    'CVE-2022-7777': r'weakAlgorithm6\(.*\)',
    'CVE-2022-8888': r'vulnerableModule6\.encrypt\(.+\)',
    'CVE-2022-7777': r'sqlInjection7\(.*\)',
    'CVE-2022-8888': r'vulnerableDB7\.query\(.+\)',
    'CVE-2022-9999': r'codeExecution8\(.*\)',
    'CVE-2022-1010': r'exploitableService8\.execute\(.+\)',
    'CVE-2022-1111': r'insecureObject9\(.*\)',
    'CVE-2022-1212': r'vulnerablePackage9\.call\(.+\)',
    'CVE-2022-1313': r'dataExposure10\(.*\)',
    'CVE-2022-1414': r'sensitiveData10\.leak\(.+\)',
    'CVE-2022-1515': r'authenticationBypass11\(.*\)',
    'CVE-2022-1616': r'vulnerableAuth11\.login\(.+\)',
    'CVE-2022-1717': r'insecureSession12\(.*\)',
    'CVE-2022-1818': r'sessionHijack12\.perform\(.+\)',
    'CVE-2022-1919': r'misconfiguredCORS13\(.*\)',
    'CVE-2022-2020': r'vulnerableAPI13\.request\(.+\)',
    'CVE-2022-2121': r'insecureDeserialization14\(.*\)',
    'CVE-2022-2222': r'deserializationVuln14\.process\(.+\)',
    'CVE-2022-2323': r'openRedirect15\(.*\)',
    'CVE-2022-2424': r'vulnerableApp15\.redirect\(.+\)',
    'CVE-2022-2525': r'xmlInjection16\(.*\)',
    'CVE-2022-2626': r'insecureXML16\.parse\(.+\)',
}
def analyze_go_file(file_path):
    with open(file_path, 'r') as file:
        go_code = file.read()

    issues = []

    for rule, rule_details in go_ruleset.items():
        rule_pattern = re.compile(r'\b{}\b'.format(re.escape(rule)), re.IGNORECASE)
        if re.search(rule_pattern, go_code):
            issues.append({
                'file_path': file_path,
                'severity': rule_details['severity'],
                'description': rule_details['description'],
                'recommendation': rule_details['recommendation'],
                'category': rule_details['category'],
                'rule_id': rule_details['rule_id']
            })

    for cve, pattern in cve_patterns.items():
        matches = re.findall(pattern, go_code)
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

def scan_go_files(directory_path):
    issues = []

    # Regular expression pattern to match Go file extensions
    go_file_pattern = r'.*\.go$'

    for root, _, files in os.walk(directory_path):
        for file in files:
            if re.match(go_file_pattern, file):
                file_path = os.path.join(root, file)
                issues += analyze_go_file(file_path)

    return issues

class ScanWorker(QThread):
    scan_complete = pyqtSignal(list)

    def __init__(self, directory_path):
        super().__init__()
        self.directory_path = directory_path

    def run(self):
        detected_issues = scan_go_files(self.directory_path)
        self.scan_complete.emit(detected_issues)

class SecurityScannerApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Go Security Scanner')
        self.setGeometry(100, 100, 800, 600)
        self.setStyleSheet("background-color: lightgray;")

        self.textbox = QTextEdit(self)
        self.textbox.setReadOnly(True)
        self.textbox.setStyleSheet("background-color: rgb(187, 255, 255, 0.7); color: red; font-size: 16px; font-family: Arial, sans-serif;")

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
            # Simulate a progress bar update (you can adjust this logic as needed)
            for i in range(101):
                self.progress_bar.setValue(i)
                QCoreApplication.processEvents()  # Allows the UI to update

            detected_issues = scan_go_files(self.directory_path)
            if detected_issues:
                result_text = '\n'.join([f"<b>File:</b> {issue['file_path']}<br><b>Severity:</b> {issue['severity']}<br><b>Description:</b> {issue['description']}<br><b>Recommendation:</b> {issue['recommendation']}<br><br>" for issue in detected_issues])
                self.textbox.setHtml(result_text)
            else:
                self.textbox.setPlainText("No security issues found in the Go files.")
        else:
            self.textbox.setPlainText("Please select a directory first.")

def main():
    app = QApplication(sys.argv)
    window = SecurityScannerApp()
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()