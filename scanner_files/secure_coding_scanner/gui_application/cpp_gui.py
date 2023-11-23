import sys
import os
import re
import subprocess
from PyQt5.QtCore import Qt, QCoreApplication
from PyQt5.QtCore import Qt, QDir, QThread, pyqtSignal
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QTextEdit, QPushButton, QApplication, QFileDialog, QProgressBar, QGroupBox
from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QFileDialog, QTextEdit, QVBoxLayout

cpp_ruleset = {

    'Buffer Overflow': {
        'category': 'Memory Safety',
        'parameters': ['Buffer', 'Size'],
        'rule_id': 'CPP001',
        'severity': 'High',
        'description': 'Buffer overflow can lead to memory corruption and code execution vulnerabilities.',
        'recommendation': 'Use safe C++ functions and bounds checking to prevent buffer overflows.',
    },
    'Null Pointer Dereference': {
        'category': 'Memory Safety',
        'parameters': ['Pointer'],
        'rule_id': 'CPP002',
        'severity': 'High',
        'description': 'Dereferencing a null pointer can lead to crashes and security vulnerabilities.',
        'recommendation': 'Always check for null pointers before dereferencing.',
    },
    'Use After Free': {
        'category': 'Memory Safety',
        'parameters': ['Pointer'],
        'rule_id': 'CPP003',
        'severity': 'High',
        'description': 'Using a pointer after it has been deallocated can lead to crashes and vulnerabilities.',
        'recommendation': 'Always set pointers to null or a valid value after deallocation.',
    },
    'Uninitialized Variables': {
        'category': 'Variable Initialization',
        'parameters': ['Variable'],
        'rule_id': 'CPP004',
        'severity': 'Medium',
        'description': 'Using uninitialized variables can lead to unexpected behavior and vulnerabilities.',
        'recommendation': 'Always initialize variables before using them.',
    },
    
    'Integer Overflow': {
        'category': 'Arithmetic Operations',
        'parameters': ['Integer', 'Operation'],
        'rule_id': 'CPP005',
        'severity': 'High',
        'description': 'Unchecked integer arithmetic can lead to overflow vulnerabilities.',
        'recommendation': 'Use safe integer types and bounds checking to prevent overflows.',
    },
    'Format String Vulnerability': {
        'category': 'Input Validation',
        'parameters': ['Format String', 'User Input'],
        'rule_id': 'CPP006',
        'severity': 'High',
        'description': 'Improper use of format string functions can lead to information leakage or code execution.',
        'recommendation': 'Always specify format strings correctly and avoid using user input as format strings.',
    },
    'Insecure Input Handling': {
        'category': 'Input Validation',
        'parameters': ['User Input'],
        'rule_id': 'CPP007',
        'severity': 'High',
        'description': 'Improper input validation can lead to various vulnerabilities, including injection attacks.',
        'recommendation': 'Implement proper input validation and sanitization for user inputs.',
    },
    'Insecure Memory Management': {
        'category': 'Memory Management',
        'parameters': ['Memory', 'Resource'],
        'rule_id': 'CPP008',
        'severity': 'High',
        'description': 'Improper memory management can lead to memory leaks and vulnerabilities.',
        'recommendation': 'Use smart pointers and resource management techniques to handle memory securely.',
    },
    'Insecure File Operations': {
        'category': 'File Handling',
        'parameters': ['File', 'Path'],
        'rule_id': 'CPP009',
        'severity': 'High',
        'description': 'Improper file handling can lead to security vulnerabilities, including file-based attacks.',
        'recommendation': 'Use secure file handling functions and validate file paths.',
    },
    'Insecure Network Communication': {
        'category': 'Network Communication',
        'parameters': ['Network', 'Protocol'],
        'rule_id': 'CPP010',
        'severity': 'High',
        'description': 'Improper network communication can lead to network-related vulnerabilities.',
        'recommendation': 'Use secure protocols and validate input from the network.',
    },
    'Race Conditions': {
        'category': 'Concurrency',
        'parameters': ['Concurrency', 'Race Condition'],
        'rule_id': 'CPP011',
        'severity': 'High',
        'description': 'Uncontrolled race conditions can lead to data corruption and vulnerabilities.',
        'recommendation': 'Implement proper synchronization mechanisms to prevent race conditions.',
    },
    'Insecure Cryptographic Practices': {
        'category': 'Cryptography',
        'parameters': ['Cryptography', 'Function'],
        'rule_id': 'CPP012',
        'severity': 'High',
        'description': 'Improper use of cryptographic functions can lead to security weaknesses.',
        'recommendation': 'Follow best practices for cryptographic operations and use established libraries.',
    },
    'Code Injection': {
        'category': 'Code Execution',
        'parameters': ['Code', 'Injection'],
        'rule_id': 'CPP013',
        'severity': 'High',
        'description': 'Allowing execution of arbitrary code can lead to code injection vulnerabilities.',
        'recommendation': 'Implement proper input validation and avoid dynamic code execution.',
    },
    'Untrusted Data Handling': {
        'category': 'Data Handling',
        'parameters': ['Data', 'Validation'],
        'rule_id': 'CPP014',
        'severity': 'High',
        'description': 'Handling untrusted data without validation can lead to various vulnerabilities.',
        'recommendation': 'Validate and sanitize untrusted data before use.',
    },
    'Denial of Service (DoS)': {
        'category': 'Security',
        'parameters': ['DoS', 'Attack'],
        'rule_id': 'CPP015',
        'severity': 'High',
        'description': 'Insecure code can lead to denial of service attacks.',
        'recommendation': 'Implement safeguards and rate limiting to prevent DoS attacks.',
    },
    'Cross-Site Scripting (XSS)': {
        'category': 'Web Security',
        'parameters': ['XSS', 'Vulnerability'],
        'rule_id': 'CPP016',
        'severity': 'High',
        'description': 'Improper handling of user input can lead to XSS vulnerabilities.',
        'recommendation': 'Use output encoding and validate user inputs to prevent XSS.',
    },
    'Command Injection': {
        'category': 'Command Execution',
        'parameters': ['Command', 'Injection'],
        'rule_id': 'CPP017',
        'severity': 'High',
        'description': 'Improper handling of external commands can lead to command injection vulnerabilities.',
        'recommendation': 'Use parameterized commands and avoid building commands from user input.',
    },
    'Hardcoded Passwords': {
        'category': 'Security',
        'parameters': ['Password', 'Storage'],
        'rule_id': 'CPP018',
        'severity': 'High',
        'description': 'Storing passwords in code can lead to unauthorized access.',
        'recommendation': 'Use secure storage and encryption for passwords.',
    },
    'Insecure Third-Party Libraries': {
        'category': 'Dependency Security',
        'parameters': ['Third-Party', 'Library'],
        'rule_id': 'CPP019',
        'severity': 'High',
        'description': 'Using outdated or vulnerable third-party libraries can lead to security issues.',
        'recommendation': 'Regularly update and patch third-party dependencies.',
    },
    'Insufficient Logging and Monitoring': {
        'category': 'Security',
        'parameters': ['Logging', 'Monitoring'],
        'rule_id': 'CPP020',
        'severity': 'Medium',
        'description': 'Inadequate logging and monitoring can lead to undetected security incidents.',
        'recommendation': 'Implement robust logging and monitoring for security events.',
    },
    'Insecure Deserialization': {
        'category': 'Data Serialization',
        'parameters': ['Deserialization', 'Vulnerability'],
        'rule_id': 'CPP021',
        'severity': 'High',
        'description': 'Improper handling of deserialization can lead to code execution vulnerabilities.',
        'recommendation': 'Use safe deserialization methods and validate serialized data.',
    },
    'SQL Injection': {
        'category': 'Database Security',
        'parameters': ['SQL', 'Injection'],
        'rule_id': 'CPP022',
        'severity': 'High',
        'description': 'Improper SQL query construction can lead to SQL injection vulnerabilities.',
        'recommendation': 'Use prepared statements and parameterized queries to prevent SQL injection.',
    },
    'Insecure Session Management': {
        'category': 'Session Handling',
        'parameters': ['Session', 'Management'],
        'rule_id': 'CPP023',
        'severity': 'High',
        'description': 'Weak session management can lead to unauthorized access and attacks.',
        'recommendation': 'Implement secure session handling mechanisms.',
    },
    'Information Disclosure': {
        'category': 'Data Privacy',
        'parameters': ['Information', 'Disclosure'],
        'rule_id': 'CPP024',
        'severity': 'Medium',
        'description': 'Leaking sensitive information can lead to privacy and security issues.',
        'recommendation': 'Implement proper access controls and data protection.',
    },
    'Cross-Site Request Forgery (CSRF)': {
        'category': 'Web Security',
        'parameters': ['CSRF', 'Protection'],
        'rule_id': 'CPP025',
        'severity': 'High',
        'description': 'Inadequate CSRF protection can lead to unauthorized actions on behalf of users.',
        'recommendation': 'Use anti-CSRF tokens and validate requests to prevent CSRF attacks.',
    }
}

cpp_cve_patterns = {
    'CVE-2023-1111': r'scanf\(.+\)',  # Example: Avoid using scanf without proper input validation
    'CVE-2023-2222': r'gets\(.+\)',  # Example: Avoid using gets, as it's unsafe and can lead to buffer overflows
    'CVE-2023-3333': r'strcpy\(.+\)',  # Example: Avoid using strcpy, as it can lead to buffer overflows
    'CVE-2023-4444': r'strcat\(.+\)',  # Example: Avoid using strcat, as it can lead to buffer overflows
    'CVE-2023-5555': r'system\(.+\)',  # Example: Avoid using system calls with untrusted input
    'CVE-2023-6666': r'exec\(.+\)',  # Example: Avoid using exec calls with unvalidated input
    'CVE-2023-7777': r'popen\(.+\)',  # Example: Avoid using popen without proper input validation
    'CVE-2023-8888': r'fclose\(.+\)',  # Example: Avoid using fclose without proper file handling
    'CVE-2023-9999': r'freopen\(.+\)',  # Example: Avoid using freopen without proper file handling
    'CVE-2023-1010': r'fread\(.+\)',  # Example: Avoid using fread with unvalidated input
    'CVE-2023-1111': r'fwrite\(.+\)',  # Example: Avoid using fwrite with unvalidated data
    'CVE-2023-1212': r'memcpy\(.+\)',  # Example: Avoid using memcpy with unvalidated data
    'CVE-2023-1313': r'memmove\(.+\)',  # Example: Avoid using memmove with unvalidated data
    'CVE-2023-1414': r'sprintf\(.+\)',  # Example: Avoid using sprintf, as it can lead to buffer overflows
    'CVE-2023-1515': r'vsprintf\(.+\)',  # Example: Avoid using vsprintf, as it can lead to buffer overflows
    'CVE-2023-1616': r'fprintf\(.+\)',  # Example: Avoid using fprintf with unvalidated data
    'CVE-2023-1717': r'vfprintf\(.+\)',  # Example: Avoid using vfprintf with unvalidated data
    'CVE-2023-1818': r'open\(.+\)',  # Example: Avoid using open calls with unvalidated file paths
    'CVE-2023-1919': r'fdopen\(.+\)',  # Example: Avoid using fdopen with unvalidated file descriptors
    'CVE-2023-2020': r'bind\(.+\)',  # Example: Avoid using bind with untrusted addresses
    'CVE-2023-2121': r'listen\(.+\)',  # Example: Avoid using listen with unvalidated input
    'CVE-2023-2222': r'accept\(.+\)',  # Example: Avoid using accept with untrusted connections
    'CVE-2023-2323': r'shmat\(.+\)',  # Example: Avoid using shmat without proper validation
    'CVE-2023-2424': r'shmctl\(.+\)',  # Example: Avoid using shmctl without proper validation
    'CVE-2023-2525': r'shmget\(.+\)',  # Example: Avoid using shmget without proper validation
    'CVE-2023-2626': r'read\(.+\)',  # Example: Avoid using read with unvalidated input
    'CVE-2023-2727': r'write\(.+\)',  # Example: Avoid using write with unvalidated data
    'CVE-2023-2828': r'memset\(.+\)',  # Example: Avoid using memset with unvalidated data
    'CVE-2023-2929': r'sscanf\(.+\)',  # Example: Avoid using sscanf with untrusted input
    'CVE-2023-3030': r'snprintf\(.+\)',  # Example: Avoid using snprintf, as it can lead to buffer overflows
}

def analyze_cpp_file(file_path):
    with open(file_path, 'r') as file:
        cpp_code = file.read()

    issues = []

    for rule, rule_details in cpp_ruleset.items():
        rule_pattern = re.compile(r'\b{}\b'.format(re.escape(rule)), re.IGNORECASE)
        if re.search(rule_pattern, cpp_code):
            issues.append({
                'file_path': file_path,
                'severity': rule_details['severity'],
                'description': rule_details['description'],
                'recommendation': rule_details['recommendation'],
                'category': rule_details['category'],
                'rule_id': rule_details['rule_id']
            })

    for cve, pattern in cpp_cve_patterns.items():
        matches = re.findall(pattern, cpp_code)
        if matches:
            issues.extend([{
                'file_path': file_path,
                'severity': 'High',
                'description': f'Potential CVE {cve} pattern found: {pattern}',
                'recommendation': 'Follow security best practices for this code.',
                'category': 'CVE',
                'rule_id': cve
            }])

    return issues

def scan_cpp_files(directory_path):
    issues = []

    # Regular expression pattern to match C++ file extensions
    cpp_file_pattern = r'.*\.cpp$'

    for root, _, files in os.walk(directory_path):
        for file in files:
            if re.match(cpp_file_pattern, file):
                file_path = os.path.join(root, file)
                issues += analyze_cpp_file(file_path)

    return issues

class ScanWorker(QThread):
    scan_complete = pyqtSignal(list)

    def __init__(self, directory_path):
        super().__init__()
        self.directory_path = directory_path

    def run(self):
        detected_issues = scan_cpp_files(self.directory_path)
        self.scan_complete.emit(detected_issues)

class CodeScannerApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Code Scanner (C++)')
        self.setGeometry(100, 100, 800, 600)
        self.setStyleSheet("background-color: lightgray;")

        self.textbox = QTextEdit(self)
        self.textbox.setReadOnly(True)
        self.textbox.setStyleSheet("background-color: rgba(187, 255, 255, 0.7); color: red; font-size: 16px; font-family: Arial, sans-serif;")

        self.progress_bar = QProgressBar(self)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setStyleSheet

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
            self.textbox.setPlainText("No security issues found in the C++ code files.")

def main():
    app = QApplication(sys.argv)
    window = CodeScannerApp()
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()

'''class SecurityScannerApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('C++ Security Scanner')
        self.setGeometry(100, 100, 800, 600)

        # Remove the background image
        self.setStyleSheet("background-color: lightgray;")  # Set the background color

        self.textbox = QTextEdit(self)
        self.textbox.setReadOnly(True)
        self.textbox.setStyleSheet("background-color: rgba(255, 255, 255, 0.7); color: red; font-size: 14px; font-family: Arial, sans-serif;")

        browse_button = QPushButton('Select Directory', self)
        browse_button.setStyleSheet("background-color: lightblue; color: black; font-size: 15px; height: 30px; width: 70px; border: 2px solid black")
        browse_button.clicked.connect(self.selectDirectory)  # Connect the button to the function

        scan_button = QPushButton('Scan Directory', self)
        scan_button.setStyleSheet("background-color: lightgreen; color: black; font-size: 15px; height: 30px; width: 70px; border: 2px solid black")
        scan_button.clicked.connect(self.scanDirectory)  # Connect the button to the function

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
            detected_issues = scan_cpp_files(self.directory_path)
            if detected_issues:
                result_text = '\n'.join([f"<b>File:</b> {issue['file_path']}<br><b>Severity:</b> {issue['severity']}<br><b>Description:</b> {issue['description']}<br><b>Recommendation:</b> {issue['recommendation']}<br><br>" for issue in detected_issues])
                self.textbox.setHtml(result_text)
            else:
                self.textbox.setPlainText("No security issues found in the C++ files.")
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