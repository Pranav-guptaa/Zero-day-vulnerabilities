import sys
import os
import re
import subprocess
from PyQt5.QtCore import Qt, QCoreApplication
from PyQt5.QtCore import Qt, QDir, QThread, pyqtSignal
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QTextEdit, QPushButton, QApplication, QFileDialog, QProgressBar, QGroupBox
from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QFileDialog, QTextEdit, QVBoxLayout

c_ruleset = {
    'Buffer Overflow': {
        'category': 'Memory and Code Execution',
        'parameters': ['vulnerable_function', 'buffer_size'],
        'description': 'Buffer overflow can lead to memory corruption and code execution vulnerabilities.',
        'recommendation': 'Use safe C functions and bounds checking to prevent buffer overflows.',
        'rule_id': 'C001',
    },
    'Null Pointer Dereference': {
        'category': 'Memory and Code Execution',
        'parameters': ['pointer_check'],
        'description': 'Dereferencing a null pointer can lead to crashes and security vulnerabilities.',
        'recommendation': 'Always check for null pointers before dereferencing.',
        'rule_id': 'C002',
    },
    'Use After Free': {
        'category': 'Memory and Code Execution',
        'parameters': ['pointer_check'],
        'description': 'Using a pointer after it has been deallocated can lead to crashes and vulnerabilities.',
        'recommendation': 'Always set pointers to null or a valid value after deallocation.',
        'rule_id': 'C003',
    },
    'Uninitialized Variables': {
        'category': 'Memory and Code Execution',
        'parameters': ['variable_initialization'],
        'description': 'Using uninitialized variables can lead to unexpected behavior and vulnerabilities.',
        'recommendation': 'Always initialize variables before using them.',
        'rule_id': 'C004',
    },
    'Integer Overflow': {
        'category': 'Memory and Code Execution',
        'parameters': ['safe_integer_types'],
        'description': 'Unchecked integer arithmetic can lead to overflow vulnerabilities.',
        'recommendation': 'Use safe integer types and bounds checking to prevent overflows.',
        'rule_id': 'C005',
    },
    'Format String Vulnerability': {
        'category': 'Code Execution and Information Leakage',
        'parameters': ['format_string_validation'],
        'description': 'Improper use of format string functions can lead to information leakage or code execution.',
        'recommendation': 'Always specify format strings correctly and avoid using user input as format strings.',
        'rule_id': 'C006',
    },
    'Insecure Input Handling': {
        'category': 'Injection Attacks',
        'parameters': ['input_validation'],
        'description': 'Improper input validation can lead to various vulnerabilities, including injection attacks.',
        'recommendation': 'Implement proper input validation and sanitization for user inputs.',
        'rule_id': 'C007',
    },
    'Insecure Memory Management': {
        'category': 'Memory Management',
        'parameters': ['memory_management_best_practices'],
        'description': 'Improper memory management can lead to memory leaks and vulnerabilities.',
        'recommendation': 'Use smart pointers and resource management techniques to handle memory securely.',
        'rule_id': 'C008',
    },
    'Insecure File Operations': {
        'category': 'File Handling',
        'parameters': ['file_operation_validation'],
        'description': 'Improper file handling can lead to security vulnerabilities, including file-based attacks.',
        'recommendation': 'Use secure file handling functions and validate file paths.',
        'rule_id': 'C009',
    },
    'Insecure Network Communication': {
        'category': 'Network Security',
        'parameters': ['network_protocol_security'],
        'description': 'Improper network communication can lead to network-related vulnerabilities.',
        'recommendation': 'Use secure protocols and validate input from the network.',
        'rule_id': 'C010',
    },
    'Race Conditions': {
        'category': 'Concurrency and Synchronization',
        'parameters': ['synchronization_best_practices'],
        'description': 'Uncontrolled race conditions can lead to data corruption and vulnerabilities.',
        'recommendation': 'Implement proper synchronization mechanisms to prevent race conditions.',
        'rule_id': 'C011',
    },
    'Insecure Cryptographic Practices': {
        'category': 'Cryptography',
        'parameters': ['cryptography_best_practices'],
        'description': 'Improper use of cryptographic functions can lead to security weaknesses.',
        'recommendation': 'Follow best practices for cryptographic operations and use established libraries.',
        'rule_id': 'C012',
    },
    'Code Injection': {
        'category': 'Injection Attacks',
        'parameters': ['code_injection_prevention'],
        'description': 'Allowing execution of arbitrary code can lead to code injection vulnerabilities.',
        'recommendation': 'Implement proper input validation and avoid dynamic code execution.',
        'rule_id': 'C013',
    },
    'Untrusted Data Handling': {
        'category': 'Input Validation',
        'parameters': ['data_validation'],
        'description': 'Handling untrusted data without validation can lead to various vulnerabilities.',
        'recommendation': 'Validate and sanitize untrusted data before use.',
        'rule_id': 'C014',
    },
    'Denial of Service (DoS)': {
        'category': 'DoS Prevention',
        'parameters': ['dos_prevention'],
        'description': 'Insecure code can lead to denial of service attacks.',
        'recommendation': 'Implement safeguards and rate limiting to prevent DoS attacks.',
        'rule_id': 'C015',
    },
    'Cross-Site Scripting (XSS)': {
        'category': 'Web Security',
        'parameters': ['xss_prevention'],
        'description': 'Improper handling of user input can lead to XSS vulnerabilities.',
        'recommendation': 'Use output encoding and validate user inputs to prevent XSS.',
        'rule_id': 'C016',
    },
    'Command Injection': {
        'category': 'Injection Attacks',
        'parameters': ['command_injection_prevention'],
        'description': 'Improper handling of external commands can lead to command injection vulnerabilities.',
        'recommendation': 'Use parameterized commands and avoid building commands from user input.',
        'rule_id': 'C017',
    },
    'Hardcoded Passwords': {
        'category': 'Authentication and Authorization',
        'parameters': ['password_security'],
        'description': 'Storing passwords in code can lead to unauthorized access.',
        'recommendation': 'Use secure storage and encryption for passwords.',
        'rule_id': 'C018',
    },
    'Insecure Third-Party Libraries': {
        'category': 'Dependency Security',
        'parameters': ['dependency_management'],
        'description': 'Using outdated or vulnerable third-party libraries can lead to security issues.',
        'recommendation': 'Regularly update and patch third-party dependencies.',
        'rule_id': 'C019',
    },
    'Insufficient Logging and Monitoring': {
        'category': 'Logging and Monitoring',
        'parameters': ['logging_best_practices'],
        'description': 'Inadequate logging and monitoring can lead to undetected security incidents.',
        'recommendation': 'Implement robust logging and monitoring for security events.',
        'rule_id': 'C020',
    },
    'Insecure Deserialization': {
        'category': 'Data Serialization',
        'parameters': ['serialization_security'],
        'description': 'Improper handling of deserialization can lead to code execution vulnerabilities.',
        'recommendation': 'Validate and secure deserialization processes.',
        'rule_id': 'C021',
    },
    'CORS Misconfiguration': {
        'category': 'Web Security',
        'parameters': ['cors_security'],
        'description': 'Insecure Cross-Origin Resource Sharing (CORS) configuration can lead to data exposure.',
        'recommendation': 'Configure CORS policies correctly and restrict access as needed.',
        'rule_id': 'C022',
    },
    'Broken Authentication': {
        'category': 'Authentication and Authorization',
        'parameters': ['authentication_best_practices'],
        'description': 'Insecure authentication mechanisms can lead to unauthorized access.',
        'recommendation': 'Implement strong authentication and authorization practices.',
        'rule_id': 'C023',
    },
    'Path Traversal': {
        'category': 'File and Path Security',
        'parameters': ['path_traversal_prevention'],
        'description': 'Improper handling of file paths can lead to unauthorized access and data exposure.',
        'recommendation': 'Sanitize and validate file paths to prevent path traversal.',
        'rule_id': 'C024',
    },
    'XML External Entity (XXE)': {
        'category': 'XML Security',
        'parameters': ['xxe_prevention'],
        'description': 'Improper XML processing can lead to XXE vulnerabilities.',
        'recommendation': 'Use secure XML processing libraries and disable external entities.',
        'rule_id': 'C025',
    },
    'Cross-Site Request Forgery (CSRF)': {
        'category': 'Web Security',
        'parameters': ['csrf_prevention'],
        'description': 'Lack of CSRF protection can lead to unauthorized actions on behalf of users.',
        'recommendation': 'Implement anti-CSRF tokens and validate requests.',
        'rule_id': 'C026',
    },
    'Unvalidated Redirects and Forwards': {
        'category': 'Web Security',
        'parameters': ['url_validation'],
        'description': 'Unvalidated redirects can lead to phishing and other attacks.',
        'recommendation': 'Validate and verify redirects and forwards.',
        'rule_id': 'C027',
    },
    'Security Misconfiguration': {
        'category': 'Configuration Management',
        'parameters': ['configuration_security'],
        'description': 'Insecure configuration settings can lead to security vulnerabilities.',
        'recommendation': 'Follow secure configuration practices and minimize attack surfaces.',
        'rule_id': 'C028',
    },
    'Sensitive Data Exposure': {
        'category': 'Data Protection',
        'parameters': ['data_encryption'],
        'description': 'Exposing sensitive data without encryption can lead to data breaches.',
        'recommendation': 'Encrypt sensitive data and use strong encryption algorithms.',
        'rule_id': 'C029',
    },
    'SQL Injection': {
        'category': 'Injection Attacks',
        'parameters': ['sql_injection_prevention'],
        'description': 'Improper SQL query handling can lead to SQL injection vulnerabilities.',
        'recommendation': 'Use parameterized queries and avoid string concatenation.',
        'rule_id': 'C030',
    },
    'Code Execution': {
        'category': 'Code Execution',
        'parameters': ['code_execution_validation'],
        'description': 'Allowing code execution from untrusted sources can lead to code execution vulnerabilities.',
        'recommendation': 'Avoid executing code from untrusted sources.',
        'rule_id': 'C031',
    },
    'Broken Access Control': {
        'category': 'Access Control',
        'parameters': ['access_control_best_practices'],
        'description': 'Inadequate access control can lead to unauthorized access to resources.',
        'recommendation': 'Implement proper access control mechanisms.',
        'rule_id': 'C032',
    },
    'Unvalidated User Input': {
        'category': 'Input Validation',
        'parameters': ['input_validation'],
        'description': 'Lack of user input validation can lead to various vulnerabilities.',
        'recommendation': 'Validate and sanitize user inputs.',
        'rule_id': 'C033',
    },
    'Insufficient Anti-Automation': {
        'category': 'Automation Prevention',
        'parameters': ['anti-automation_security'],
        'description': 'Inadequate protection against automation can lead to abuse and fraud.',
        'recommendation': 'Implement anti-automation measures to protect against abuse.',
        'rule_id': 'C034',
    },
    'File Upload Vulnerabilities': {
        'category': 'File Handling',
        'parameters': ['file_upload_security'],
        'description': 'Insecure file uploads can lead to arbitrary file execution and data exposure.',
        'recommendation': 'Implement secure file upload mechanisms and validate file types.',
        'rule_id': 'C035',
    },
}

cve_patterns = {
    'CVE-2023-1111': r'scanf\(.+\)',  # Example: Avoid using scanf without proper input validation
    'CVE-2023-2222': r'gets\(.+\)',  # Example: Avoid using gets, as it's unsafe and can lead to buffer overflows
    'CVE-2023-3333': r'system\(.+\)',  # Example: Avoid using system calls with untrusted input
    'CVE-2023-4444': r'strcpy\(.+\)',  # Example: Use safer string copy functions like strncpy
    'CVE-2023-5555': r'strpcat\(.+\)',  # Example: Use safer string concatenation functions like strncat
    'CVE-2023-6666': r'memcpy\(.+\)',  # Example: Use safer memory copy functions and validate sizes
    'CVE-2023-7777': r'fopen\(.+\)',  # Example: Check for file open failures and handle errors
    'CVE-2023-8888': r'access\(.+\)',  # Example: Ensure proper file access checks are in place
    'CVE-2023-9999': r'fprintf\(.+\)',  # Example: Avoid format string vulnerabilities in fprintf
    'CVE-2023-1010': r'snprintf\(.+\)',  # Example: Use snprintf with proper bounds checking
    'CVE-2023-1111': r'execl\(.+\)',  # Example: Avoid executing external commands without validation
    'CVE-2023-1212': r'malloc\(.+\)',  # Example: Check for memory allocation failures and handle them
    'CVE-2023-1313': r'free\(.+\)',  # Example: Avoid double freeing memory and ensure proper memory management
    'CVE-2023-1414': r'chroot\(.+\)',  # Example: Use chroot with caution and validate input
    'CVE-2023-1515': r'unlink\(.+\)',  # Example: Ensure proper file removal checks and permissions
    'CVE-2023-1616': r'sprintf\(.+\)',  # Example: Avoid format string vulnerabilities in sprintf
    'CVE-2023-1717': r'execve\(.+\)',  # Example: Validate arguments in execve calls
    'CVE-2023-1818': r'opendir\(.+\)',  # Example: Check for directory open failures and handle them
    'CVE-2023-1919': r'printf\(.+\)',  # Example: Avoid format string vulnerabilities in printf
    'CVE-2023-2020': r'getenv\(.+\)',  # Example: Validate and sanitize environment variables
    'CVE-2023-2121': r'fread\(.+\)',  # Example: Check for file read failures and handle errors
    'CVE-2023-2222': r'rename\(.+\)',  # Example: Ensure proper file rename checks and permissions
    'CVE-2023-2323': r'atof\(.+\)',  # Example: Validate and sanitize floating-point conversions
    'CVE-2023-2424': r'memmove\(.+\)',  # Example: Use safer memory move functions and validate sizes
    'CVE-2023-2525': r'memset\(.+\)',  # Example: Use safer memory set functions and validate sizes
    'CVE-2023-2626': r'setuid\(.+\)',  # Example: Avoid insecure use of setuid and setgid
    'CVE-2023-2727': r'fputc\(.+\)',  # Example: Check for file write failures and handle errors
    'CVE-2023-2828': r'getpwuid\(.+\)',  # Example: Validate the results of getpwuid to prevent unauthorized access
    'CVE-2023-2929': r'chown\(.+\)',  # Example: Ensure proper file ownership changes and permissions
    'CVE-2023-3030': r'setsid\(.+\)',  # Example: Use setsid with proper error handling and validation
}

def analyze_c_file(file_path):
    with open(file_path, 'r') as file:
        c_code = file.read()

    issues = []

    for rule, rule_details in c_ruleset.items():
        if all(key in rule_details for key in ('description', 'severity', 'recommendation')):
            rule_pattern = re.compile(r'\b{}\b'.format(re.escape(rule)), re.IGNORECASE)
            if re.search(rule_pattern, c_code):
                issues.append({
                    'file_path': file_path,
                    'severity': rule_details['severity'],
                    'description': rule_details['description'],
                    'recommendation': rule_details['recommendation'],
                    'category': rule_details.get('category', ''),
                    'rule_id': rule_details.get('rule_id', '')
                })

    for cve, pattern in cve_patterns.items():
        matches = re.findall(pattern, c_code)
        if matches:
            issues.extend([{
                'file_path': file_path,
                'severity': 'High',  # Adjust the severity as needed for CVEs
                'description': f'Potential CVE {cve} pattern found: {pattern}',
                'recommendation': 'Follow security best practices for this code.',
                'category': 'CVE',
                'rule_id': cve
            }])

    return issues

def scan_c_files(directory_path):
    issues = []

    # Regular expression pattern to match C code file extensions
    c_file_pattern = r'.*\.c$'

    for root, _, files in os.walk(directory_path):
        for file in files:
            if re.match(c_file_pattern, file):
                file_path = os.path.join(root, file)
                issues += analyze_c_file(file_path)

    return issues


class ScanWorker(QThread):
    scan_complete = pyqtSignal(list)

    def __init__(self, directory_path):
        super().__init__()
        self.directory_path = directory_path

    def run(self):
        detected_issues = scan_c_files(self.directory_path)
        self.scan_complete.emit(detected_issues)

class CodeScannerApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Code Scanner (C)')
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
            self.textbox.setPlainText("No security issues found in the C code files.")

def main():
    app = QApplication(sys.argv)
    window = CodeScannerApp()
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()

