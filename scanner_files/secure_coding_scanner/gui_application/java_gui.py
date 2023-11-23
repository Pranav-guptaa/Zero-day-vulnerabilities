import sys
import os
import re
import subprocess
from PyQt5.QtCore import Qt, QCoreApplication
from PyQt5.QtCore import Qt, QDir, QThread, pyqtSignal
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QTextEdit, QPushButton, QApplication, QFileDialog, QProgressBar, QGroupBox
from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QFileDialog, QTextEdit, QVBoxLayout

java_ruleset = {
    
    'BufferedReader.readLine': {
        'severity': 'High',
        'description': 'May not handle large input lines properly and can lead to buffer overflows',
        'recommendation': 'Consider using a custom input handling mechanism with proper input validation and error handling',
        'category': 'Buffer Overflow',
        'parameters': {},
        'rule_id': 'FF1001'
    },
    'String.getBytes': {
        'severity': 'Medium',
        'description': 'May not specify character encoding, leading to potential security issues',
        'recommendation': 'Always specify the character encoding when converting strings to bytes',
        'category': 'Encoding',
        'parameters': {
            'encoding': 'UTF-8'
        },
        'rule_id': 'FF1002'
    },
    'Runtime.exec': {
        'severity': 'High',
        'description': 'Allows execution of arbitrary system commands, leading to security risks',
        'recommendation': 'Avoid using Runtime.exec or validate and sanitize user input before executing commands',
        'category': 'Command Injection',
        'parameters': {},
        'rule_id': 'FF1003'
    },
    'Password Hardcoding': {
        'severity': 'High',
        'description': 'Hardcoded passwords in the source code are a significant security risk',
        'recommendation': 'Store passwords in a secure configuration file or use environment variables',
        'category': 'Authentication',
        'parameters': {},
        'rule_id': 'FF1004'
    },
    'SQL Injection': {
        'severity': 'High',
        'description': 'Failure to properly sanitize user inputs in SQL queries can lead to SQL injection attacks',
        'recommendation': 'Use parameterized queries or prepared statements to prevent SQL injection',
        'category': 'SQL Injection',
        'parameters': {},
        'rule_id': 'FF1005'
    },
    'Insecure Deserialization': {
        'severity': 'High',
        'description': 'Deserializing untrusted data can lead to security vulnerabilities',
        'recommendation': 'Validate and sanitize input data before deserialization or use safe serialization libraries',
        'category': 'Serialization',
        'parameters': {},
        'rule_id': 'FF1006'
    },
    'Weak Password Storage': {
        'severity': 'High',
        'description': 'Storing passwords in plaintext or weakly hashed forms is insecure',
        'recommendation': 'Use strong password hashing algorithms like bcrypt or scrypt',
        'category': 'Authentication',
        'parameters': {},
        'rule_id': 'FF1007'
    },
    'Cross-Site Scripting (XSS)': {
        'severity': 'High',
        'description': 'Failure to properly sanitize and escape user-generated content can lead to XSS attacks',
        'recommendation': 'Sanitize and escape user inputs before rendering them in HTML',
        'category': 'Cross-Site Scripting',
        'parameters': {},
        'rule_id': 'FF1008'
    },
    'Inadequate Session Management': {
        'severity': 'Medium',
        'description': 'Weak or missing session management can lead to unauthorized access',
        'recommendation': 'Implement secure session management practices and use strong session identifiers',
        'category': 'Session Management',
        'parameters': {},
        'rule_id': 'FF1009'
    },
    'File Inclusion Vulnerability': {
        'severity': 'High',
        'description': 'Improper handling of file inclusion can lead to arbitrary file read or code execution',
        'recommendation': 'Always validate and sanitize file paths used in includes and use allow-lists',
        'category': 'File Inclusion',
        'parameters': {},
        'rule_id': 'FF1010'
    },
    'Broken Authentication': {
        'severity': 'High',
        'description': 'Weak authentication mechanisms can lead to unauthorized access and data breaches',
        'recommendation': 'Implement strong authentication methods and ensure secure password management',
        'category': 'Authentication',
        'parameters': {},
        'rule_id': 'FF1011'
    },
    # Add more rules as needed
    'XML External Entity (XXE) Injection': {
        'severity': 'High',
        'description': 'Failure to properly parse XML input can lead to XXE vulnerabilities',
        'recommendation': 'Use secure XML parsers and disable external entity expansion',
        'category': 'XML Security',
        'parameters': {},
        'rule_id': 'FF1012'
    },
    'Unvalidated Redirects and Forwards': {
        'severity': 'Medium',
        'description': 'Improper handling of redirects and forwards can lead to open redirect vulnerabilities',
        'recommendation': 'Always validate and sanitize input for redirects and use whitelists',
        'category': 'Web Security',
        'parameters': {},
        'rule_id': 'FF1013'
    },
    'Insecure Random Number Generation': {
        'severity': 'Medium',
        'description': 'Using weak random number generation can compromise security',
        'recommendation': 'Use cryptographically secure random number generators for security-critical operations',
        'category': 'Cryptographic Security',
        'parameters': {},
        'rule_id': 'FF1014'
    },
    'Sensitive Data Exposure': {
        'severity': 'High',
        'description': 'Failure to properly protect sensitive data can lead to data exposure',
        'recommendation': 'Implement strong encryption and access controls for sensitive data',
        'category': 'Data Security',
        'parameters': {},
        'rule_id': 'FF1015'
    },
    'Cross-Origin Resource Sharing (CORS) Misconfiguration': {
        'severity': 'Medium',
        'description': 'Incorrect CORS configuration can lead to security vulnerabilities',
        'recommendation': 'Ensure proper CORS configuration and validate origins',
        'category': 'Web Security',
        'parameters': {},
        'rule_id': 'FF1016'
    },
    'Path Traversal Vulnerability': {
        'severity': 'High',
        'description': 'Inadequate input validation can lead to path traversal attacks',
        'recommendation': 'Always validate and sanitize input for path traversal and use allow-lists',
        'category': 'File System Security',
        'parameters': {},
        'rule_id': 'FF1017'
    },
    'Cross-Site Request Forgery (CSRF)': {
        'severity': 'High',
        'description': 'Failure to protect against CSRF can lead to unauthorized actions',
        'recommendation': 'Use anti-CSRF tokens and validate requests for security-critical operations',
        'category': 'Web Security',
        'parameters': {},
        'rule_id': 'FF1018'
    },
    'Insecure Direct Object References': {
        'severity': 'High',
        'description': 'Lack of proper access controls can lead to insecure direct object references',
        'recommendation': 'Implement access controls and proper validation for sensitive data access',
        'category': 'Access Control',
        'parameters': {},
        'rule_id': 'FF1019'
    },
    'Code Injection (e.g., eval)': {
        'severity': 'High',
        'description': 'Using functions like eval can lead to code injection vulnerabilities',
        'recommendation': 'Avoid using eval or any dynamic code execution unless absolutely necessary',
        'category': 'Code Injection',
        'parameters': {},
        'rule_id': 'FF1020'
    }

}

cve_patterns = {
    'CVE-2019-1234': r'unsafeMethod\(.*\)',

    'CVE-2020-5678': r'vulnerableLibrary\.doSomething\(.+\)',    

    'CVE-2021-1234': r'Runtime\.getRuntime\(\)\.exec\(.+\)',

    'CVE-2019-5678': r'new\sProcessBuilder\(.*\)\.command\(.*\)',

    'CVE-2020-9876': r'Dispatcher\.servletPath\s*=\s*request\.getParameter\("servletPath"\)',

    'CVE-2021-4321': r'XMLReader\s*reader\s*=\s*XMLReaderFactory\.createXMLReader\(\)',

    'CVE-2018-8765': r'SQL\s*query\s*=\s*request\.getParameter\("query"\)',

    'CVE-2017-6543': r'User\.getPassword\(\)',

    'CVE-2022-2109': r'new\sSocket\(.+\)\.connect\(new\sInetSocketAddress\(.+\)\)',

    'CVE-2019-1111': r'Cipher\s*encryptionCipher\s*=\s*Cipher\.getInstance\("AES/ECB/PKCS5Padding"\)',
    
    'CVE-2023-1001': r'Runtime\.getRuntime\(\)\.exec\(.+\)',

    'CVE-2023-1002': r'new\sProcessBuilder\(.*\)\.command\(.*\)',

    'CVE-2023-1003': r'Dispatcher\.servletPath\s*=\s*request\.getParameter\("servletPath"\)',

    'CVE-2023-1004': r'XMLReader\s*reader\s*=\s*XMLReaderFactory\.createXMLReader\(\)',

    'CVE-2023-1005': r'SQL\s*query\s*=\s*request\.getParameter\("query"\)',

    'CVE-2023-1006': r'User\.getPassword\(\)',

    'CVE-2023-1007': r'new\sSocket\(.+\)\.connect\(new\sInetSocketAddress\(.+\)\)',

    'CVE-2023-1008': r'Cipher\s*encryptionCipher\s*=\s*Cipher\.getInstance\("AES/ECB/PKCS5Padding"\)',

    'CVE-2023-1009': r'new\sObjectInputStream\(.*\)',

    'CVE-2023-1010': r'new\sObjectOutputStream\(.*\)',

    'CVE-2023-1011': r'System\.setSecurityManager\(.*\)',

    'CVE-2023-1012': r'System\.exit\(.+\)',

    'CVE-2023-1013': r'LDAP\sbind\(.+\)',

    'CVE-2023-1014': r'Deserialization\sfrom\suntrusted\sstreams',

    'CVE-2023-1015': r'Password\sstring\scomparison\susing\s==\sor\s!=',

    'CVE-2023-1016': r'Weak\srandom\snumber\sgeneration',

    'CVE-2023-1017': r'Hardcoded\ssecrets\sor\scredentials',

    'CVE-2023-1018': r'Insecure\susage\sof\sHTTP',

    'CVE-2023-1019': r'File\supload\ssecurity\sbypass',

    'CVE-2023-1020': r'SQL\sInjection\susing\sraw\suser\sinput',

    'CVE-2023-1021': r'Cross-Site\sScripting\s(XSS)\svulnerability',

    'CVE-2023-1022': r'Server\sSide\sRequest\sForgery\s(SSRF)',

    'CVE-2023-1023': r'XML\sExternal\sEntity\s(XXE)\svulnerability',

    'CVE-2023-1024': r'Denial\sof\Service\s(DoS)\svulnerability',

    'CVE-2023-1025': r'Insecure\sAuthentication\sor\sAuthorization',
}

def analyze_java_file(file_path):
    with open(file_path, 'r') as file:
        java_code = file.read()

    issues = []

    for rule, rule_details in java_ruleset.items():
        rule_pattern = re.compile(r'\b{}\b'.format(rule), re.IGNORECASE)
        if re.search(rule_pattern, java_code):
            issues.append({
                'file_path': file_path,  # Store the file path
                'severity': rule_details['severity'],
                'description': rule_details['description'],
                'recommendation': rule_details['recommendation'],
                'category': rule_details['category'],
                'rule_id': rule_details['rule_id']
            })

    for cve, pattern in cve_patterns.items():
        matches = re.findall(pattern, java_code)
        if matches:
            issues.extend([{
                'file_path': file_path,  # Store the file path
                'severity': 'High',  # Adjust the severity as needed for CVEs
                'description': f'Potential vulnerability {cve} pattern found: {pattern}',
                'recommendation': 'Follow security best practices for this code.',
                'category': 'CVE',
                'rule_id': cve
            }])

    return issues

def scan_java_files(directory_path):
    issues = []

    # Regular expression pattern to match Java file extensions
    java_file_pattern = r'.*\.java$'

    for root, _, files in os.walk(directory_path):
        for file in files:
            if re.match(java_file_pattern, file):
                file_path = os.path.join(root, file)
                issues += analyze_java_file(file_path)

    return issues

class ScanWorker(QThread):
    scan_complete = pyqtSignal(list)

    def __init__(self, directory_path):
        super().__init__()
        self.directory_path = directory_path

    def run(self):
        detected_issues = scan_java_files(self.directory_path)
        self.scan_complete.emit(detected_issues)

class CodeScannerApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Code Scanner')
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
            self.textbox.setPlainText("No security issues found in the code files.")

def main():
    app = QApplication(sys.argv)
    window = CodeScannerApp()
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()

