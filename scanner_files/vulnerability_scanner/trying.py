import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, QLabel, QAction, QTextBrowser

class VulnerabilityCheckerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Vulnerability Checker Tool')
        self.setGeometry(100, 100, 800, 600)
        

        # Create a tab widget
        tab_widget = QTabWidget(self)

        # Create tab titles
        tabs = [
            'WELCOME TO WORLD OF SCANNING !!'
        ]

        # Create tabs and add them to the tab widget
        self.tab_widgets = [QWidget() for _ in tabs]
        for i, tab_title in enumerate(tabs):
            tab_widget.addTab(self.tab_widgets[i], tab_title)

        self.setCentralWidget(tab_widget)

        # Create menu actions
        self.create_menu_actions()

        # Set up the tabs with content
        self.setup_tabs()

    def create_menu_actions(self):
        file_menu = self.menuBar().addMenu('SCAN')

        menu_actions = [
            ('Broken Authentication Scanner', 'gui_broken_auth.py'),
            ('Clickjacking Scanner', 'gui_clickjacking.py'),
            ('Content Spoofing Checker', 'gui_content_spoofing.py'),
            ('Website Crawler', 'gui_crawler.py'),
            ('Directory-SSRF-CRLF Vuln Scanner', 'gui_directory_ssrf_clrf.py'),
            ('Inadequate Security Headers Scanner', 'gui_InadequateSecurityHeaders.py'),
            ('Insecure File Upload Scanner', 'gui_InsecureFileUpload.py'),
            ('Local File Inclusion Scanner', 'gui_lfi.py'),
            ('SQL Injection Scanner', 'gui_sql_injection.py'),
            ('Unvalidated Redirects & Forwards Scanner', 'gui_unvalidatedRedirectsandForwards.py'),
            ('Cross-Site Scripting Scanner', 'gui_xss_scanner.py')
        ]

        for action_text, script_path in menu_actions:
            action = QAction(action_text, self)
            action.triggered.connect(lambda checked, script=script_path: self.run_script(script))
            file_menu.addAction(action)

    def setup_tabs(self):
        tab_contents = [
            # Content for the first tab (WELCOME TO WORLD OF SCANNING !!)
            """
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerability Scanning</title>
</head>
<body>

<h1>Vulnerability Scanning</h1>

<p>Vulnerability scanning is a vital cybersecurity practice that identifies and mitigates weaknesses in computer systems, networks, and software applications, ensuring digital asset security. <br> Vulnerabilities, ranging from OS flaws to human errors, offer entry points for attackers to breach defenses, steal data, and disrupt operations.</p>

<h2>Purpose of Vulnerability Scanning</h2>
<p>Vulnerability scanning involves identification, assessment, prioritization, and remediation of weaknesses. <br> It helps organizations reduce risk by patching software, configuring systems, and strengthening security policies. <br> Regular scans detect emerging threats.</p>

<h2>Types of Vulnerability Scanning</h2>
<p>Network vulnerability scanning assesses devices like routers, switches, and firewalls.<br> Web application scanning targets vulnerabilities, such as SQL injection and XSS. <br>Operating system scans identify missing patches and OS-specific issues. Database scanning examines data security.</p>

<h2>Role of Automation</h2>
<p>Automation enhances efficiency by scanning large networks and generating reports swiftly. <br> It enables proactive threat response and regular scans, crucial in today's dynamic threat landscape.</p>

<h2>Challenges and Considerations</h2>
<p>Challenges include false positives/negatives, scanning impact on system performance, <br> regulatory compliance, and integration with broader cybersecurity strategies.</p>

<h2>Evolving Threat Landscape</h2>
<p>Adapting to ever-evolving threats, advanced scanning tools stay ahead of zero-day exploits and evolving malware.<br> Vigilance is key in the ever-changing cybersecurity landscape.</p>

<h2>Conclusion</h2>
<p>Vulnerability scanning safeguards digital assets, maintains confidentiality, and ensures business continuity. <br> It addresses weaknesses systematically, protecting systems against evolving threats.</p>

</body>
</html>

            """
        ]

        for i, content in enumerate(tab_contents):
            text_browser = QTextBrowser()
            text_browser.setOpenExternalLinks(True)
            text_browser.setOpenLinks(True)
            text_browser.setHtml(content)
            layout = QVBoxLayout()
            layout.addWidget(text_browser)
            self.tab_widgets[i].setLayout(layout)

    def run_script(self, script_path):
        import subprocess
        subprocess.Popen(['python3', '/home/radheya/personal/vuln_scanner/scanner_files/vulnerability_scanner/' + script_path])

def main():
    app = QApplication(sys.argv)
    window = VulnerabilityCheckerApp()
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
