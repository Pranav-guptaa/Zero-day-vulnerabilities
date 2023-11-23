import sys
import subprocess
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import QDialog, QVBoxLayout, QLabel, QComboBox, QPushButton, QApplication

class LanguageScannerApp(QDialog):
    def __init__(self):
        super().__init__()

        self.setWindowTitle('Vulnerability Scanner')
        self.setFixedSize(400, 200)

        layout = QVBoxLayout()

        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title_font.setFamily('Arial') 

        self.title_label = QLabel('Select a Language to Scan:', self)
        self.title_label.setFont(title_font)
        self.title_label.setAlignment(Qt.AlignCenter)

        self.language_combo = QComboBox(self)
        self.language_combo.addItem('C')
        self.language_combo.addItem('C++')
        self.language_combo.addItem('Java')
        self.language_combo.addItem('JavaScript')
        self.language_combo.addItem('Golang')
        self.language_combo.setCurrentIndex(-1)

        self.scan_button = QPushButton('Scan', self)
        self.scan_button.clicked.connect(self.scanLanguage)

        layout.addWidget(self.title_label)
        layout.addWidget(self.language_combo)
        layout.addWidget(self.scan_button)

        self.setLayout(layout)

        # Apply custom stylesheet
        self.setStyleSheet(
            "QDialog { background-color: #FFDAB9; }"
            "QLabel { color: blue;}"
            "QLabel:hover {color: red;}"
            "QComboBox { background-color: #fff; color: #000; font-size: 14px; font-weight: bold; font-family: Arial, sans-serif;}"
            "QPushButton { background-color: #007ACC; color: #fff; font-size: 14px; font-weight: bold;}"
            "QPushButton:hover { background-color: #7FFF00; color: black;}"
        )
        
    def scanLanguage(self):
        selected_language = self.language_combo.currentText()
        if selected_language:
            script_to_run = None

            if selected_language == 'C':
                script_to_run = '/home/radheya/personal/vuln_scanner/scanner_files/secure_coding_scanner/gui_application/c_gui.py'
            elif selected_language == 'C++':
                script_to_run = '/home/radheya/personal/vuln_scanner/scanner_files/secure_coding_scanner/gui_application/cpp_gui.py'
            elif selected_language == 'Java':
                script_to_run = '/home/radheya/personal/vuln_scanner/scanner_files/secure_coding_scanner/gui_application/java_gui.py'
            elif selected_language == 'JavaScript':
                script_to_run = '/home/radheya/personal/vuln_scanner/scanner_files/secure_coding_scanner/gui_application/js_gui.py'
            elif selected_language == 'Golang':
                script_to_run = '/home/radheya/personal/vuln_scanner/scanner_files/secure_coding_scanner/gui_application/go_gui.py'

            if script_to_run:
                subprocess.run(['python3', script_to_run])
            else:
                print("No script defined for the selected language.")
        else:
            print("Please select a language to scan.")

def main():
    app = QApplication(sys.argv)
    window = LanguageScannerApp()
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
