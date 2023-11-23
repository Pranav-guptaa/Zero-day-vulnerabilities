import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, QLabel

class VulnerabilityCheckerApp(QMainWindow):
    def __init__(self):
        super().__init__()

        self.initUI()

    def initUI(self):
        self.setWindowTitle('Vulnerability Checker')
        self.setGeometry(100, 100, 800, 600)

        # Create a tab widget
        tab_widget = QTabWidget(self)

        # Create tabs for different vulnerabilities
        self.tab1 = QWidget()
        self.tab2 = QWidget()
        self.tab3 = QWidget()

        # Add tabs to the tab widget
        tab_widget.addTab(self.tab1, 'Vulnerability 1')
        tab_widget.addTab(self.tab2, 'Vulnerability 2')
        tab_widget.addTab(self.tab3, 'Vulnerability 3')

        # Add widgets to each tab to demonstrate vulnerabilities
        self.add_widgets_to_tab1()
        self.add_widgets_to_tab2()
        self.add_widgets_to_tab3()

        self.setCentralWidget(tab_widget)

    def add_widgets_to_tab1(self):
        layout = QVBoxLayout()
        label = QLabel('Vulnerability 1: Description of the first vulnerability')
        layout.addWidget(label)
        self.tab1.setLayout(layout)

    def add_widgets_to_tab2(self):
        layout = QVBoxLayout()
        label = QLabel('Vulnerability 2: Description of the second vulnerability')
        layout.addWidget(label)
        self.tab2.setLayout(layout)

    def add_widgets_to_tab3(self):
        layout = QVBoxLayout()
        label = QLabel('Vulnerability 3: Description of the third vulnerability')
        layout.addWidget(label)
        self.tab3.setLayout(layout)

def main():
    app = QApplication(sys.argv)
    window = VulnerabilityCheckerApp()
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
