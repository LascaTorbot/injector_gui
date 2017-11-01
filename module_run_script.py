from PyQt4.QtCore import QThread
from PyQt4.QtCore import pyqtSlot
from PyQt4.QtGui import QWidget, QGridLayout, QLabel, QPushButton, QLineEdit, QFileDialog
from SyntaxHighlighting import *
from scapy.all import *
from injector_lib import getFlags, TextBox

### FUNCTIONS THAT RUNS ON SCRIPT ###

# Attack the IP passed with a generic Denail of Service
# TODO: implement the package sending
def DoS(ip):
        original_textBox.setText("Attacking " + ip)


# Return True if pkt contains the substring
def verifyRaw(pkt, substring):
        if Raw in pkt:
            load = str(pkt[Raw].load)
            if substring in load:
                return True

# Return True if pkt contains the substring
def contains(substring):
        sniff(filter="tcp", prn=lambda pkt: verifyRaw(pkt, substring))


# Return true if the source IP is hostname
def source_url(hostname):
        sniff(count=1, filter="ip src " + hostname)
        return True


# Return true if the destination IP is hostname
def destin_url(hostname):
        sniff(count=1, filter="ip dst " + hostname)
        return True


# Return the IP address from the URL
def getIP(url):
        return socket.gethostbyname(url)

log_textBox = None
original_textBox = None
new_textBox = None

def setTextBox(log, original, new):
    global log_textBox, original_textBox, new_textBox
    log_textBox = log
    original_textBox = original
    new_textBox = new

class Module_Run_Script(QThread):
    def __init__(self):
        QThread.__init__(self)
        self.script = ""

    def __del__(self):
        self.wait()

    def setupUI(self):
        window = QWidget()
        window.setWindowTitle('Run script')
        window.resize(550, 300)
        window_layout = QGridLayout()
        window.setLayout(window_layout)

        btn_load = QPushButton("Load file")
        lbl_loaded = QLabel("Nothing loaded...")
        window_layout.addWidget(btn_load, 0, 0)
        window_layout.addWidget(lbl_loaded, 0, 1)

        script_textBox = TextBox()
        window_layout.addWidget(script_textBox, 1, 0, 1, 0)
        self.highlight = PythonHighlighter(script_textBox.document())

        btn_att = QPushButton("Attack!")
        window_layout.addWidget(btn_att, 2, 0)

        @pyqtSlot()
        def on_click():
            self.attack_file = QFileDialog.getOpenFileName(window, 'Open file',
                '',"")
            path = self.attack_file.rfind('/')
            self.attack_file = self.attack_file[path+1:]
            lbl_loaded.setText(self.attack_file)
            script_textBox.setText("")

            with open(self.attack_file) as f:
                for line in f.readlines():
                    self.script += line
                    script_textBox.appendText(line)

            script_textBox.updateText()

        btn_load.clicked.connect(on_click)

        @pyqtSlot()
        def on_click():
            self.start()

        btn_att.clicked.connect(on_click)

        return window


    def setTextBox(self, log_textBox, original_textBox, new_textBox):
        self.log_textBox = log_textBox
        self.original_textBox = original_textBox
        self.new_textBox = new_textBox

    def attack(self):
        self.start()

    def run(self):
        exec("if " + self.script)
