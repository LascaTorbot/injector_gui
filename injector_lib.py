from scapy.all import *
from PyQt4.QtCore import QThread
from PyQt4.QtGui import QColor, QTableWidgetItem

def getFlags(F):
    # TCP Flags and their hex code
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80

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

class Sniffer(QThread):

    def __init__(self):
        QThread.__init__(self)
        self.i = 0
        self.table = None
        self.filter = "tcp"
        self.restart = False

    def __del__(self):
        self.wait()

    def setTable(self, table):
        self.table = table

    def setFilter(self, filter_arg):
        self.filter = filter_arg

    def setRestart(self):
        self.restart = True

    def capture(self):
        s = sniff(filter=self.filter, prn=lambda packet: self.unpack(packet))

    def setTableColor(self, flags):
        if 'RST' in flags:
            cell_color = QColor(164, 0, 0)
            font_color = QColor(255, 255, 255)
        elif 'FIN' in flags or 'SYN' in flags:
            cell_color = QColor(160, 160, 160)
            font_color = QColor(0, 0, 0)
        elif 'ACK' in flags and 'PSH' in flags:
            cell_color = QColor(228, 255, 199)
            font_color = QColor(0, 0, 0)
        elif 'ACK' in flags:
            cell_color = QColor(231, 230, 255)
            font_color = QColor(0, 0, 0)
        else:
            cell_color = QColor(255, 255, 255)
            font_color = QColor(0, 0, 0)

        return cell_color, font_color

    def unpack(self, packet):
        try:
            if IP in packet:
                src = packet[IP].src
                dst = packet[IP].dst
            elif IPv6 in packet:
                src = packet[IPv6].src
                dst = packet[IPv6].dst
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
        except:
            print("Error in unpack")

        finally:
            self.updateTable([src, dst, str(sport), str(dport), str(flags), raw])

        if self.restart:
            self.restart = False
            self.terminate()

    def updateTable(self, args):
        cell_color, font_color = self.setTableColor(args[4])

        j = 0
        for data in args:
            item = QTableWidgetItem(data)
            self.table.setItem(self.i, j, item)
            item.setBackground(cell_color)
            item.setForeground(font_color)
            j += 1

        self.i += 1

    def run(self):
        self.capture()
