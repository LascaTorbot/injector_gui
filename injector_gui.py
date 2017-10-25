#!/bin/python

import sys
from PyQt4.QtCore import pyqtSlot, SIGNAL,SLOT, pyqtSignal
from PyQt4.QtCore import QThread
from PyQt4.QtGui import *
from scapy.all import *
import sys
import os
from injector_lib import getFlags, Sniffer
from rst_ares import Attack_RST

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

class TextBox(QPlainTextEdit):
    def __init__(self, text=""):
        super(TextBox, self).__init__()
        self.text = text

    def setText(self, text):
        self.text = text

    def appendText(self, text):
        self.text +=  text

    def getText(self):
        return self.text

    def updateText(self):
        self.setPlainText(self.text)

class MainWindow(QWidget):
    def __init__(self):
        super(MainWindow, self).__init__()


if __name__ == "__main__":

    # create our window
    app = QApplication(sys.argv)
    w = MainWindow()
    w.setWindowTitle('Packet injector')
    w.resize(700, 900)

    # set layout
    grid = QGridLayout()
    grid.setSpacing(10)
    w.setLayout(grid)

    # set title label
    title_label = QLabel('Packet injector                 Filter (BPF syntax):')
    grid.addWidget(title_label, 0, 0)

    # set filter text box
    filter_textbox = QLineEdit()
    grid.addWidget(filter_textbox, 0, 1)

    # set filter button
    btn_filter = QPushButton("Apply")
    grid.addWidget(btn_filter, 0, 2)
    @pyqtSlot()
    def on_click():
        f = filter_textbox.text()
        if len(f) > 0:
            global sniffer
            sniffer.setRestart()
            sniffer = Sniffer()
            sniffer.setTable(table)
            sniffer.setFilter("tcp and " + f)
            sniffer.start()

    btn_filter.clicked.connect(on_click)


    # prepare table
    table 	= QTableWidget()
    tableItem 	= QTableWidgetItem()
    table.setRowCount(1000)
    table.setColumnCount(6)
    table.setHorizontalHeaderLabels(("IP src; IP dst; Port src; Port dst; Flags; Raw").split(";"))
    grid.addWidget(table, 1, 0, 1, 3)

    # start sniffing
    sniffer = Sniffer()
    sniffer.setTable(table)
    sniffer.start()

    # prepare "Attack" label
    attack_label = QLabel('Attacks')
    grid.addWidget(attack_label, 2, 0)

    # create RST button
    btn_rst = QPushButton('RST attack (Ares)')
    rst = Attack_RST()
    @pyqtSlot()
    def on_click():
        text_log.appendText("RST attack starting...")
        text_log.updateText()
        rst.start()

    grid.addWidget(btn_rst, 3, 0)
    btn_rst.clicked.connect(on_click)


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

    # system log
    log_label = QLabel('System log:')
    grid.addWidget(log_label, 5, 0)
    text_log = TextBox()
    text_log.setEnabled(False)
    grid.addWidget(text_log, 6, 0)
    w.connect(rst, SIGNAL("finished()"), text_log.updateText)

    # original payload
    original_label = QLabel('Original payload:')
    grid.addWidget(original_label, 5, 1)
    text_original = TextBox()
    text_original.setEnabled(False)
    grid.addWidget(text_original, 6, 1)
    w.connect(rst, SIGNAL("finished()"), text_original.updateText)

    # new payload
    new_label = QLabel('New payload:')
    grid.addWidget(new_label, 5, 2)
    text_new = TextBox()
    text_new.setEnabled(False)
    grid.addWidget(text_new, 6, 2)
    w.connect(rst, SIGNAL("finished()"), text_new.updateText)

    rst.setTextBox(text_log, text_original, text_new)

    # Show the window and run the app
    w.show()
    app.exec_()
