#!/bin/python

import sys
from PyQt4.QtCore import pyqtSlot, SIGNAL,SLOT, pyqtSignal
from PyQt4.QtCore import QThread
from PyQt4.QtGui import *
from injector_lib import getFlags, Sniffer
from module_rst import Module_RST

class customAttack(QThread):
    def __init__(self):
        QThread.__init__(self)
        self.attack_file = None
        self.attack_obj = None

    def __del__(self):
        self.wait()

    def setTextBox(self, log_textBox, original_textBox, new_textBox):
        self.log_textBox = log_textBox
        self.original_textBox = original_textBox
        self.new_textBox = new_textBox

    def getFile(self, window):
        self.attack_file = QFileDialog.getOpenFileName(window, 'Open file',
            '',"Attack script (*.py)")
        path = self.attack_file.rfind('/')
        self.attack_file = self.attack_file[path+1:].replace('.py', '')
        self.setupAttack()

    def setupAttack(self):
        if self.attack_file != " ":
            self.attack_obj = __import__(self.attack_file)
            self.attack_obj = self.attack_obj.Attack()
            self.attack_obj.setTextBox(self.log_textBox, self.original_textBox, self.new_textBox)
        else:
            print("Import error")

    def run(self):
        self.attack_obj.attack()

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
        self.log_textBox = None
        self.original_textBox = None
        self.new_textBox = None
        self.attack_button = None

    def setAttackButton(self, attack_button):
        self.attack_button = attack_button

    def setTextBox(self, log_textBox, original_textBox, new_textBox):
        self.log_textBox = log_textBox
        self.original_textBox = original_textBox
        self.new_textBox = new_textBox

    def updateScreen(self):
        self.log_textBox.updateText()
        self.original_textBox.updateText()
        self.new_textBox.updateText()
        self.attack_button.setEnabled(True)


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

    rst = Module_RST()
    # create RST button
    btn_rst = QPushButton('TCP reset attack')
    @pyqtSlot()
    def on_click():
        w_rst.show()
        text_log.appendText("TCP reset attack starting...\n")
        text_log.updateText()

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
        text_log.appendText("Starting " + custom_attack.attack_file + "...\n")
        text_log.updateText()
        custom_attack.start()
        btn_attack.setEnabled(False)

    grid.addWidget(btn_attack, 4, 2)
    btn_attack.clicked.connect(on_click)
    w.setAttackButton(btn_attack)
    w.connect(custom_attack, SIGNAL("finished()"), w.updateScreen)

    # system log
    log_label = QLabel('System log:')
    grid.addWidget(log_label, 5, 0)
    text_log = TextBox()
    text_log.setEnabled(False)
    grid.addWidget(text_log, 6, 0)
    w.connect(rst, SIGNAL("finished()"), text_log.updateText)

    # original payload
    original_label = QLabel('')
    grid.addWidget(original_label, 5, 1)
    text_original = TextBox()
    text_original.setEnabled(False)
    grid.addWidget(text_original, 6, 1)
    w.connect(rst, SIGNAL("finished()"), text_original.updateText)

    # new payload
    new_label = QLabel('')
    grid.addWidget(new_label, 5, 2)
    text_new = TextBox()
    text_new.setEnabled(False)
    grid.addWidget(text_new, 6, 2)
    w.connect(rst, SIGNAL("finished()"), text_new.updateText)

    rst.setTextBox(text_log, text_original, text_new)
    custom_attack.setTextBox(text_log, text_original, text_new)
    w.setTextBox(text_log, text_original, text_new)
    w.setAttackButton(btn_attack)

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
    rst_txt_iface = QLineEdit()
    w_rst_layout.addWidget(rst_lbl_iface, 1, 0)
    w_rst_layout.addWidget(rst_txt_iface, 1, 1)

    rst_lbl_filter = QLabel("BPF Filter: ")
    rst_txt_filter = QLineEdit()
    w_rst_layout.addWidget(rst_lbl_filter, 2, 0)
    w_rst_layout.addWidget(rst_txt_filter, 2, 1)

    rst_btn_att = QPushButton("Attack!")
    w_rst_layout.addWidget(rst_btn_att, 3, 0)


    @pyqtSlot()
    def on_click():
        text_log.appendText("TCP reset attack starting...\n")
        rst.setTarget(rst_txt_iface.text(), rst_txt_filter.text(), rst_txt_target.text())
        w_rst.close()
        rst.start()

    rst_btn_att.clicked.connect(on_click)

    # Show the window and run the app
    w.show()
    app.exec_()
