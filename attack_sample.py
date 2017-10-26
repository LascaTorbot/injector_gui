### RST Attack made to Ares botnet from experiments ###

class Attack():
    def __init__(self):
        self.log_textBox = None
        self.original_textBox = None
        self.new_textBox = None

    def setTextBox(self, log_textBox, original_textBox, new_textBox):
        self.log_textBox = log_textBox
        self.original_textBox = original_textBox
        self.new_textBox = new_textBox

    def attack(self):
        pass
        # Your attack script should be write here. Use the text boxes to interact
        # with the user interface
