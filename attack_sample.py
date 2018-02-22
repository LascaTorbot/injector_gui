''' 
Sample attack
You should add your class to injector_gui.py, just as made with others 
pre-installed, like rst = Module_RST(). Check for all occurrencies of rst
to check how it works. Check TextBox class on injector_lib.py to check
the methods to manipulate it.

'''

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
