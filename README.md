# injector_gui

injector_gui is a software similar to WireShark, where you can see the traffic of packets in your network.

### Dependencies:
- Python2/3
- Scapy
- PyQt4

### Using:
Run in the root user (`sudo` may not work):
```bash
python injector_gui.py
```
#### Custom attacks
You can add yours own custom attacks. Use the attack_sample.py file to write it. Your actions must be write on `attack` method and you can use the text boxes (log_textBox, original_textBox, new_textBox) to interact with the GUI.

#### Scripting
Also, you can write scripts to launch custom and quickly attacks. Click on "Run script" button and load your file. The syntax is like python `if`:
``` python
condition1 and condition2 or conditionN: expression1, expression2, expressionN
```
