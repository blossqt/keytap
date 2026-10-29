"""A Qt login box, shown without taking the keyboard.

    python qt_target.py <report file> <seconds> <x> <y>"""
import json
import sys

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import QApplication, QLabel, QLineEdit, QPushButton, QVBoxLayout, QWidget

app = QApplication([])
w = QWidget()
w.setWindowTitle('Qt login')
w.setAttribute(Qt.WA_ShowWithoutActivating)
lay = QVBoxLayout(w)
user, pw = QLineEdit(), QLineEdit()
pw.setEchoMode(QLineEdit.Password)
user.setAccessibleName('Email')
pw.setAccessibleName('Password')
state = {'s': ''}
button = QPushButton('Log in')
button.clicked.connect(lambda: state.update(s='submitted'))
for widget in (QLabel('Email'), user, QLabel('Password'), pw, button):
    lay.addWidget(widget)
w.move(int(sys.argv[3]), int(sys.argv[4]))
w.resize(320, 200)
w.show()
print(json.dumps({'hwnd': int(w.winId())}), flush=True)


def write():
    with open(sys.argv[1], 'w', encoding='utf-8') as f:
        f.write(json.dumps({'u': user.text(), 'p': pw.text(), 's': state['s']}))


t = QTimer()
t.timeout.connect(write)
t.start(100)
QTimer.singleShot(int(float(sys.argv[2]) * 1000), app.quit)
app.exec()
