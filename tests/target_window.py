"""A stand-in login form for type_test.py.

    python target_window.py "<title>" <boxes> <result file>

<boxes> is a number of text boxes, or a pattern of them: "tp" is a text box
then a password box. Enter in any box writes what they all hold to the result
file and closes. First it writes <result file>.ready: its process id and the
middle of each box in physical screen pixels. It gives up after a minute.
"""

import json
import os
import sys
from pathlib import Path

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import QApplication, QLineEdit, QVBoxLayout, QWidget


def main() -> None:
    title, pattern, out = sys.argv[1], sys.argv[2], Path(sys.argv[3])
    if pattern.isdigit():
        pattern = 't' * int(pattern)
    app = QApplication(sys.argv[:1])
    window = QWidget(None, Qt.WindowStaysOnTopHint)
    window.setWindowTitle(title)
    layout = QVBoxLayout(window)
    layout.setContentsMargins(0, 0, 0, 0)
    boxes = []
    for kind in pattern:
        box = QLineEdit()
        if kind == 'p':
            box.setEchoMode(QLineEdit.Password)
        boxes.append(box)

    def submit() -> None:
        out.write_text(json.dumps([box.text() for box in boxes], ensure_ascii=False), encoding='utf-8')
        app.quit()

    for box in boxes:
        box.setMinimumHeight(40)
        box.returnPressed.connect(submit)
        layout.addWidget(box)
    window.resize(460, 46 * len(boxes))
    area = app.primaryScreen().availableGeometry()
    window.move(area.center().x() - 230, area.top() + area.height() // 4)
    window.show()
    boxes[0].setFocus()

    def ready() -> None:
        screen = window.screen()
        origin, ratio = screen.geometry().topLeft(), screen.devicePixelRatio()
        centers = []
        for box in boxes:
            point = box.mapToGlobal(box.rect().center())
            centers.append([origin.x() + round((point.x() - origin.x()) * ratio),
                            origin.y() + round((point.y() - origin.y()) * ratio)])
        Path(str(out) + '.ready').write_text(json.dumps({'pid': os.getpid(), 'hwnd': int(window.winId()),
                                                         'boxes': centers}))
    QTimer.singleShot(200, ready)
    QTimer.singleShot(60_000, app.quit)
    app.exec()


if __name__ == '__main__':
    main()
