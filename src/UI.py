import sys
from typing import List
from PyQt5.QtWidgets import QBoxLayout, QGroupBox, QMainWindow, QLineEdit, QPlainTextEdit, QPushButton, QToolBox, QVBoxLayout, QApplication
from PyQt5.QtCore import Qt

from DSA2 import create_random_keys, verify_str, sign_str

WIDTH = 500
HEIGHT = 500

TITLE = "DSA Demo"


class Window(QMainWindow):
    def __init__(self):
        super(Window, self).__init__()
        self.private_key = None
        self.public_key = None
        self.p = None
        self.q = None
        self.g = None
        self.initUI()

    def initUI(self):
        self.setWindowTitle(TITLE)
        self.setGeometry(0, 0, WIDTH, HEIGHT)
        self.main_box = QGroupBox(self)
        main_layout = QVBoxLayout(self.main_box)
        self.main_layout = main_layout
        self.create_text_boxes()
        self.create_buttons()
        self.main_layout.addWidget(self.text_boxes, stretch=1)
        self.main_layout.addWidget(self.action_box, stretch=0)
        self.main_box.setLayout(self.main_layout)
        self.add_listener()
        self.show_all()

    def show_all(self):
        self.main_box.setMinimumSize(WIDTH, HEIGHT)
        self.main_box.adjustSize()
        self.main_box.show()
        self.show()

    def create_buttons(self):
        self.action_box = QGroupBox(self)
        create_keys_btn = QPushButton(self)
        create_keys_btn.setText('Create my keys')
        create_keys_btn.adjustSize()
        self.create_keys_btn = create_keys_btn

        gen_token_btn = QPushButton(self)
        gen_token_btn.setText('Generate my Token/DSA')
        gen_token_btn.adjustSize()
        self.gen_token_btn = gen_token_btn
        layout = QVBoxLayout()
        layout.addWidget(
            create_keys_btn)
        layout.addWidget(gen_token_btn)
        self.action_box.setLayout(layout)

    def create_text_boxes(self):
        self.text_boxes = QGroupBox(self)
        message_box = QPlainTextEdit(self)
        message_box.setPlaceholderText("Enter your message")
        message_box.adjustSize()
        self.message_box = message_box

        public_key_box = QLineEdit(self)
        public_key_box.setPlaceholderText("Your public key")
        public_key_box.adjustSize()
        self.public_key_box = public_key_box

        dsa_box = QLineEdit(self)
        dsa_box.setPlaceholderText("Your DSA from your message")
        dsa_box.adjustSize()
        self.dsa_box = dsa_box

        layout = QVBoxLayout()
        layout.addWidget(message_box)
        layout.addWidget(public_key_box)
        layout.addWidget(dsa_box)
        layout.setAlignment(Qt.AlignmentFlag.AlignRight)
        self.text_boxes.setLayout(layout)

    def on_create_keys_clicked(self):
        print("CLICKED")
        p, q, g, x, y = create_random_keys()
        self.private_key = x
        self.public_key = y
        self.p = p
        self.q = q
        self.g = g
        self.public_key_box.setText(str(y))

    def on_gen_dsa_clicked(self):
        message = self.message_box.toPlainText()
        x = self.private_key
        if x is None:
            return
        if not message:
            return
        (r, s) = sign_str(message, self.p, self.q, self.g, x)
        self.dsa_box.setText(str(r) + '/' + str(s))
        print(r, s)

    def add_listener(self):
        self.create_keys_btn.clicked.connect(self.on_create_keys_clicked)
        self.gen_token_btn.clicked.connect(self.on_gen_dsa_clicked)


def start():
    app = QApplication(sys.argv)

    win = Window()

    sys.exit(app.exec_())


start()
