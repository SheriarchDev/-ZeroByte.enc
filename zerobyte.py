import os
import sys
import winreg
from PyQt6.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QFileDialog, QMessageBox
from PyQt6.QtCore import Qt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

STYLE = """
    QWidget { background-color: #0F1218; color: #F0F0F0; font-family: 'Segoe UI'; font-size: 13px; }
    QLineEdit { background-color: #171C24; border: 1px solid #2A313E; border-radius: 6px; padding: 5px; color: white; }
    QPushButton { background-color: #242933; border: 1px solid #2A313E; border-radius: 6px; color: #00BFFF; padding: 7px; font-weight: bold; }
    QPushButton:hover { background-color: #2F3644; }
"""

def manager_registry(remove=False):
    path = r"Software\Classes\*\shell\ZeroByte"
    if remove:
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path + r"\command")
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path)
        except FileNotFoundError:
            pass
    else:
        exe = os.path.abspath(sys.argv[0])
        cmd = f'"{sys.executable}" "{exe}" "%1"' if exe.endswith(".py") else f'"{exe}" "%1"'
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, path) as k:
            winreg.SetValue(k, "", winreg.REG_SZ, "Открыть в ZeroByte")
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, path + r"\command") as k:
            winreg.SetValue(k, "", winreg.REG_SZ, cmd)

class ZeroByteApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.filepath = None
        self.setWindowTitle("ZeroByte.enc")
        self.setFixedSize(450, 400)
        self.setAcceptDrops(True)
        self.setStyleSheet(STYLE)

        main = QWidget()
        self.setCentralWidget(main)
        layout = QVBoxLayout(main)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(10)

        title = QLabel("ZeroByte")
        title.setStyleSheet("font-size: 22px; font-weight: bold; color: #00BFFF;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        self.lbl = QLabel("Перетащите файл сюда или откройте через проводник")
        self.lbl.setStyleSheet("border: 2px dashed #242933; border-radius: 8px; padding: 20px; color: #8A99AD;")
        self.lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl.setWordWrap(True)
        layout.addWidget(self.lbl)

        layout.addWidget(QLabel("Мастер-пароль:"))
        self.pass_in = QLineEdit()
        self.pass_in.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.pass_in)

        self.btn_open = QPushButton("Открыть проводник")
        self.btn_open.clicked.connect(self.get_file)
        layout.addWidget(self.btn_open)

        btns = QHBoxLayout()
        self.btn_enc = QPushButton("Зашифровать")
        self.btn_enc.setStyleSheet("background-color: #C63535; color: white;")
        self.btn_enc.clicked.connect(lambda: self.process(True))
        self.btn_dec = QPushButton("Расшифровать")
        self.btn_dec.setStyleSheet("background-color: #28874E; color: white;")
        self.btn_dec.clicked.connect(lambda: self.process(False))
        btns.addWidget(self.btn_enc)
        btns.addWidget(self.btn_dec)
        layout.addLayout(btns)

        reg_box = QHBoxLayout()
        self.r_on = QPushButton("Включить ПКМ")
        self.r_on.clicked.connect(lambda: manager_registry(False))
        self.r_off = QPushButton("Выключить ПКМ")
        self.r_off.clicked.connect(lambda: manager_registry(True))
        reg_box.addWidget(self.r_on)
        reg_box.addWidget(self.r_off)
        layout.addLayout(reg_box)

        self.foot = QLabel("© 2026 Sheriarch • Licensed under GNU GPLv3")
        self.foot.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.foot)

        if len(sys.argv) > 1:
            arg_path = sys.argv[1]
            if os.path.isfile(arg_path):
                self.lock_file(arg_path)

    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()

    def dropEvent(self, e):
        urls = e.mimeData().urls()
        if urls:
            path = urls[0].toLocalFile()
            if os.path.isfile(path):
                self.lock_file(path)

    def get_file(self):
        p, _ = QFileDialog.getOpenFileName(self, "Выбрать файл", "", "All Files (*)")
        if p:
            self.lock_file(p)

    def lock_file(self, p):
        self.filepath = p
        self.lbl.setText(f"Выбран файл:\n{os.path.basename(p)}")
        self.lbl.setStyleSheet("border: 2px solid #00BFFF; border-radius: 8px; padding: 20px; background: #171C24;")

    def popup(self, t, txt, err=False):
        b = QMessageBox(self)
        b.setWindowTitle(t)
        b.setText(txt)
        b.setIcon(QMessageBox.Icon.Warning if err else QMessageBox.Icon.Information)
        b.exec()

    def zero(self, t):
        if isinstance(t, (bytearray, memoryview)):
            for i in range(len(t)):
                t[i] = 0

    def make_key(self, p_bytes, salt):
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
        return bytearray(kdf.derive(bytes(p_bytes)))

    def shred(self, p):
        if os.path.exists(p):
            sz = os.path.getsize(p)
            with open(p, "ba+", buffering=0) as f:
                f.seek(0)
                f.write(os.urandom(sz))
            os.remove(p)

    def process(self, enc=True):
        p_str = self.pass_in.text()
        if not p_str or not self.filepath:
            self.popup("Внимание", "Заполните поля!", True)
            return

        p_bytes = bytearray(p_str.encode())
        self.pass_in.clear()
        old_p = self.filepath
        
        if enc:
            if old_p.endswith(".zrb"):
                self.zero(p_bytes)
                self.popup("Внимание", "Файл уже зашифрован!", True)
                return
            final_p = old_p + ".zrb"
        else:
            if not old_p.endswith(".zrb"):
                self.zero(p_bytes)
                self.popup("Внимание", "Файл не имеет расширения .zrb!", True)
                return
            final_p = old_p[:-4]

        tmp = final_p + ".tmp"
        buf_size = 64 * 1024

        try:
            if enc:
                salt, iv = os.urandom(16), os.urandom(12)
                key = self.make_key(p_bytes, salt)
                aes = Cipher(algorithms.AES(bytes(key)), modes.GCM(iv)).encryptor()
                with open(old_p, "rb") as f_in, open(tmp, "w+b") as f_out:
                    f_out.write(salt + iv + b"\x00" * 16)
                    buf = bytearray(buf_size)
                    while True:
                        r = f_in.readinto(buf)
                        if not r:
                            break
                        view = memoryview(buf)[:r]
                        f_out.write(aes.update(bytes(view)))
                        self.zero(view)
                    f_out.write(aes.finalize())
                    f_out.seek(28)
                    f_out.write(aes.tag)
            else:
                with open(old_p, "rb") as f_in:
                    salt, iv, tag = f_in.read(16), f_in.read(12), f_in.read(16)
                    key = self.make_key(p_bytes, salt)
                    aes = Cipher(algorithms.AES(bytes(key)), modes.GCM(iv, tag)).decryptor()
                    with open(tmp, "wb") as f_out:
                        buf = bytearray(buf_size)
                        while True:
                            r = f_in.readinto(buf)
                            if not r:
                                break
                            view = memoryview(buf)[:r]
                            f_out.write(aes.update(bytes(view)))
                            self.zero(view)
                        f_out.write(aes.finalize())

            self.zero(key)
            self.zero(p_bytes)
            os.replace(tmp, final_p)
            self.shred(old_p) if enc else os.remove(old_p)
            self.filepath = None
            self.lbl.setText("Перетащите файл сюда")
            self.lbl.setStyleSheet("border: 2px dashed #242933; border-radius: 8px; padding: 20px; color: #8A99AD;")
            self.popup("Успешно", "Готово!")
        except Exception:
            self.zero(p_bytes)
            if 'key' in locals():
                self.zero(key)
            if os.path.exists(tmp):
                os.remove(tmp)
            self.popup("Ошибка", "Сбой операции.", True)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ZeroByteApp()
    window.show()
    sys.exit(app.exec())
