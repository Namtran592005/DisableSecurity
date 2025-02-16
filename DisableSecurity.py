import sys
import subprocess
import os
import logging
import datetime
import psutil
import ctypes
from PyQt5.QtWidgets import QApplication, QMainWindow, QMessageBox, QVBoxLayout, QPushButton, QWidget, QLabel, QTextEdit, QDialog, QHBoxLayout
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QIcon

# Cấu hình logging
def setup_logging():
    logging.basicConfig(
        filename="system_tool.log",
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )

# Kiểm tra quyền admin
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

# Sao lưu registry
def backup_registry():
    backup_dir = "backup"
    if not os.path.exists(backup_dir):
        os.makedirs(backup_dir)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = os.path.join(backup_dir, f"registry_backup_{timestamp}.reg")
    try:
        subprocess.run(["reg", "export", "HKLM\\SOFTWARE", backup_file], check=True, creationflags=subprocess.CREATE_NO_WINDOW)
        logging.info(f"Đã sao lưu registry vào {backup_file}")
        return True, backup_file
    except subprocess.CalledProcessError as e:
        logging.error(f"Lỗi khi sao lưu registry: {e}")
        return False, str(e)

# Khôi phục registry
def restore_registry(backup_file):
    try:
        subprocess.run(["reg", "import", backup_file], check=True, creationflags=subprocess.CREATE_NO_WINDOW)
        logging.info(f"Đã khôi phục registry từ {backup_file}")
        return True
    except subprocess.CalledProcessError as e:
        logging.error(f"Lỗi khi khôi phục registry: {e}")
        return False

# Vô hiệu hóa Windows Security và Defender
def disable_windows_security():
    try:
        subprocess.run(
            [
                "reg", "add", "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender",
                "/v", "DisableAntiSpyware", "/t", "REG_DWORD", "/d", "1", "/f"
            ], check=True, creationflags=subprocess.CREATE_NO_WINDOW
        )
        subprocess.run(
            [
                "reg", "add", "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender",
                "/v", "DisableAntiVirus", "/t", "REG_DWORD", "/d", "1", "/f"
            ], check=True, creationflags=subprocess.CREATE_NO_WINDOW
        )
        subprocess.run(
            [
                "reg", "add", "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
                "/v", "DisableIOAVProtection", "/t", "REG_DWORD", "/d", "1", "/f"
            ], check=True, creationflags=subprocess.CREATE_NO_WINDOW
        )
        subprocess.run(["netsh", "advfirewall", "set", "allprofiles", "state", "off"], check=True, creationflags=subprocess.CREATE_NO_WINDOW)
        logging.info("Đã vô hiệu hóa Windows Security và Defender.")
        return True
    except subprocess.CalledProcessError as e:
        logging.error(f"Lỗi khi vô hiệu hóa Windows Security: {e}")
        return False

# Vô hiệu hóa phần mềm chống virus của bên thứ ba
def disable_third_party_antivirus():
    antivirus_software = ["kaspersky", "eset", "avast", "avg", "bitdefender"]
    for software in antivirus_software:
        try:
            for proc in psutil.process_iter():
                if software.lower() in proc.name().lower():
                    proc.kill()
                    logging.info(f"Đã dừng tiến trình {proc.name()}")
            subprocess.run(["sc", "config", software, "start=disabled"], check=True, creationflags=subprocess.CREATE_NO_WINDOW)
            subprocess.run(["reg", "delete", f"HKLM\\SOFTWARE\\{software}", "/f"], check=True, creationflags=subprocess.CREATE_NO_WINDOW)
            logging.info(f"Đã vô hiệu hóa {software}.")
        except Exception as e:
            logging.error(f"Lỗi khi xử lý {software}: {e}")

# Ngăn chặn khởi động dịch vụ bảo mật
def prevent_security_service_restart():
    security_services = ["windefend", "securityhealthservice", "wscsvc", "mpssvc"]
    for service in security_services:
        try:
            subprocess.run(["sc", "config", service, "start=disabled"], check=True, creationflags=subprocess.CREATE_NO_WINDOW)
            logging.info(f"Đã vô hiệu hóa dịch vụ {service}.")
        except subprocess.CalledProcessError as e:
            logging.error(f"Lỗi khi vô hiệu hóa dịch vụ {service}: {e}")

# Vô hiệu hóa các tính năng bảo mật khác của Windows
def disable_windows_features():
    try:
        subprocess.run(
            [
                "reg", "add", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                "/v", "EnableLUA", "/t", "REG_DWORD", "/d", "0", "/f"
            ], check=True, creationflags=subprocess.CREATE_NO_WINDOW
        )
        subprocess.run(
            [
                "reg", "add", "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate",
                "/v", "DisableWindowsUpdateAccess", "/t", "REG_DWORD", "/d", "1", "/f"
            ], check=True, creationflags=subprocess.CREATE_NO_WINDOW
        )
        subprocess.run(
            [
                "reg", "add", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments",
                "/v", "SaveZoneInformation", "/t", "REG_DWORD", "/d", "1", "/f"
            ], check=True, creationflags=subprocess.CREATE_NO_WINDOW
        )
        logging.info("Đã vô hiệu hóa các tính năng bảo mật khác của Windows.")
        return True
    except subprocess.CalledProcessError as e:
        logging.error(f"Lỗi khi vô hiệu hóa các tính năng bảo mật: {e}")
        return False

# Custom MessageBox
class CustomMessageBox(QDialog):
    def __init__(self, title, message, icon, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setWindowIcon(QIcon("icon.ico"))
        self.setGeometry(200, 200, 300, 150)
        self.setStyleSheet("background-color: #f0f0f0;")

        layout = QVBoxLayout()
        self.label = QLabel(message)
        self.label.setFont(QFont("Arial", 10))
        layout.addWidget(self.label)

        button_layout = QHBoxLayout()
        self.ok_button = QPushButton("OK")
        self.ok_button.clicked.connect(self.accept)
        button_layout.addWidget(self.ok_button)

        layout.addLayout(button_layout)
        self.setLayout(layout)

# Giao diện chính
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("System Security Tool")
        self.setGeometry(100, 100, 600, 400)
        self.setWindowIcon(QIcon("icon.ico"))
        self.setStyleSheet("background-color: #ffffff;")
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()

        self.label = QLabel("Chọn chức năng để vô hiệu hóa bảo mật:")
        self.label.setFont(QFont("Arial", 12))
        layout.addWidget(self.label)

        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        layout.addWidget(self.log_text)

        buttons = [
            ("Sao lưu Registry", self.backup_registry),
            ("Khôi phục Registry", self.restore_registry),
            ("Vô hiệu hóa Windows Security", self.disable_security),
            ("Vô hiệu hóa Phần mềm Chống Virus", self.disable_antivirus),
            ("Ngăn chặn Dịch vụ Bảo mật", self.prevent_services),
            ("Vô hiệu hóa Tính năng Bảo mật Khác", self.disable_features),
            ("Vô hiệu hóa Tất cả", self.disable_all),
            ("Thoát", self.close),
        ]

        for text, callback in buttons:
            button = QPushButton(text)
            button.setStyleSheet("background-color: #0078d7; color: white; padding: 10px;")
            button.clicked.connect(callback)
            layout.addWidget(button)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

    def backup_registry(self):
        success, message = backup_registry()
        if success:
            self.log_text.append("Sao lưu registry thành công!")
            QMessageBox.information(self, "Thành công", "Sao lưu registry thành công!")
        else:
            self.log_text.append(f"Lỗi khi sao lưu registry: {message}")
            QMessageBox.critical(self, "Lỗi", f"Lỗi khi sao lưu registry: {message}")

    def restore_registry(self):
        backup_file = "backup/registry_backup_latest.reg"
        if os.path.exists(backup_file):
            success = restore_registry(backup_file)
            if success:
                self.log_text.append("Khôi phục registry thành công!")
                QMessageBox.information(self, "Thành công", "Khôi phục registry thành công!")
            else:
                self.log_text.append("Lỗi khi khôi phục registry!")
                QMessageBox.critical(self, "Lỗi", "Lỗi khi khôi phục registry!")
        else:
            self.log_text.append("Không tìm thấy file sao lưu!")
            QMessageBox.warning(self, "Cảnh báo", "Không tìm thấy file sao lưu!")

    def disable_security(self):
        if is_admin():
            success = disable_windows_security()
            if success:
                self.log_text.append("Đã vô hiệu hóa Windows Security và Defender!")
                QMessageBox.information(self, "Thành công", "Đã vô hiệu hóa Windows Security và Defender!")
            else:
                self.log_text.append("Lỗi khi vô hiệu hóa Windows Security!")
                QMessageBox.critical(self, "Lỗi", "Lỗi khi vô hiệu hóa Windows Security!")
        else:
            self.log_text.append("Vui lòng chạy chương trình với quyền Administrator!")
            CustomMessageBox("Lỗi", "Vui lòng chạy chương trình với quyền Administrator!", QMessageBox.Critical).exec_()

    def disable_antivirus(self):
        if is_admin():
            disable_third_party_antivirus()
            self.log_text.append("Đã vô hiệu hóa phần mềm chống virus của bên thứ ba!")
            QMessageBox.information(self, "Thành công", "Đã vô hiệu hóa phần mềm chống virus của bên thứ ba!")
        else:
            self.log_text.append("Vui lòng chạy chương trình với quyền Administrator!")
            CustomMessageBox("Lỗi", "Vui lòng chạy chương trình với quyền Administrator!", QMessageBox.Critical).exec_()

    def prevent_services(self):
        if is_admin():
            prevent_security_service_restart()
            self.log_text.append("Đã ngăn chặn khởi động dịch vụ bảo mật!")
            QMessageBox.information(self, "Thành công", "Đã ngăn chặn khởi động dịch vụ bảo mật!")
        else:
            self.log_text.append("Vui lòng chạy chương trình với quyền Administrator!")
            CustomMessageBox("Lỗi", "Vui lòng chạy chương trình với quyền Administrator!", QMessageBox.Critical).exec_()

    def disable_features(self):
        if is_admin():
            success = disable_windows_features()
            if success:
                self.log_text.append("Đã vô hiệu hóa các tính năng bảo mật khác của Windows!")
                QMessageBox.information(self, "Thành công", "Đã vô hiệu hóa các tính năng bảo mật khác của Windows!")
            else:
                self.log_text.append("Lỗi khi vô hiệu hóa các tính năng bảo mật!")
                QMessageBox.critical(self, "Lỗi", "Lỗi khi vô hiệu hóa các tính năng bảo mật!")
        else:
            self.log_text.append("Vui lòng chạy chương trình với qu yền Administrator!")
            CustomMessageBox("Lỗi", "Vui lòng chạy chương trình với quyền Administrator!", QMessageBox.Critical).exec_()

    def disable_all(self):
        if is_admin():
            # Xác nhận trước khi thực hiện
            confirm = QMessageBox.question(self, "Xác nhận", "Bạn có chắc chắn muốn vô hiệu hóa tất cả các tính năng bảo mật?", QMessageBox.Yes | QMessageBox.No)
            if confirm == QMessageBox.Yes:
                disable_windows_security()
                disable_third_party_antivirus()
                prevent_security_service_restart()
                disable_windows_features()
                self.log_text.append("Đã vô hiệu hóa tất cả các tính năng bảo mật!")
                QMessageBox.information(self, "Thành công", "Đã vô hiệu hóa tất cả các tính năng bảo mật!")
        else:
            self.log_text.append("Vui lòng chạy chương trình với quyền Administrator!")
            CustomMessageBox("Lỗi", "Vui lòng chạy chương trình với quyền Administrator!", QMessageBox.Critical).exec_()

# Chạy chương trình
if __name__ == "__main__":
    setup_logging()
    if not is_admin():
        logging.error("Chương trình cần được chạy với quyền Administrator.")
        CustomMessageBox("Lỗi", "Vui lòng chạy chương trình với quyền Administrator!", QMessageBox.Critical).exec_()
        sys.exit(1)

    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
