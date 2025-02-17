# DisableSecurity - Công cụ Tắt Bảo Mật Windows

[![Version](https://img.shields.io/badge/version-1.5-blue.svg)](https://github.com/yourusername/yourrepository)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](https://github.com/yourusername/yourrepository/blob/main/LICENSE)
<!-- Thay thế yourusername và yourrepository bằng thông tin của bạn -->
<img src="https://github.com/Namtran592005/DisableSecurity/blob/main/Screenshot%202025-02-17%20061613.png" width=50% height=50%>

## Giới thiệu

**DisableSecurity** là một công cụ mạnh mẽ, được phát triển bằng Python và PyQt5, cho phép bạn vô hiệu hóa nhiều tính năng bảo mật cốt lõi của Windows.  Công cụ này được thiết kế dành cho các nhà nghiên cứu bảo mật, quản trị viên hệ thống và những người dùng có kinh nghiệm, cần kiểm soát sâu hơn đối với các cài đặt bảo mật trên hệ thống của họ (trong môi trường thử nghiệm).

**Cảnh báo:** Việc sử dụng công cụ này có thể làm giảm đáng kể tính bảo mật của hệ thống, khiến hệ thống dễ bị tấn công bởi phần mềm độc hại và các mối đe dọa khác.  **Chỉ sử dụng công cụ này trong môi trường được kiểm soát (ví dụ: máy ảo), nơi bạn hiểu rõ và chấp nhận các rủi ro liên quan.**  Không sử dụng trên hệ thống chính hoặc hệ thống chứa dữ liệu nhạy cảm.

## Tính năng chính

*   **Vô hiệu hóa Windows Security:**
    *   Tắt Windows Defender (Antivirus và AntiSpyware).
    *   Tắt Tường lửa Windows (Windows Firewall).

*   **Vô hiệu hóa Phần mềm Chống Virus của Bên Thứ Ba:**  Cố gắng tắt các tiến trình và dịch vụ liên quan đến các phần mềm chống virus phổ biến (Kaspersky, ESET, Avast, AVG, Bitdefender, McAfee). (thử nghiệm)

*   **Ngăn Dịch vụ Bảo mật Khởi động lại:** Vô hiệu hóa các dịch vụ Windows liên quan đến bảo mật (WinDefend, SecurityHealthService, wscsvc, MpsSvc) để ngăn chúng tự động khởi động lại.

*   **Vô hiệu hóa các Tính năng Bảo mật Windows:**
    *   Tắt Kiểm soát Tài khoản Người dùng (UAC).
    *   Vô hiệu hóa quyền truy cập Windows Update.
    *   Vô hiệu hóa SmartScreen.
    *   Vô hiệu hóa Ngăn Chặn Thực thi Dữ liệu (DEP).
    *   Vô hiệu hóa Bảo vệ Luồng Điều khiển (CFG).
    *   Vô hiệu hóa Truy cập Thư mục Được Kiểm soát.
    *   Vô hiệu hóa Bảo vệ Mạng.
    *   Vô hiệu hóa các quy tắc Giảm Bề mặt Tấn công (ASR).
    *   vô hiệu hóa Chống Giả mạo (Tamper Protection)
    *   vô hiệu hóa Ghi nhật ký Sự kiện Windows (Windows Event Logging)

*   **Sao lưu và Khôi phục Registry:**
    *   Sao lưu toàn bộ các khóa registry bị ảnh hưởng *trước khi* thực hiện thay đổi.
    *   Khôi phục registry từ bản sao lưu gần nhất.

*   **Giao diện Người dùng Trực quan:**
    *   Giao diện đồ họa (GUI) thân thiện, dễ sử dụng.
    *   Chế độ tối (dark mode) dễ nhìn.
    *   Htoàn
<img src="https://github.com/Namtran592005/DisableSecurity/blob/main/%E1%BA%A2nh%20ch%E1%BB%A5p%20m%C3%A0n%20h%C3%ACnh_17-2-2025_61248_www.virustotal.com.jpeg" width=50% height=50%>
------------------
<img src="https://github.com/Namtran592005/DisableSecurity/blob/main/%E1%BA%A2nh%20ch%E1%BB%A5p%20m%C3%A0n%20h%C3%ACnh_17-2-2025_61312_www.virustotal.com.jpeg" width=50% height=50%>

