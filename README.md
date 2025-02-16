# DisableSecurity - Công cụ Tắt Bảo Mật Windows

[![Version](https://img.shields.io/badge/version-1.5-blue.svg)](https://github.com/yourusername/yourrepository)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](https://github.com/yourusername/yourrepository/blob/main/LICENSE)
<!-- Thay thế yourusername và yourrepository bằng thông tin của bạn -->

## Giới thiệu

[Screenshot 2025-02-17 061613.png]

**DisableSecurity** là một công cụ mạnh mẽ, được phát triển bằng Python và PyQt5, cho phép bạn vô hiệu hóa nhiều tính năng bảo mật cốt lõi của Windows.  Công cụ này được thiết kế dành cho các nhà nghiên cứu bảo mật, quản trị viên hệ thống và những người dùng có kinh nghiệm, cần kiểm soát sâu hơn đối với các cài đặt bảo mật trên hệ thống của họ (trong môi trường thử nghiệm).

**Cảnh báo:** Việc sử dụng công cụ này có thể làm giảm đáng kể tính bảo mật của hệ thống, khiến hệ thống dễ bị tấn công bởi phần mềm độc hại và các mối đe dọa khác.  **Chỉ sử dụng công cụ này trong môi trường được kiểm soát (ví dụ: máy ảo), nơi bạn hiểu rõ và chấp nhận các rủi ro liên quan.**  Không sử dụng trên hệ thống chính hoặc hệ thống chứa dữ liệu nhạy cảm.

## Tính năng chính

*   **Vô hiệu hóa Windows Security:**
    *   Tắt Windows Defender (Antivirus và AntiSpyware).
    *   Tắt Tường lửa Windows (Windows Firewall).

*   **Vô hiệu hóa Phần mềm Chống Virus của Bên Thứ Ba:**  Cố gắng tắt các tiến trình và dịch vụ liên quan đến các phần mềm chống virus phổ biến (Kaspersky, ESET, Avast, AVG, Bitdefender, McAfee).

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
    *   Cố gắng vô hiệu hóa Chống Giả mạo (Tamper Protection) - có thể yêu cầu khởi động lại.
    *   Cố gắng vô hiệu hóa Ghi nhật ký Sự kiện Windows (Windows Event Logging) - một hành động rất mạnh mẽ.

*   **Sao lưu và Khôi phục Registry:**
    *   Sao lưu các khóa registry bị ảnh hưởng *trước khi* thực hiện thay đổi.
    *   Khôi phục registry từ bản sao lưu gần nhất.
    *   Chỉ sao lưu những key registry bị thay đổi, không sao lưu toàn bộ, tối ưu dung lượng.

*   **Giao diện Người dùng Trực quan:**
    *   Giao diện đồ họa (GUI) thân thiện, dễ sử dụng.
    *   Chế độ tối (dark mode) dễ nhìn.
    *   Hỗ trợ đa ngôn ngữ (Tiếng Anh và Tiếng Việt).
    *   Hiển thị trạng thái thời gian thực của các tính năng bảo mật (đang hoạt động/không hoạt động/không rõ).
    *   Nhật ký (log) chi tiết các hành động.
    *   Cửa sổ tùy chỉnh (không có thanh tiêu đề Windows mặc định).
    *   Âm thanh thông báo (sử dụng âm thanh hệ thống Windows).

*   **Kỹ thuật Che giấu (Obfuscation):**
    *   Mã hóa chuỗi (string encoding) để ẩn các lệnh và đường dẫn registry nhạy cảm.
    *   Thực thi lệnh động (dynamic command execution) để tránh bị phát hiện bởi các công cụ phân tích tĩnh.
    *   Đổi tên hàm (function renaming) cơ bản.

## Yêu cầu

*   **Hệ điều hành:** Windows 10 hoặc Windows 11 (64-bit).  Các phiên bản Windows cũ hơn *có thể* hoạt động, nhưng chưa được kiểm tra.
*   **Python:** Python 3.7 trở lên.
*   **Thư viện:**
    *   `PyQt5`: `pip install PyQt5`
    *   `qdarkstyle`: `pip install qdarkstyle`
    *   `psutil`: `pip install psutil`
    *   `winsound`: Thư viện chuẩn của Python (không cần cài đặt).
    *   `ctypes`: Thư viện chuẩn của Python (không cần cài đặt).
    *   `base64`: Thư viện chuẩn của Python (không cần cài đặt).

*   **Quyền Quản trị viên (Administrator):** Chương trình *bắt buộc* phải được chạy với quyền quản trị viên.

## Hướng dẫn Cài đặt

1.  **Tải về:** Tải mã nguồn của chương trình từ kho lưu trữ GitHub.
2.  **Cài đặt Python:** Đảm bảo bạn đã cài đặt Python 3.7 trở lên.
3.  **Cài đặt Thư viện:** Mở Command Prompt hoặc PowerShell (với quyền Administrator) và chạy các lệnh sau:

    ```bash
    pip install PyQt5 qdarkstyle psutil
    ```
4. **Chạy chương trình**
    ```bash
    python DisableSecurity.py
    ```

## Hướng dẫn Sử dụng

1.  **Chạy với Quyền Quản trị viên:** Nhấp chuột phải vào tệp `DisableSecurity.py` và chọn "Run as administrator".
2.  **Giao diện Chính:**
    *   **Bảng điều khiển bên trái:** Chứa các nút để thực hiện các hành động (sao lưu, khôi phục, vô hiệu hóa).
    *   **Bảng điều khiển bên phải:**
        *   **Trạng thái:** Hiển thị trạng thái hiện tại của các tính năng bảo mật Windows (màu xanh lá cây = đang hoạt động, màu đỏ = không hoạt động, màu xám = không rõ).
        *   **Nhật ký:** Hiển thị các thông báo về hoạt động của chương trình.
    *   **Nút Ngôn ngữ:** Chuyển đổi giữa tiếng Anh và tiếng Việt.
    *   **Nút Thông tin:** Hiển thị thông tin về tác giả, phiên bản và mô tả chương trình.
    *   **Nút Thu nhỏ/Đóng:** Các nút tùy chỉnh để thu nhỏ hoặc đóng cửa sổ chương trình.

3.  **Các Hành động:**
    *   **Sao Lưu Registry:** Tạo bản sao lưu các khóa registry sẽ bị thay đổi *trước khi* thực hiện bất kỳ hành động vô hiệu hóa nào.
    *   **Khôi Phục Registry:** Khôi phục registry từ bản sao lưu gần nhất.
    *   **Vô Hiệu Hóa ...:** Các nút để vô hiệu hóa từng tính năng bảo mật riêng lẻ.
    *   **Vô Hiệu Hóa Tất Cả:** Vô hiệu hóa *tất cả* các tính năng bảo mật (cần xác nhận).  **Sử dụng cực kỳ thận trọng!**

## Lưu ý Quan trọng

*   **Rủi ro:** Việc vô hiệu hóa các tính năng bảo mật của Windows có thể gây ra những hậu quả nghiêm trọng.  Hãy chắc chắn rằng bạn hiểu rõ những gì mình đang làm.
*   **Môi trường Thử nghiệm:** Luôn thử nghiệm công cụ này trong môi trường biệt lập (ví dụ: máy ảo) trước khi sử dụng trên bất kỳ hệ thống quan trọng nào.
*   **Khả năng Phát hiện:** Các kỹ thuật che giấu được sử dụng trong chương trình này *không* đảm bảo khả năng ẩn mình hoàn toàn trước các phần mềm bảo mật tiên tiến.
*   **Trách nhiệm:** Tác giả của công cụ này không chịu trách nhiệm cho bất kỳ thiệt hại nào gây ra do việc sử dụng công cụ này.
*   **Mã nguồn mở:** Mã nguồn của chương trình được cung cấp công khai để bạn có thể tự kiểm tra và đánh giá.

## Đóng góp

Nếu bạn muốn đóng góp cho dự án, bạn có thể tạo một pull request trên GitHub.  Mọi đóng góp đều được hoan nghênh!

## Giấy phép

Công cụ này được phát hành theo giấy phép MIT.  Xem tệp `LICENSE` để biết thêm chi tiết.

## Tác giả

Namtran5905

---

**Disclaimer (Miễn trừ trách nhiệm):** This tool is provided "as is" without warranty of any kind.  Use it at your own risk. The author is not responsible for any damage caused by the use of this tool.  This tool should only be used for legitimate research, testing, or educational purposes in controlled environments.
