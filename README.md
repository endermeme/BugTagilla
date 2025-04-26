# SpyHunt - Công cụ đa năng cho Bug Bounty và đánh giá bảo mật

<div align="center">
  <img src="https://placeholder.co/800x200/3498db/ffffff?text=SpyHunt+Security+Framework" alt="SpyHunt Logo">
  <p><i>Nền tảng bảo mật toàn diện cho Bug Bounty và Penetration Testing</i></p>
</div>

## Tổng quan

SpyHunt là một công cụ bảo mật toàn diện được thiết kế để hỗ trợ các chuyên gia bảo mật, thợ săn lỗi và kỹ sư kiểm tra xâm nhập. SpyHunt kết hợp nhiều công cụ và kỹ thuật khác nhau vào một nền tảng thống nhất, tạo điều kiện thuận lợi cho việc phát hiện và khai thác các lỗ hổng bảo mật.

### Tính năng chính

- **Quét tự động toàn diện**: Quét đầy đủ các dịch vụ và giao thức
- **Phân tích AI thông minh**: Tối ưu hóa quá trình săn lỗi bằng AI
- **Các scanner chuyên biệt**: SMB, LDAP, Redis, FTP và nhiều dịch vụ khác
- **Web Application Testing**: Kiểm tra đầy đủ các lỗ hổng web phổ biến
- **Cloud Security Testing**: Phát hiện cấu hình sai và lỗ hổng trên các dịch vụ đám mây
- **Hệ thống Báo cáo**: Tạo báo cáo chuyên nghiệp với các khuyến nghị về cách khắc phục

## Cài đặt

```bash
# Clone repository
git clone https://github.com/yourusername/spyhunt.git
cd spyhunt

# Cài đặt các dependencies
pip install -r requirements.txt

# Kiểm tra cài đặt
python spyhunt.py --version
```

## Hướng dẫn sử dụng nhanh

SpyHunt có hai chế độ hoạt động chính:

### 1. Chế độ AutoRecon (quét tự động toàn diện)

```bash
# Quét tổng quát
python spyhunt.py --autorecon example.com --intensity medium

# Quét chuyên sâu với tất cả các module
python spyhunt.py --autorecon example.com --intensity aggressive --max-time 3600 --scan-profile full --save-autorecon results
```

### 2. Chế độ AI Bug Bounty (phân tích thông minh)

```bash
# Phân tích thông minh cho bug bounty
python spyhunt.py --ai-bug-bounty example.com --focus web_vulns

# Phân tích chuyên sâu với báo cáo chi tiết
python spyhunt.py --ai-bug-bounty example.com --focus api --max-threads 20 --output-report detailed
```

### 3. Các scanner chuyên biệt

```bash
# Kiểm tra lỗ hổng SMB
python spyhunt.py --smb-scan 192.168.1.1 --smb-port 445 --smb-brute

# Kiểm tra lỗ hổng Redis
python spyhunt.py --redis-scan 192.168.1.1 --redis-port 6379

# Kiểm tra lỗ hổng LDAP
python spyhunt.py --ldap-scan domain.com --ldap-port 389 --ldaps-port 636

# Kiểm tra lỗ hổng FTP
python spyhunt.py --ftp-scan example.com --ftp-port 21 --username-wordlist users.txt --password-wordlist passwords.txt
```

## Tài liệu

- [Scanners.md](Scanners.md) - Mô tả chi tiết về các scanner chuyên biệt
- [AI-Mode.md](AI-Mode.md) - Hướng dẫn về chế độ phân tích AI
- [Usage.md](Usage.md) - Hướng dẫn sử dụng chi tiết

## Cấu trúc dự án

```
spyhunt/
├── spyhunt.py           # Main script
├── requirements.txt     # Dependencies
├── modules/             # Các module chức năng
│   ├── scanners/        # Scanner chuyên biệt
│   │   ├── __init__.py
│   │   ├── smb_scanner.py
│   │   ├── ldap_scanner.py
│   │   ├── redis_scanner.py
│   │   └── ftp_scanner.py
│   ├── web/             # Web testing modules
│   ├── cloud/           # Cloud security modules
│   └── utils/           # Utility functions
├── wordlists/           # Wordlists cho brute force
└── results/             # Default directory for results
```

## Demo

### Quét tự động với SpyHunt

![SpyHunt Demo](https://placeholder.co/800x400/34495e/ffffff?text=SpyHunt+Demo)

### Phân tích AI

![AI Analysis](https://placeholder.co/800x400/2c3e50/ffffff?text=AI+Analysis+Demo)

## Đóng góp

Chúng tôi rất hoan nghênh các đóng góp! Vui lòng xem [CONTRIBUTING.md](CONTRIBUTING.md) để biết thêm chi tiết về cách đóng góp vào dự án.

## Lưu ý về bảo mật

SpyHunt là một công cụ mạnh mẽ được thiết kế cho các mục đích bảo mật chính đáng. Vui lòng sử dụng có trách nhiệm:

- Chỉ thực hiện quét và đánh giá trên các hệ thống mà bạn được phép
- Tuân thủ tất cả các luật và quy định áp dụng
- Không sử dụng công cụ này cho các hoạt động bất hợp pháp hoặc gây hại

## Giấy phép

Dự án này được phát hành theo giấy phép MIT. Xem file [LICENSE](LICENSE) để biết thêm chi tiết.
