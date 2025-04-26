# SpyHunt - Specialized Scanners

Tài liệu này mô tả chi tiết các scanner chuyên biệt đã được tích hợp vào SpyHunt và cách sử dụng chúng.

## Cấu trúc thư mục

```
modules/
  scanners/
    __init__.py      # Định nghĩa package
    smb_scanner.py   # Scanner kiểm tra lỗ hổng SMB
    ldap_scanner.py  # Scanner kiểm tra lỗ hổng LDAP
    redis_scanner.py # Scanner kiểm tra lỗ hổng Redis
    ftp_scanner.py   # Scanner kiểm tra lỗ hổng FTP
```

## 1. SMB Scanner

### Mô tả
Scanner chuyên dụng để kiểm tra các lỗ hổng và cấu hình sai trong giao thức SMB (Server Message Block), thường được sử dụng cho chia sẻ file trong mạng Windows.

### Tính năng chính
- Kiểm tra cổng SMB (mặc định 445)
- Phát hiện lỗ hổng EternalBlue (MS17-010)
- Kiểm tra yêu cầu SMB signing
- Liệt kê các share có thể truy cập qua null session
- Thử tìm các share nhạy cảm

### Cách sử dụng
```bash
# Sử dụng riêng lẻ
python modules/scanners/smb_scanner.py 192.168.1.1 --brute-force

# Tích hợp với SpyHunt
python spyhunt.py --smb-scan 192.168.1.1 --smb-port 445 --smb-brute
```

### Tham số
- `--smb-scan`: Địa chỉ IP/tên miền mục tiêu
- `--smb-port`: Cổng SMB (mặc định: 445)
- `--smb-brute`: Kích hoạt thử các kỹ thuật brute force

## 2. LDAP Scanner

### Mô tả
Scanner chuyên dụng để kiểm tra các lỗ hổng và cấu hình sai trong dịch vụ LDAP (Lightweight Directory Access Protocol), thường được sử dụng cho xác thực và thư mục người dùng.

### Tính năng chính
- Kiểm tra cổng LDAP (mặc định 389) và LDAPS (mặc định 636)
- Thử truy cập LDAP ẩn danh (anonymous bind)
- Kiểm tra cấu hình LDAP và chính sách mật khẩu yếu
- Kiểm tra lỗ hổng LDAP injection

### Cách sử dụng
```bash
# Sử dụng riêng lẻ
python modules/scanners/ldap_scanner.py domain.com --port 389 --ldaps-port 636

# Tích hợp với SpyHunt
python spyhunt.py --ldap-scan domain.com --ldap-port 389 --ldaps-port 636
```

### Tham số
- `--ldap-scan`: Địa chỉ IP/tên miền mục tiêu
- `--ldap-port`: Cổng LDAP (mặc định: 389)
- `--ldaps-port`: Cổng LDAPS (mặc định: 636)
- `--brute-force`: Kích hoạt thử các kỹ thuật brute force

## 3. Redis Scanner

### Mô tả
Scanner chuyên dụng để kiểm tra các lỗ hổng và cấu hình sai trong dịch vụ Redis, một hệ thống lưu trữ key-value phổ biến.

### Tính năng chính
- Kiểm tra cổng Redis (mặc định 6379)
- Kiểm tra xác thực Redis
- Phát hiện các lệnh nguy hiểm (CONFIG, FLUSHALL, KEYS, CLIENT LIST)
- Kiểm tra lỗ hổng RCE thông qua kỹ thuật master-slave replication
- Phát hiện phiên bản Redis

### Cách sử dụng
```bash
# Sử dụng riêng lẻ
python modules/scanners/redis_scanner.py 192.168.1.1 --port 6379 --brute-force

# Tích hợp với SpyHunt
python spyhunt.py --redis-scan 192.168.1.1 --redis-port 6379
```

### Tham số
- `--redis-scan`: Địa chỉ IP/tên miền mục tiêu
- `--redis-port`: Cổng Redis (mặc định: 6379)

## 4. FTP Scanner

### Mô tả
Scanner chuyên dụng để kiểm tra các lỗ hổng và cấu hình sai trong dịch vụ FTP (File Transfer Protocol).

### Tính năng chính
- Kiểm tra cổng FTP (mặc định 21)
- Lấy banner và nhận diện phiên bản
- Phát hiện các phiên bản FTP server dễ bị tấn công
- Kiểm tra truy cập ẩn danh (anonymous)
- Liệt kê thư mục có thể truy cập
- Kiểm tra khả năng ghi file
- Brute force thông tin đăng nhập yếu

### Cách sử dụng
```bash
# Sử dụng riêng lẻ
python modules/scanners/ftp_scanner.py example.com --port 21 --brute-force --userlist users.txt --passlist passwords.txt

# Tích hợp với SpyHunt
python spyhunt.py --ftp-scan example.com --ftp-port 21 --username-wordlist users.txt --password-wordlist passwords.txt
```

### Tham số
- `--ftp-scan`: Địa chỉ IP/tên miền mục tiêu
- `--ftp-port`: Cổng FTP (mặc định: 21)
- `--username-wordlist`: File chứa danh sách username để brute force
- `--password-wordlist`: File chứa danh sách password để brute force

## Sử dụng chung với AutoRecon

Có thể sử dụng các scanner này như một phần của quá trình quét tự động với AutoRecon:

```bash
python spyhunt.py --autorecon example.com --intensity aggressive --max-time 3600 --scan-profile full --save-autorecon results
```

## Sử dụng với AI Bug Bounty

Các scanner này cũng được tích hợp vào quy trình phân tích AI cho Bug Bounty:

```bash
python spyhunt.py --ai-bug-bounty example.com --focus network
```

AI sẽ quyết định khi nào sử dụng các scanner này dựa trên phân tích ban đầu về mục tiêu và các dịch vụ được phát hiện.

## Lưu ý quan trọng

1. Các scanner này chỉ nên được sử dụng với các hệ thống mà bạn có quyền kiểm tra.
2. Một số kỹ thuật quét có thể được xem là xâm nhập và có thể gây ra vấn đề pháp lý nếu sử dụng mà không có sự cho phép.
3. Đối với chế độ brute-force, hãy cẩn thận vì có thể gây tác động lớn đến hệ thống mục tiêu và có thể kích hoạt các biện pháp bảo mật.
4. Luôn đọc và hiểu các kết quả quét trước khi đưa ra kết luận về bảo mật của hệ thống.

## Cách mở rộng

Để thêm scanner mới:

1. Tạo file Python mới trong thư mục `modules/scanners/`
2. Thêm scanner vào danh sách `__all__` trong file `modules/scanners/__init__.py`
3. Thêm xử lý cho scanner trong file `spyhunt.py`

## Bản quyền và giấy phép

SpyHunt và các scanner chuyên biệt được phát hành dưới giấy phép MIT. 