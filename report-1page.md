# Lab 8 - Báo cáo 1 trang

## 1. Mục tiêu

Bài lab xây dựng chương trình truyền dữ liệu an toàn qua TCP socket bằng mô hình mã hóa lai kết hợp DES-CBC, SHA-256 và RSA-OAEP.  

Mục tiêu chính là:
- bảo mật nội dung dữ liệu truyền đi,
- kiểm tra tính toàn vẹn dữ liệu,
- bảo vệ khóa DES khi gửi qua mạng.

---

## 2. Luồng xử lý Sender

Sender thực hiện các bước:

1. Đọc plaintext từ biến môi trường `MESSAGE`, file `INPUT_FILE` hoặc nhập từ bàn phím.
2. Tính SHA-256 của plaintext gốc.
3. Sinh ngẫu nhiên DES key 8 byte và IV 8 byte.
4. Mã hóa plaintext bằng DES-CBC với PKCS#7 padding.
5. Gắn IV vào đầu ciphertext.
6. Mã hóa DES key bằng RSA public key của Receiver bằng cơ chế RSA-OAEP.
7. Đóng gói packet theo định dạng:
   - độ dài encrypted DES key,
   - encrypted DES key,
   - độ dài ciphertext,
   - ciphertext,
   - SHA-256 hash.
8. Gửi packet qua TCP socket.

---

## 3. Luồng xử lý Receiver

Receiver thực hiện các bước:

1. Nhận packet từ socket.
2. Tách encrypted DES key, ciphertext và SHA-256 hash.
3. Dùng RSA private key để giải mã DES key.
4. Dùng DES key và IV để giải mã ciphertext bằng DES-CBC.
5. Tính lại SHA-256 của plaintext sau giải mã.
6. So sánh hash nhận được với hash vừa tính.
7. Nếu hash khớp thì dữ liệu toàn vẹn; nếu khác thì dữ liệu đã bị thay đổi.

---

## 4. Kết quả minh chứng

- Sender gửi dữ liệu thành công qua localhost.
- Receiver giải mã đúng plaintext ban đầu.
- SHA-256 xác minh dữ liệu không bị thay đổi.
- Test phát hiện được packet bị sửa hash hoặc ciphertext.

Các file minh chứng:
- `logs/sender_success.log`
- `logs/receiver_success.log`
- `sample_input.txt`
- `sample_output.txt`

---

## 5. Nhận xét

RSA-OAEP giúp bảo vệ khóa DES trong quá trình truyền qua mạng nên attacker không thể đọc được khóa phiên nếu chỉ chặn được packet.  

SHA-256 giúp kiểm tra tính toàn vẹn dữ liệu và phát hiện packet bị sửa đổi.  

Tuy nhiên DES hiện không còn an toàn cho hệ thống thực tế vì kích thước khóa nhỏ và có thể bị brute-force. Trong thực tế nên nâng cấp lên:
- AES-128 hoặc AES-256,
- AES-GCM để kết hợp mã hóa và xác thực dữ liệu,
- chữ ký số RSA/ECDSA để xác minh danh tính Sender.
