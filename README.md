[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-22041afd0340ce965d47ae6ef1cefeee28c7c493a6346c4f15d667ab976d596c.svg)](https://classroom.github.com/a/1tfxOnrV)
# FIT4012 - Lab 8 - Xây dựng ứng dụng truyền dữ liệu an toàn

Repo starter kit này dùng cho **Lab 8**: xây dựng chương trình truyền dữ liệu an toàn qua **TCP socket** bằng mô hình lai:

1. **DES-CBC** để mã hóa bản tin.
2. **SHA-256** để kiểm tra tính toàn vẹn của bản tin gốc.
3. **RSA-OAEP** để mã hóa khóa DES trước khi gửi qua mạng.

Lab 8 kế thừa cách tổ chức repo của Lab 6 socket starter, nhưng thay đổi protocol: thay vì gửi key/IV plaintext, Sender mã hóa DES key bằng khóa công khai RSA của Receiver.

> Lưu ý quan trọng: DES hiện không còn an toàn cho hệ thống thật vì kích thước khóa nhỏ. Repo này dùng DES theo đúng yêu cầu bài thực hành để sinh viên hiểu cơ chế mã hóa lai, kiểm tra toàn vẹn và bảo vệ khóa đối xứng.

---

## Team members

- **Thành viên 1**: BUIVANTAI_1 - MSSV: 1871020515_ID
- **Thành viên 2**: NGUYENHOANGVIET_2 - MSSV: 1871020654_ID

## Task division

- **Thành viên 1 phụ trách chính**: BUIVANTAI_1
- **Thành viên 2 phụ trách chính**: NGUYỄN HOÀNG VIỆT_2
- **Phần làm chung**: CẢ NHÓM 

## Demo roles

- **Demo Sender / mã hóa / log gửi**: BUIVANTAI
- **Demo Receiver / giải mã / kiểm tra hash**: NGUYENHOANGVIET
- **Cả hai cùng trả lời câu hỏi mở rộng AES và chữ ký số**: CẢ NHÓM 
---

## Mục tiêu học tập

Sau bài lab này, sinh viên có thể:

- Mô tả được luồng truyền dữ liệu an toàn giữa Sender và Receiver qua TCP socket.
- Cài đặt được DES-CBC với key, IV và PKCS#7 padding.
- Tính và kiểm tra được SHA-256 để phát hiện dữ liệu bị thay đổi.
- Sử dụng RSA-OAEP để mã hóa khóa DES trước khi truyền.
- Thiết kế được packet có header độ dài cho dữ liệu nhị phân.
- Viết test cho các tình huống đúng, sai định dạng, sai hash và dữ liệu bị can thiệp.
- Phân tích được hạn chế của DES và đề xuất nâng cấp lên AES/chữ ký số.

---

## Cấu trúc repo

```text
.
├── secure_transfer_utils.py
├── keygen.py
├── sender.py
├── receiver.py
├── requirements.txt
├── sample_input.txt
├── sample_output.txt
├── report-1page.md
├── threat-model-1page.md
├── peer-review-response.md
├── logs/
├── keys/
├── tests/
└── .github/workflows/ci.yml
```

---

## Protocol truyền dữ liệu

Sender gửi **một gói dữ liệu nhị phân** qua socket theo thứ tự:

```text
[len_key: 4 bytes]
[encrypted_des_key: N bytes]
[len_cipher: 4 bytes]
[ciphertext: M bytes, gồm IV 8 byte ở đầu]
[sha256_hash: 32 bytes]
```

Ý nghĩa từng trường:

| Trường | Ý nghĩa |
|---|---|
| `len_key` | Độ dài khóa DES đã mã hóa bằng RSA, lưu bằng 4 byte network byte order |
| `encrypted_des_key` | DES key 8 byte sau khi được mã hóa bằng RSA public key của Receiver |
| `len_cipher` | Độ dài ciphertext, bao gồm IV ở 8 byte đầu |
| `ciphertext` | `IV + DES_CBC(PKCS7(plaintext))` |
| `sha256_hash` | SHA-256 của plaintext gốc, dài 32 byte |

---

## Cài đặt môi trường

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Windows PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

---

## Bước 1 - Tạo khóa RSA cho Receiver

```bash
python keygen.py
```

Lệnh trên tạo:

```text
keys/receiver_private.pem
keys/receiver_public.pem
```

Trong demo học tập local, hai file có thể nằm cùng repo. Trong hệ thống thật, Receiver phải giữ bí mật `receiver_private.pem`; Sender chỉ cần có `receiver_public.pem`.

---

## Bước 2 - Chạy demo local

### Terminal 1 - Receiver

```bash
RECEIVER_HOST=127.0.0.1 \
DATA_PORT=6000 \
RECEIVER_PRIVATE_KEY=keys/receiver_private.pem \
python receiver.py
```

### Terminal 2 - Sender

```bash
SERVER_IP=127.0.0.1 \
DATA_PORT=6000 \
RECEIVER_PUBLIC_KEY=keys/receiver_public.pem \
MESSAGE="Xin chao FIT4012 - Lab 8 Secure Transfer" \
python sender.py
```

---

## Chạy có log minh chứng

Terminal 1:

```bash
RECEIVER_HOST=127.0.0.1 \
DATA_PORT=6000 \
RECEIVER_PRIVATE_KEY=keys/receiver_private.pem \
RECEIVER_LOG_FILE=logs/receiver_success.log \
OUTPUT_FILE=sample_output.txt \
python receiver.py
```

Terminal 2:

```bash
SERVER_IP=127.0.0.1 \
DATA_PORT=6000 \
RECEIVER_PUBLIC_KEY=keys/receiver_public.pem \
MESSAGE="Xin chao FIT4012 - Lab 8 Secure Transfer" \
SENDER_LOG_FILE=logs/sender_success.log \
python sender.py
```

---

## Gửi dữ liệu từ file

Terminal 1:

```bash
RECEIVER_HOST=127.0.0.1 DATA_PORT=6000 OUTPUT_FILE=sample_output.txt python receiver.py
```

Terminal 2:

```bash
SERVER_IP=127.0.0.1 DATA_PORT=6000 INPUT_FILE=sample_input.txt python sender.py
```

---

## Chạy test

```bash
pytest -q
```

---

## Deliverables bắt buộc

- `README.md`
- `sender.py`
- `receiver.py`
- `secure_transfer_utils.py`
- `keygen.py`
- `tests/`
- `logs/`
- `report-1page.md`
- `threat-model-1page.md`
- `sample_input.txt`
- `sample_output.txt`

---

## Submission contract cho CI

CI sẽ kiểm tra:

- Có đủ file bắt buộc.
- Có sử dụng `DES` trong phần mã hóa bản tin.
- Có sử dụng `SHA-256` để kiểm tra toàn vẹn.
- Có sử dụng `RSA`/`PKCS1_OAEP` để bảo vệ khóa DES.
- Có ít nhất 8 test.
- Có test định dạng packet theo Lab 8.
- Có test DES-CBC roundtrip.
- Có test RSA encrypt/decrypt DES key.
- Có test hash bị sửa đổi.
- Có test ciphertext bị can thiệp.
- Có test socket helper local.
- README có thông tin nhóm 2 người.
- Các file báo cáo không còn `TODO_STUDENT`.
- Có thư mục `logs/` để nộp minh chứng chạy demo.

---

## Câu hỏi mở rộng

### Q1. Thay DES bằng AES

DES có key hiệu dụng nhỏ nên không còn phù hợp cho hệ thống thật. Khi nâng cấp lên AES, sinh viên cần trả lời:

- AES-128 dùng key bao nhiêu byte?
- AES-256 dùng key bao nhiêu byte?
- Nếu dùng AES-CBC, IV dài bao nhiêu byte?
- Nếu dùng AES-GCM, vì sao GCM có thể giải quyết cả mã hóa và xác thực dữ liệu tốt hơn CBC + hash rời rạc?

### Q2. Thêm chữ ký số

Phiên bản hiện tại giúp Receiver lấy được DES key một cách bí mật, nhưng chưa chứng minh Sender là ai. Hướng mở rộng:

- Sender có cặp khóa RSA riêng.
- Sender ký lên hash của `encrypted_des_key + ciphertext + sha256_hash` bằng private key của Sender.
- Receiver xác minh chữ ký bằng public key của Sender.
- Nếu verify thành công, Receiver có thêm bằng chứng về nguồn gửi và tính toàn vẹn của các thành phần quan trọng.

---

## Ethics & Safe use

- Chỉ chạy demo trên máy cá nhân, VM hoặc mạng nội bộ phục vụ học tập.
- Không quét cổng hoặc thử nghiệm trên hệ thống không được phép.
- Không dùng dữ liệu cá nhân thật hoặc dữ liệu nhạy cảm để demo.
- Không commit private key thật lên GitHub.
- Không trình bày hệ thống DES-CBC này như một giải pháp an toàn sẵn sàng triển khai thực tế.
- Nếu tham khảo code/tài liệu, hãy ghi nguồn rõ ràng.

---

## Bài học chính

Một hệ thống truyền dữ liệu an toàn không chỉ cần mã hóa nội dung.

Lab 8 cho thấy cần phối hợp nhiều lớp bảo vệ:

```text
DES-CBC che nội dung
SHA-256 kiểm tra dữ liệu có bị thay đổi không
RSA-OAEP bảo vệ khóa DES khi truyền qua mạng
```
