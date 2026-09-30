# BT10 – JWT với Nimbus

Bài demo Java thay thư viện JWT bằng **Nimbus JOSE + JWT**. Chương trình tạo JWT ký HS256, giải mã claims sau khi xác minh chữ ký và từ chối token bị sửa.

## Chạy chương trình

Cần JDK 8 trở lên và Maven:

```bash
mvn compile exec:java
```

## Nội dung

- `JwtService.createToken`: tạo token với `iss`, `sub`, `aud`, `iat`, `exp`, `jti`, `username`, `role`.
- `JwtService.verifyToken`: chỉ chấp nhận HS256, kiểm tra chữ ký, issuer, audience, thời hạn và `nbf` nếu có.
- `JwtDemo`: in token và claims; sau đó sửa token để minh họa xác minh thất bại.

Secret trong `JwtDemo` chỉ dành cho bài tập. Ứng dụng thực tế nên lấy secret ngẫu nhiên tối thiểu 32 byte từ biến môi trường hoặc secret manager; không đưa secret thật lên Git. Payload JWT chỉ được mã hóa Base64URL, không được mã hóa kín, nên không đặt mật khẩu hay dữ liệu nhạy cảm vào claims.
