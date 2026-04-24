# 本地样本库

## 1. plain_http
- 地址：127.0.0.1:8080
- 实现：python3 -m http.server
- 特征：明文 HTTP

## 2. tls_service
- 地址：127.0.0.1:8443
- 实现：openssl s_server
- 特征：标准 TLS 握手

## 3. socks5_service
- 地址：127.0.0.1:1080
- 实现：go-socks5-proxy
- 特征：标准 SOCKS5 握手

## 4. native_aead_like
- 地址：127.0.0.1:8388
- 实现：shadowsocks-libev
- method：aes-256-gcm
- password：test123456

## 5. native_aead_like
- 地址：127.0.0.1:8389
- 实现：shadowsocks-libev
- method：chacha20-ietf-poly1305
- password：test123456

## 6. outline_like
- 地址：127.0.0.1:8390
- 实现：shadowsocks-libev
- method：chacha20-ietf-poly1305
- password：outline-test-pass
- 备注：仅作 outline-like 行为样本，不代表官方 Outline 完整部署 
