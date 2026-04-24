import socket
import ssl
import time
import math
import struct
import os
import json
from collections import Counter
from typing import Dict, Any, Optional, Tuple, List


class LabEncryptedProxyProfiler:
    """
    授权实验环境中的加密代理家族评分器

    目标：
    1. 不确认某个真实协议
    2. 只做行为指纹采集与家族评分
    3. 用于本地样本库对比：
       - plain_http
       - tls_service
       - socks5_service
       - native_aead_like
       - outline_like
       - ss2022_like
       - unknown_encrypted_binary
    """

    FAMILY_NAMES = [
        "plain_http",
        "tls_service",
        "socks5_service",
        "native_aead_like",
        "outline_like",
        "ss2022_like",
        "unknown_encrypted_binary",
    ]

    def __init__(self, timeout: float = 3.0, recv_size: int = 4096):
        self.timeout = timeout
        self.recv_size = recv_size

    # =========================================================
    # 对外主入口
    # =========================================================
    def profile(self, ip: str, port: int) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "target": f"{ip}:{port}",
            "reachable": False,
            "connect_latency_ms": None,
            "family_scores": self._init_scores(),
            "evidence": [],
            "fingerprints": [],
            "observations": {},
            "top_family": None,
            "top_score": 0.0,
            "needs_manual_review": False,
            "errors": [],
            "service_exclusion_hits": [],
        }

        # 1. 基础连通性
        connect_info = self._test_connect(ip, port)
        result["observations"]["connect"] = connect_info

        if not connect_info["reachable"]:
            result["errors"].append(connect_info.get("error", "连接失败"))
            result["needs_manual_review"] = True
            return result

        result["reachable"] = True
        result["connect_latency_ms"] = connect_info["latency_ms"]

        # 2. 基础行为观测
        result["observations"]["idle"] = self._test_idle_behavior(ip, port)
        result["observations"]["http"] = self._test_http_probe(ip, port)
        result["observations"]["tls"] = self._test_tls_probe(ip, port)
        result["observations"]["socks5"] = self._test_socks5_probe(ip, port)
        result["observations"]["random_probe"] = self._test_random_probe(ip, port)

        # 3. 常见服务排除探针
        result["observations"]["ssh"] = self._test_ssh_probe(ip, port)
        result["observations"]["redis"] = self._test_redis_probe(ip, port)
        result["observations"]["smtp"] = self._test_smtp_probe(ip, port)
        result["observations"]["pop3"] = self._test_pop3_probe(ip, port)
        result["observations"]["imap"] = self._test_imap_probe(ip, port)
        result["observations"]["mysql"] = self._test_mysql_probe(ip, port)
        result["observations"]["postgresql"] = self._test_postgresql_probe(ip, port)

        # 4. 评分
        self._score_common_cleartext_services(result)
        self._score_tls_and_socks(result)
        self._score_encrypted_binary_behaviors(result)

        # 5. 收敛与解释
        self._normalize_scores(result["family_scores"])
        result["fingerprints"] = self._extract_fingerprints(
            result["observations"], result["family_scores"]
        )
        result["top_family"], result["top_score"] = self._pick_top_family(
            result["family_scores"]
        )
        result["needs_manual_review"] = self._needs_manual_review(result)

        return result

    # =========================================================
    # 评分逻辑
    # =========================================================
    def _score_common_cleartext_services(self, result: Dict[str, Any]) -> None:
        scores = result["family_scores"]
        evidence = result["evidence"]
        obs = result["observations"]
        exclusion_hits = result["service_exclusion_hits"]

        http = obs.get("http", {})
        idle = obs.get("idle", {})
        ssh = obs.get("ssh", {})
        redis = obs.get("redis", {})
        smtp = obs.get("smtp", {})
        pop3 = obs.get("pop3", {})
        imap = obs.get("imap", {})
        mysql = obs.get("mysql", {})
        postgresql = obs.get("postgresql", {})

        if http.get("looks_like_http"):
            scores["plain_http"] += 0.95
            evidence.append("HTTP 探针命中标准 HTTP 响应特征")

        if ssh.get("looks_like_ssh"):
            exclusion_hits.append("ssh")
            scores["unknown_encrypted_binary"] -= 0.20
            evidence.append("空连接 banner 命中 SSH 特征")

        if redis.get("looks_like_redis"):
            exclusion_hits.append("redis")
            scores["unknown_encrypted_binary"] -= 0.20
            evidence.append("PING 命中 Redis 特征")

        if smtp.get("looks_like_smtp"):
            exclusion_hits.append("smtp")
            scores["unknown_encrypted_binary"] -= 0.20
            evidence.append("SMTP 探针命中，整体更像邮件服务")

        if pop3.get("looks_like_pop3"):
            exclusion_hits.append("pop3")
            scores["unknown_encrypted_binary"] -= 0.20
            evidence.append("POP3 探针命中，整体更像邮件服务")

        if imap.get("looks_like_imap"):
            exclusion_hits.append("imap")
            scores["unknown_encrypted_binary"] -= 0.20
            evidence.append("IMAP 探针命中，整体更像邮件服务")

        if mysql.get("looks_like_mysql"):
            exclusion_hits.append("mysql")
            scores["unknown_encrypted_binary"] -= 0.20
            evidence.append("MySQL greeting 命中，整体更像数据库服务")

        if postgresql.get("looks_like_postgresql"):
            exclusion_hits.append("postgresql")
            scores["unknown_encrypted_binary"] -= 0.20
            evidence.append("PostgreSQL SSLRequest 命中，整体更像数据库服务")

        if idle.get("has_banner") and idle.get("banner_like_text") and not http.get("looks_like_http"):
            scores["plain_http"] += 0.10
            evidence.append("空连接存在明文 banner，整体更像明文服务")

    def _score_tls_and_socks(self, result: Dict[str, Any]) -> None:
        scores = result["family_scores"]
        evidence = result["evidence"]
        obs = result["observations"]

        tls = obs.get("tls", {})
        socks5 = obs.get("socks5", {})
        http = obs.get("http", {})
        idle = obs.get("idle", {})

        if tls.get("tls_handshake_success"):
            scores["tls_service"] += 0.85
            evidence.append(f"TLS 标准握手成功，版本={tls.get('tls_version')}")

            if http.get("looks_like_http"):
                scores["plain_http"] += 0.20
                evidence.append("TLS 与 HTTP 同时命中，整体更像 HTTPS/Web 服务")

            scores["native_aead_like"] -= 0.10
            scores["ss2022_like"] -= 0.10
            scores["outline_like"] -= 0.10

        if socks5.get("looks_like_socks5"):
            scores["socks5_service"] += 0.95
            evidence.append("SOCKS5 握手命中标准响应")
            scores["native_aead_like"] -= 0.15
            scores["outline_like"] -= 0.15
            scores["ss2022_like"] -= 0.15

        if idle.get("silent") and not tls.get("tls_handshake_success") and not socks5.get("looks_like_socks5"):
            scores["unknown_encrypted_binary"] += 0.20
            evidence.append("空连接静默，且 TLS/SOCKS5 未命中")

    def _score_encrypted_binary_behaviors(self, result: Dict[str, Any]) -> None:
        """
        注意：
        这里只做“实验室样本簇评分”，不做对外协议确认。
        """
        scores = result["family_scores"]
        evidence = result["evidence"]
        obs = result["observations"]

        idle = obs.get("idle", {})
        tls = obs.get("tls", {})
        socks5 = obs.get("socks5", {})
        random_probe = obs.get("random_probe", {})
        http = obs.get("http", {})

        no_clear_hit = (
            not http.get("looks_like_http")
            and not tls.get("tls_handshake_success")
            and not socks5.get("looks_like_socks5")
        )

        if random_probe.get("high_entropy_response") and random_probe.get("binary_response"):
            scores["unknown_encrypted_binary"] += 0.30
            evidence.append("随机探针下出现高熵二进制响应")

            if no_clear_hit:
                scores["native_aead_like"] += 0.15
                scores["outline_like"] += 0.10
                scores["ss2022_like"] += 0.12
                evidence.append("未命中 HTTP/TLS/SOCKS5，保留为实验室加密代理候选")

        if idle.get("silent") and not idle.get("banner_like_text"):
            scores["unknown_encrypted_binary"] += 0.20
            evidence.append("空连接静默且无明文 banner")

            if no_clear_hit:
                scores["native_aead_like"] += 0.08
                scores["outline_like"] += 0.10
                scores["ss2022_like"] += 0.08

        if random_probe.get("recv_len", 0) == 0 and random_probe.get("recv_error") in ("timeout", None):
            scores["unknown_encrypted_binary"] += 0.12
            evidence.append("随机探针下未收到响应，表现为静默处理")

            if no_clear_hit:
                scores["outline_like"] += 0.08
                scores["ss2022_like"] += 0.06

        if no_clear_hit and idle.get("connected"):
            scores["unknown_encrypted_binary"] += 0.15
            scores["native_aead_like"] += 0.08
            scores["outline_like"] += 0.08
            scores["ss2022_like"] += 0.08
            evidence.append("连接可达，但常见明文/TLS/SOCKS5 特征均未命中")

        if idle.get("silent") and random_probe.get("recv_len", 0) == 0 and no_clear_hit:
            scores["outline_like"] += 0.05
            scores["ss2022_like"] += 0.05
            evidence.append("静默型行为可保留为 outline/2022 候选，但需人工复核")

    # =========================================================
    # 基础网络工具
    # =========================================================
    def _init_scores(self) -> Dict[str, float]:
        return {name: 0.0 for name in self.FAMILY_NAMES}

    def _normalize_scores(self, scores: Dict[str, float]) -> None:
        for k, v in scores.items():
            if v < 0:
                scores[k] = 0.0
            elif v > 1.0:
                scores[k] = 1.0

    def _pick_top_family(self, scores: Dict[str, float]) -> Tuple[Optional[str], float]:
        if not scores:
            return None, 0.0
        top_family = max(scores.items(), key=lambda x: x[1])
        return top_family[0], round(top_family[1], 3)

    def _needs_manual_review(self, result: Dict[str, Any]) -> bool:
        scores = result["family_scores"]
        top_family = result["top_family"]
        top_score = result["top_score"]

        if top_family is None:
            return True

        if top_score < 0.35:
            return True

        sorted_items = sorted(scores.items(), key=lambda x: x[1], reverse=True)

        if len(sorted_items) >= 2 and (sorted_items[0][1] - sorted_items[1][1]) < 0.12:
            return True

        # 关键改动 1：只要打到 unknown_encrypted_binary，就强制人工复核
        if top_family == "unknown_encrypted_binary":
            return True

        # 关键改动 2：如果 top3 里同时有多个加密候选类，也强制复核
        top3_names = [name for name, _ in sorted_items[:3]]
        candidate_set = {
            "native_aead_like",
            "outline_like",
            "ss2022_like",
            "unknown_encrypted_binary",
        }
        if sum(1 for name in top3_names if name in candidate_set) >= 2:
            return True

        return False

    def _create_socket(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        return sock

    def _safe_close(self, sock: Optional[socket.socket]) -> None:
        if sock is None:
            return
        try:
            sock.close()
        except Exception:
            pass

    def _recv_once(self, sock: socket.socket, size: Optional[int] = None) -> Tuple[bytes, Optional[str]]:
        size = size or self.recv_size
        try:
            data = sock.recv(size)
            return data, None
        except socket.timeout:
            return b"", "timeout"
        except ConnectionResetError:
            return b"", "connection_reset"
        except Exception as e:
            return b"", f"{type(e).__name__}: {e}"

    def _send_and_recv(
        self,
        ip: str,
        port: int,
        payload: bytes,
        wait_before_recv: float = 0.1,
    ) -> Dict[str, Any]:
        sock = None
        started = time.perf_counter()

        try:
            sock = self._create_socket()
            sock.connect((ip, port))
            connect_done = time.perf_counter()

            sent_len = sock.send(payload)
            time.sleep(wait_before_recv)

            data, recv_error = self._recv_once(sock)
            ended = time.perf_counter()

            return {
                "connected": True,
                "connect_latency_ms": round((connect_done - started) * 1000, 2),
                "roundtrip_ms": round((ended - started) * 1000, 2),
                "sent_len": sent_len,
                "recv_len": len(data),
                "recv_preview_hex": data[:64].hex(),
                "recv_preview_ascii": self._safe_ascii_preview(data[:64]),
                "recv_entropy": self._calculate_entropy(data) if data else 0.0,
                "recv_error": recv_error,
                "text_like": self._is_mostly_printable(data),
                "binary_like": (len(data) > 0 and not self._is_mostly_printable(data)),
            }
        except Exception as e:
            return {
                "connected": False,
                "error": f"{type(e).__name__}: {e}",
            }
        finally:
            self._safe_close(sock)

    def _connect_and_recv_banner(self, ip: str, port: int, wait_s: float = 0.5) -> Dict[str, Any]:
        sock = None
        started = time.perf_counter()

        try:
            sock = self._create_socket()
            sock.connect((ip, port))
            connect_done = time.perf_counter()

            time.sleep(wait_s)
            data, recv_error = self._recv_once(sock)
            ended = time.perf_counter()

            return {
                "connected": True,
                "connect_latency_ms": round((connect_done - started) * 1000, 2),
                "roundtrip_ms": round((ended - started) * 1000, 2),
                "recv_len": len(data),
                "recv_preview_hex": data[:64].hex(),
                "recv_preview_ascii": self._safe_ascii_preview(data[:64]),
                "recv_entropy": self._calculate_entropy(data) if data else 0.0,
                "recv_error": recv_error,
                "text_like": self._is_mostly_printable(data),
                "binary_like": (len(data) > 0 and not self._is_mostly_printable(data)),
            }
        except Exception as e:
            return {
                "connected": False,
                "error": f"{type(e).__name__}: {e}",
            }
        finally:
            self._safe_close(sock)

    # =========================================================
    # 探针实现
    # =========================================================
    def _test_connect(self, ip: str, port: int) -> Dict[str, Any]:
        sock = None
        started = time.perf_counter()
        try:
            sock = self._create_socket()
            sock.connect((ip, port))
            ended = time.perf_counter()
            return {
                "reachable": True,
                "latency_ms": round((ended - started) * 1000, 2),
            }
        except Exception as e:
            return {
                "reachable": False,
                "error": f"{type(e).__name__}: {e}",
            }
        finally:
            self._safe_close(sock)

    def _test_idle_behavior(self, ip: str, port: int, idle_wait: float = 1.0) -> Dict[str, Any]:
        info = self._connect_and_recv_banner(ip, port, wait_s=idle_wait)
        if info.get("connected"):
            preview = info.get("recv_preview_ascii", "").lower()
            info["has_banner"] = info.get("recv_len", 0) > 0
            info["banner_like_text"] = (
                info.get("text_like", False)
                or any(
                    k in preview
                    for k in [
                        "http", "server", "welcome", "ssh", "smtp", "ftp",
                        "redis", "mysql", "postgres", "imap", "pop3", "220"
                    ]
                )
            )
            info["silent"] = (info.get("recv_len", 0) == 0 and info.get("recv_error") in ("timeout", None))
        else:
            info["has_banner"] = False
            info["banner_like_text"] = False
            info["silent"] = False
        return info

    def _test_http_probe(self, ip: str, port: int) -> Dict[str, Any]:
        payload = (
            b"GET / HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"User-Agent: LabEncryptedProxyProfiler/1.0\r\n"
            b"Connection: close\r\n\r\n"
        )
        info = self._send_and_recv(ip, port, payload)
        preview = info.get("recv_preview_ascii", "")
        lower_preview = preview.lower()
        info["looks_like_http"] = (
            preview.startswith("HTTP/")
            or "server:" in lower_preview
            or "content-" in lower_preview
            or "<html" in lower_preview
            or "<!doctype html" in lower_preview
        )
        return info

    def _test_tls_probe(self, ip: str, port: int) -> Dict[str, Any]:
        raw_sock = None
        tls_sock = None
        started = time.perf_counter()

        try:
            raw_sock = self._create_socket()
            raw_sock.connect((ip, port))
            connect_done = time.perf_counter()

            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            tls_sock = context.wrap_socket(raw_sock, server_hostname=ip)
            handshake_done = time.perf_counter()

            cert = tls_sock.getpeercert(binary_form=False)
            cipher = tls_sock.cipher()
            version = tls_sock.version()

            return {
                "connected": True,
                "tls_handshake_success": True,
                "connect_latency_ms": round((connect_done - started) * 1000, 2),
                "handshake_latency_ms": round((handshake_done - connect_done) * 1000, 2),
                "tls_version": version,
                "cipher": cipher,
                "certificate_present": cert is not None,
            }
        except ssl.SSLError as e:
            return {
                "connected": True,
                "tls_handshake_success": False,
                "ssl_error_type": type(e).__name__,
                "ssl_error": str(e),
            }
        except Exception as e:
            return {
                "connected": False,
                "tls_handshake_success": False,
                "error": f"{type(e).__name__}: {e}",
            }
        finally:
            self._safe_close(tls_sock)
            if tls_sock is None:
                self._safe_close(raw_sock)

    def _test_socks5_probe(self, ip: str, port: int) -> Dict[str, Any]:
        payload = b"\x05\x01\x00"
        info = self._send_and_recv(ip, port, payload)
        info["looks_like_socks5"] = False

        raw_hex = info.get("recv_preview_hex", "")
        if info.get("connected") and len(raw_hex) >= 4:
            if raw_hex.startswith("0500") or raw_hex.startswith("05ff"):
                info["looks_like_socks5"] = True
        return info

    def _test_random_probe(self, ip: str, port: int) -> Dict[str, Any]:
        payload = os.urandom(32)
        info = self._send_and_recv(ip, port, payload)
        entropy = info.get("recv_entropy", 0.0)
        recv_len = info.get("recv_len", 0)
        info["high_entropy_response"] = entropy >= 6.5 and recv_len >= 16
        info["binary_response"] = info.get("binary_like", False)
        return info

    def _test_ssh_probe(self, ip: str, port: int) -> Dict[str, Any]:
        info = self._connect_and_recv_banner(ip, port, wait_s=0.5)
        preview = info.get("recv_preview_ascii", "")
        info["looks_like_ssh"] = preview.startswith("SSH-")
        return info

    def _test_redis_probe(self, ip: str, port: int) -> Dict[str, Any]:
        payload = b"*1\r\n$4\r\nPING\r\n"
        info = self._send_and_recv(ip, port, payload)
        preview = info.get("recv_preview_ascii", "")
        info["looks_like_redis"] = (
            preview.startswith("+PONG")
            or preview.startswith("-NOAUTH")
            or preview.startswith("-ERR")
            or preview.startswith("-DENIED")
        )
        return info

    def _test_smtp_probe(self, ip: str, port: int) -> Dict[str, Any]:
        banner = self._connect_and_recv_banner(ip, port, wait_s=0.5)
        preview = banner.get("recv_preview_ascii", "")
        lower_preview = preview.lower()

        banner["looks_like_smtp"] = (
            preview.startswith("220") and ("smtp" in lower_preview or "mail" in lower_preview)
        )

        if not banner["looks_like_smtp"]:
            active = self._send_and_recv(ip, port, b"EHLO example.com\r\n", wait_before_recv=0.2)
            active_preview = active.get("recv_preview_ascii", "")
            active_lower = active_preview.lower()
            active["looks_like_smtp"] = (
                active_preview.startswith("250")
                or "smtp" in active_lower
                or "ehlo" in active_lower
            )
            return {
                "banner_probe": banner,
                "active_probe": active,
                "looks_like_smtp": active["looks_like_smtp"],
            }

        return {
            "banner_probe": banner,
            "active_probe": None,
            "looks_like_smtp": True,
        }

    def _test_pop3_probe(self, ip: str, port: int) -> Dict[str, Any]:
        banner = self._connect_and_recv_banner(ip, port, wait_s=0.5)
        preview = banner.get("recv_preview_ascii", "")
        lower_preview = preview.lower()

        banner["looks_like_pop3"] = (
            preview.startswith("+OK") and ("pop3" in lower_preview or "mail" in lower_preview or len(preview) > 0)
        )

        if not banner["looks_like_pop3"]:
            active = self._send_and_recv(ip, port, b"CAPA\r\n", wait_before_recv=0.2)
            active_preview = active.get("recv_preview_ascii", "")
            active["looks_like_pop3"] = (
                active_preview.startswith("+OK")
                or "capa" in active_preview.lower()
            )
            return {
                "banner_probe": banner,
                "active_probe": active,
                "looks_like_pop3": active["looks_like_pop3"],
            }

        return {
            "banner_probe": banner,
            "active_probe": None,
            "looks_like_pop3": True,
        }

    def _test_imap_probe(self, ip: str, port: int) -> Dict[str, Any]:
        banner = self._connect_and_recv_banner(ip, port, wait_s=0.5)
        preview = banner.get("recv_preview_ascii", "")
        lower_preview = preview.lower()

        banner["looks_like_imap"] = (
            preview.startswith("* OK")
            or "imap" in lower_preview
        )

        if not banner["looks_like_imap"]:
            active = self._send_and_recv(ip, port, b"a001 CAPABILITY\r\n", wait_before_recv=0.2)
            active_preview = active.get("recv_preview_ascii", "")
            active_lower = active_preview.lower()
            active["looks_like_imap"] = (
                "* capability" in active_lower
                or "imap4" in active_lower
                or active_preview.startswith("* OK")
            )
            return {
                "banner_probe": banner,
                "active_probe": active,
                "looks_like_imap": active["looks_like_imap"],
            }

        return {
            "banner_probe": banner,
            "active_probe": None,
            "looks_like_imap": True,
        }

    def _test_mysql_probe(self, ip: str, port: int) -> Dict[str, Any]:
        info = self._connect_and_recv_banner(ip, port, wait_s=0.5)
        data_hex = info.get("recv_preview_hex", "")
        data_ascii = info.get("recv_preview_ascii", "")
        looks_like_mysql = False

        if info.get("recv_len", 0) >= 5:
            if any(v in data_ascii.lower() for v in ["mariadb", "mysql", "5.7.", "8.0."]):
                looks_like_mysql = True
            else:
                raw = bytes.fromhex(data_hex) if data_hex else b""
                if len(raw) >= 6 and 0x0A in raw[:10]:
                    idx = raw.find(b"\x0a")
                    if idx != -1 and idx + 1 < len(raw):
                        tail = raw[idx + 1: idx + 20]
                        if self._is_mostly_printable(tail):
                            looks_like_mysql = True

        info["looks_like_mysql"] = looks_like_mysql
        return info

    def _test_postgresql_probe(self, ip: str, port: int) -> Dict[str, Any]:
        payload = struct.pack("!II", 8, 80877103)
        info = self._send_and_recv(ip, port, payload, wait_before_recv=0.2)

        info["looks_like_postgresql"] = False
        preview_hex = info.get("recv_preview_hex", "")
        preview_ascii = info.get("recv_preview_ascii", "")

        if info.get("recv_len", 0) >= 1:
            if preview_ascii.startswith("S") or preview_ascii.startswith("N"):
                info["looks_like_postgresql"] = True
            elif preview_hex.startswith("53") or preview_hex.startswith("4e"):
                info["looks_like_postgresql"] = True

        return info

    # =========================================================
    # 指纹提炼
    # =========================================================
    def _extract_fingerprints(self, observations: Dict[str, Any], scores: Dict[str, float]) -> List[str]:
        fp: List[str] = []

        connect = observations.get("connect", {})
        idle = observations.get("idle", {})
        http = observations.get("http", {})
        tls = observations.get("tls", {})
        socks5 = observations.get("socks5", {})
        random_probe = observations.get("random_probe", {})

        if connect.get("latency_ms") is not None:
            fp.append(f"connect_latency={connect['latency_ms']}ms")

        if idle.get("has_banner"):
            fp.append("idle_banner=text" if idle.get("banner_like_text") else "idle_banner=binary")
        elif idle.get("silent"):
            fp.append("idle_behavior=silent")

        if http.get("looks_like_http"):
            fp.append("http_probe=positive")

        if tls.get("tls_handshake_success"):
            fp.append(f"tls={tls.get('tls_version')}")
        elif "ssl_error" in tls or "error" in tls:
            fp.append("tls=handshake_failed")

        if socks5.get("looks_like_socks5"):
            fp.append("socks5=positive")

        if random_probe.get("connected"):
            fp.append(f"random_entropy={random_probe.get('recv_entropy', 0.0):.2f}")
            if random_probe.get("high_entropy_response"):
                fp.append("random_probe=high_entropy_response")

        sorted_scores = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        fp.append("top3_scores=" + ",".join([f"{k}:{v:.2f}" for k, v in sorted_scores[:3]]))
        return fp

    # =========================================================
    # 辅助函数
    # =========================================================
    def _calculate_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        counter = Counter(data)
        n = len(data)
        entropy = 0.0
        for count in counter.values():
            p = count / n
            entropy -= p * math.log2(p)
        return entropy

    def _safe_ascii_preview(self, data: bytes) -> str:
        if not data:
            return ""
        chars = []
        for b in data:
            if 32 <= b <= 126 or b in (9, 10, 13):
                chars.append(chr(b))
            else:
                chars.append(".")
        return "".join(chars)

    def _is_mostly_printable(self, data: bytes) -> bool:
        if not data:
            return False
        printable = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13))
        return printable / len(data) >= 0.8


def pretty_print_result(result: Dict[str, Any]) -> None:
    print("=" * 100)
    print(f"目标: {result['target']}")
    if "real_label" in result:
        print(f"真实类别: {result['real_label']}")
    if "round_id" in result:
        print(f"轮次: {result['round_id']}")
    print(f"可达: {result['reachable']}")
    print(f"连接耗时: {result['connect_latency_ms']} ms")
    print(f"Top Family: {result['top_family']}")
    print(f"Top Score: {result['top_score']}")
    print(f"需要人工复核: {result['needs_manual_review']}")
    print()

    print("[家族评分]")
    for k, v in sorted(result["family_scores"].items(), key=lambda x: x[1], reverse=True):
        print(f"  - {k}: {v:.2f}")

    print("\n[证据]")
    for item in result.get("evidence", []):
        print(f"  - {item}")

    print("\n[排除命中]")
    for item in result.get("service_exclusion_hits", []):
        print(f"  - {item}")

    print("\n[行为指纹]")
    for item in result.get("fingerprints", []):
        print(f"  - {item}")

    print("\n[详细观测]")
    for name, obs in result.get("observations", {}).items():
        print(f"\n  <{name}>")
        if isinstance(obs, dict):
            for k, v in obs.items():
                print(f"    {k}: {v}")
        else:
            print(f"    {obs}")

    if result.get("errors"):
        print("\n[错误]")
        for err in result["errors"]:
            print(f"  - {err}")
    print("=" * 100)


def save_result_jsonl(path: str, result: Dict[str, Any]) -> None:
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(result, ensure_ascii=False) + "\n")


def print_summary_table(results: List[Dict[str, Any]]) -> None:
    print("\n" + "=" * 120)
    print("SUMMARY")
    print("=" * 120)
    print(f"{'round':<8} {'target':<18} {'real_label':<22} {'pred_label':<26} {'score':<8} {'manual_review'}")
    for item in results:
        print(
            f"{item.get('round_id', '-'): <8} "
            f"{item['target']:<18} "
            f"{item.get('real_label', '-'): <22} "
            f"{str(item.get('top_family', '-')):<26} "
            f"{item.get('top_score', 0):<8} "
            f"{item.get('needs_manual_review')}"
        )


def main():
    profiler = LabEncryptedProxyProfiler(timeout=3.0)

    targets = [
        ("plain_http", "127.0.0.1", 8080),
        ("tls_service", "127.0.0.1", 8443),
        ("socks5_service", "127.0.0.1", 1080),
        ("native_aead_like", "127.0.0.1", 8381),
        ("native_aead_like", "127.0.0.1", 8389),
        ("outline_like", "127.0.0.1", 8390),
    ]

    output_file = "lab_results.jsonl"
    if os.path.exists(output_file):
        os.remove(output_file)

    all_results: List[Dict[str, Any]] = []

    for round_id in range(1, 6):
        print(f"\n######## ROUND {round_id} ########\n")
        for real_label, ip, port in targets:
            result = profiler.profile(ip, port)
            result["real_label"] = real_label
            result["round_id"] = round_id
            pretty_print_result(result)
            save_result_jsonl(output_file, result)
            all_results.append(result)

    print_summary_table(all_results)


if __name__ == "__main__":
    main()
