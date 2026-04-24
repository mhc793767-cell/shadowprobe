import socket
import time
import os
import random
from typing import Dict, Any, Optional, Tuple
import math
from collections import Counter
class ShadowsocksProbeProfiler:
    """
    专注于主动探测Shadowsocks协议的探针：
    1. 第一阶段：基础连通性探测
    2. 第二阶段：主动探测与行为指纹采集
    3. 第三阶段：加密代理协议分类与优化
    """

    def __init__(self, timeout: float = 3.0, recv_size: int = 4096):
        self.timeout = timeout
        self.recv_size = recv_size

    # =========================================================
    # 基础工具
    # =========================================================
    def _create_socket(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        return sock

    def _safe_close(self, sock: socket.socket) -> None:
        if sock:
            try:
                sock.close()
            except Exception:
                pass

    def _recv_once(self, sock: socket.socket) -> Tuple[bytes, Optional[str]]:
        try:
            data = sock.recv(self.recv_size)
            if data == b"":
                return data, "peer_closed"
            return data, None
        except socket.timeout:
            return b"", "timeout"
        except ConnectionResetError:
            return b"", "connection_reset"
        except BrokenPipeError:
            return b"", "broken_pipe"
        except Exception as e:
            return b"", f"{type(e).__name__}: {e}"

    # =========================================================
    # 第一阶段：基础连通性探测
    # =========================================================
    def connect_only(self, ip: str, port: int) -> Dict[str, Any]:
        sock = None
        result = {
            "connected": False,
            "connect_latency_ms": None,
            "recv_error": None,
        }

        try:
            sock = self._create_socket()
            start_time = time.perf_counter()
            sock.connect((ip, port))
            end_time = time.perf_counter()

            result["connected"] = True
            result["connect_latency_ms"] = round((end_time - start_time) * 1000, 2)
        except Exception as e:
            result["recv_error"] = f"{type(e).__name__}: {e}"
        finally:
            self._safe_close(sock)

        return result

    # =========================================================
    # 第二阶段：主动探测与行为指纹采集
    # =========================================================
    def probe_random_1_byte(self, ip: str, port: int) -> Dict[str, Any]:
        payload = os.urandom(1)
        return self._send_probe(ip, port, payload, "random_1_byte")

    def probe_random_8_bytes(self, ip: str, port: int) -> Dict[str, Any]:
        payload = os.urandom(8)
        return self._send_probe(ip, port, payload, "random_8_bytes")

    def probe_random_64_bytes(self, ip: str, port: int) -> Dict[str, Any]:
        payload = os.urandom(64)
        return self._send_probe(ip, port, payload, "random_64_bytes")

    def probe_split_random_32(self, ip: str, port: int) -> Dict[str, Any]:
        payload = os.urandom(32)
        part1 = payload[:16]
        part2 = payload[16:]
        return self._send_probe(ip, port, part1 + part2, "split_random_32")

    def probe_random_32_then_shutdown_wr(self, ip: str, port: int) -> Dict[str, Any]:
        payload = os.urandom(32)
        return self._send_probe(ip, port, payload, "random_32_then_shutdown_wr", shutdown_after_send=True)

    def _send_probe(self, ip: str, port: int, payload: bytes, probe_name: str, shutdown_after_send: bool = False) -> Dict[str, Any]:
        sock = None
        result = {
            "probe_name": probe_name,
            "connected": False,
            "connect_latency_ms": None,
            "roundtrip_ms": None,
            "sent_len": len(payload),
            "recv_len": 0,
            "recv_error": None,
            "recv_preview_hex": "",
            "recv_preview_ascii": "",
            "recv_entropy": 0.0,
            "shutdown_wr_after_send": shutdown_after_send,
        }

        try:
            sock = self._create_socket()
            start_time = time.perf_counter()
            sock.connect((ip, port))
            connect_done = time.perf_counter()

            sock.send(payload)

            if shutdown_after_send:
                sock.shutdown(socket.SHUT_WR)

            time.sleep(0.1)  # Wait before receiving response
            data, error = self._recv_once(sock)
            end_time = time.perf_counter()

            result["connected"] = True
            result["connect_latency_ms"] = round((connect_done - start_time) * 1000, 2)
            result["roundtrip_ms"] = round((end_time - start_time) * 1000, 2)
            result["recv_len"] = len(data)
            result["recv_error"] = error
            result["recv_preview_hex"] = data[:64].hex()
            result["recv_preview_ascii"] = self._safe_ascii_preview(data[:64])
            result["recv_entropy"] = self._calculate_entropy(data) if data else 0.0
        except Exception as e:
            result["recv_error"] = f"{type(e).__name__}: {e}"
        finally:
            self._safe_close(sock)

        return result

    def _safe_ascii_preview(self, data: bytes) -> str:
        """
        将接收到的字节数据转换为可打印的 ASCII 字符，并将无法显示的字符替换为 '.'。
        """
        if not data:
            return ""
        chars = []
        for b in data:
            if 32 <= b <= 126 or b in (9, 10, 13):  # 允许 ASCII 可打印字符和一些特殊字符（如换行符、回车符、制表符）
                chars.append(chr(b))
            else:
                chars.append(".")
        return "".join(chars)

    # =========================================================
    # 判断是否为Shadowsocks
    # =========================================================
    def is_shadowsocks_behavior(self, result: Dict[str, Any]) -> bool:
        connect_latency = result.get('connect_latency_ms', 0)
        recv_len = result.get('recv_len', 0)
        recv_error = result.get('recv_error', '')
        recv_entropy = result.get('recv_entropy', 0)

        # 连接时延判断：Shadowsocks 连接时延通常较长，但不超过 300ms
        if not (100 <= connect_latency <= 500):  # 更宽松的时延判断
            return False

        # 超时或连接关闭，且熵值较高，符合加密特征
        if recv_len == 0 and ('timeout' in recv_error or 'peer_closed' in recv_error):
            if recv_entropy > 6:
                return True

        return False

    def classify_service(self, result: Dict[str, Any]) -> str:
        # 进一步排除其他加密协议
        if self.is_shadowsocks_behavior(result):
            return "Shadowsocks"
        else:
            return "Other"


# =========================================================
# 执行探测并分类
# =========================================================
def run_tests():
    profiler = ShadowsocksProbeProfiler(timeout=3.0)
    target = "127.0.0.1"
    port = 8381

    # 执行探测
    results = {
        "random_1_byte": profiler.probe_random_1_byte(target, port),
        "random_8_bytes": profiler.probe_random_8_bytes(target, port),
        "random_64_bytes": profiler.probe_random_64_bytes(target, port),
        "split_random_32": profiler.probe_split_random_32(target, port),
        "random_32_then_shutdown_wr": profiler.probe_random_32_then_shutdown_wr(target, port),
    }

    # 分类结果
    for probe_name, result in results.items():
        classification = profiler.classify_service(result)
        print(f"Probe {probe_name}: {classification} (Connect Latency: {result['connect_latency_ms']} ms, Recv Error: {result['recv_error']})")

if __name__ == "__main__":
    run_tests()
