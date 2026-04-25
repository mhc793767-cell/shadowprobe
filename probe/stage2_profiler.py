import socket
import time
import os
import json
import math
from collections import Counter, defaultdict
from statistics import mean
from typing import Dict, Any, Optional, Tuple, List

class Stage2SilentBinaryProfiler:
    """
    第二阶段细分探针：
    面向第一阶段已经被归到 unknown_encrypted_binary 的静默型候选端口，
    继续做非法首包 / 分片 / 半关闭行为采样。
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

    # =========================================================
    # 核心执行器
    # =========================================================
    def _connect_only(self, ip: str, port: int) -> Dict[str, Any]:
        sock = None
        started = time.perf_counter()
        try:
            sock = self._create_socket()
            sock.connect((ip, port))
            ended = time.perf_counter()
            return {
                "connected": True,
                "connect_latency_ms": round((ended - started) * 1000, 2),
            }
        except Exception as e:
            return {
                "connected": False,
                "error": f"{type(e).__name__}: {e}",
            }
        finally:
            self._safe_close(sock)

    def _send_recv_pattern(
        self,
        ip: str,
        port: int,
        payload_parts: List[bytes],
        sleeps_between_parts: Optional[List[float]] = None,
        shutdown_wr_after_send: bool = False,
        wait_before_recv: float = 0.1,
    ) -> Dict[str, Any]:
        sock = None
        started = time.perf_counter()
        sleeps_between_parts = sleeps_between_parts or []

        try:
            sock = self._create_socket()
            sock.connect((ip, port))
            connect_done = time.perf_counter()

            total_sent = 0
            send_events = []

            for idx, part in enumerate(payload_parts):
                sent = sock.send(part)
                total_sent += sent
                send_events.append({
                    "part_index": idx,
                    "planned_len": len(part),
                    "actual_sent_len": sent,
                })

                if idx < len(sleeps_between_parts):
                    time.sleep(sleeps_between_parts[idx])

            shutdown_error = None
            if shutdown_wr_after_send:
                try:
                    sock.shutdown(socket.SHUT_WR)
                except Exception as e:
                    shutdown_error = f"{type(e).__name__}: {e}"

            time.sleep(wait_before_recv)
            data, recv_error = self._recv_once(sock)
            ended = time.perf_counter()

            return {
                "connected": True,
                "connect_latency_ms": round((connect_done - started) * 1000, 2),
                "roundtrip_ms": round((ended - started) * 1000, 2),
                "payload_parts": len(payload_parts),
                "send_events": send_events,
                "sent_len": total_sent,
                "shutdown_wr_after_send": shutdown_wr_after_send,
                "shutdown_error": shutdown_error,
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
                "shutdown_wr_after_send": shutdown_wr_after_send,
            }
        finally:
            self._safe_close(sock)

    # =========================================================
    # 第二阶段探针
    # =========================================================
    def probe_random_1_byte(self, ip: str, port: int) -> Dict[str, Any]:
        payload = os.urandom(1)
        result = self._send_recv_pattern(ip, port, [payload], wait_before_recv=0.1)
        result["probe_name"] = "random_1_byte"
        return result

    def probe_random_8_bytes(self, ip: str, port: int) -> Dict[str, Any]:
        payload = os.urandom(8)
        result = self._send_recv_pattern(ip, port, [payload], wait_before_recv=0.1)
        result["probe_name"] = "random_8_bytes"
        return result

    def probe_random_64_bytes(self, ip: str, port: int) -> Dict[str, Any]:
        payload = os.urandom(64)
        result = self._send_recv_pattern(ip, port, [payload], wait_before_recv=0.1)
        result["probe_name"] = "random_64_bytes"
        return result

    def probe_split_random_32(self, ip: str, port: int) -> Dict[str, Any]:
        payload = os.urandom(32)
        part1 = payload[:5]
        part2 = payload[5:]
        result = self._send_recv_pattern(
            ip,
            port,
            [part1, part2],
            sleeps_between_parts=[0.2],
            wait_before_recv=0.1,
        )
        result["probe_name"] = "split_random_32"
        return result

    def probe_random_32_then_shutdown_wr(self, ip: str, port: int) -> Dict[str, Any]:
        payload = os.urandom(32)
        result = self._send_recv_pattern(
            ip,
            port,
            [payload],
            shutdown_wr_after_send=True,
            wait_before_recv=0.1,
        )
        result["probe_name"] = "random_32_then_shutdown_wr"
        return result

    def run_all_probes(self, ip: str, port: int) -> Dict[str, Any]:
        return {
            "connect_only": self._connect_only(ip, port),
            "random_1_byte": self.probe_random_1_byte(ip, port),
            "random_8_bytes": self.probe_random_8_bytes(ip, port),
            "random_64_bytes": self.probe_random_64_bytes(ip, port),
            "split_random_32": self.probe_split_random_32(ip, port),
            "random_32_then_shutdown_wr": self.probe_random_32_then_shutdown_wr(ip, port),
        }


# =========================================================
# 结果保存与汇总
# =========================================================
def save_result_jsonl(path: str, result: Dict[str, Any]) -> None:
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(result, ensure_ascii=False) + "\n")


def summarize_stage2(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    grouped = defaultdict(list)
    for row in rows:
        key = (row["target"], row["probe_name"])
        grouped[key].append(row)

    summaries = []
    for (target, probe_name), items in grouped.items():
        real_label = items[0].get("real_label", "-")

        connect_ok = sum(1 for x in items if x.get("connected"))
        recv_errors = Counter(x.get("recv_error", None) for x in items)
        recv_lens = [x.get("recv_len", 0) for x in items]
        conn_lat = [x.get("connect_latency_ms") for x in items if x.get("connect_latency_ms") is not None]
        rtt = [x.get("roundtrip_ms") for x in items if x.get("roundtrip_ms") is not None]

        summaries.append({
            "target": target,
            "real_label": real_label,
            "probe_name": probe_name,
            "rounds": len(items),
            "connect_ok_count": connect_ok,
            "avg_connect_latency_ms": round(mean(conn_lat), 3) if conn_lat else None,
            "avg_roundtrip_ms": round(mean(rtt), 3) if rtt else None,
            "avg_recv_len": round(mean(recv_lens), 3) if recv_lens else 0.0,
            "timeout_count": recv_errors.get("timeout", 0),
            "peer_closed_count": recv_errors.get("peer_closed", 0),
            "connection_reset_count": recv_errors.get("connection_reset", 0),
            "none_error_count": recv_errors.get(None, 0),
        })

    summaries.sort(key=lambda x: (x["target"], x["probe_name"]))
    return summaries


def print_stage2_summary(summaries: List[Dict[str, Any]]) -> None:
    print("=" * 170)
    print("STAGE2 SUMMARY")
    print("=" * 170)
    print(
        f"{'target':<18} {'real_label':<18} {'probe_name':<28} {'rounds':<6} "
        f"{'conn_ok':<8} {'avg_conn_ms':<12} {'avg_rtt_ms':<12} {'avg_recv_len':<12} "
        f"{'timeout':<8} {'peer_closed':<12} {'conn_reset':<11} {'recv_ok_none':<12}"
    )
    for s in summaries:
        print(
            f"{s['target']:<18} "
            f"{s['real_label']:<18} "
            f"{s['probe_name']:<28} "
            f"{s['rounds']:<6} "
            f"{s['connect_ok_count']:<8} "
            f"{str(s['avg_connect_latency_ms']):<12} "
            f"{str(s['avg_roundtrip_ms']):<12} "
            f"{str(s['avg_recv_len']):<12} "
            f"{s['timeout_count']:<8} "
            f"{s['peer_closed_count']:<12} "
            f"{s['connection_reset_count']:<11} "
            f"{s['none_error_count']:<12}"
        )


def summarize_stage2_by_target(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    grouped = defaultdict(list)
    for row in rows:
        grouped[row["target"]].append(row)

    summaries: List[Dict[str, Any]] = []
    for target, items in grouped.items():
        real_label = items[0].get("real_label", "-")
        by_probe = defaultdict(list)
        for item in items:
            by_probe[item["probe_name"]].append(item)

        random_probe_names = ["random_1_byte", "random_8_bytes", "random_64_bytes", "split_random_32"]
        random_items = [x for name in random_probe_names for x in by_probe.get(name, [])]
        shutdown_items = by_probe.get("random_32_then_shutdown_wr", [])
        connect_items = by_probe.get("connect_only", [])

        timeout_count = sum(1 for x in random_items if x.get("recv_error") == "timeout")
        peer_closed_count = sum(1 for x in shutdown_items if x.get("recv_error") == "peer_closed")
        random_rtt = [x.get("roundtrip_ms") for x in random_items if x.get("roundtrip_ms") is not None]
        split_rtt = [x.get("roundtrip_ms") for x in by_probe.get("split_random_32", []) if x.get("roundtrip_ms") is not None]
        shutdown_rtt = [x.get("roundtrip_ms") for x in shutdown_items if x.get("roundtrip_ms") is not None]
        connect_latency = [x.get("connect_latency_ms") for x in connect_items if x.get("connect_latency_ms") is not None]

        summaries.append({
            "target": target,
            "real_label": real_label,
            "rounds": len(connect_items),
            "random_timeout_ratio": round(timeout_count / len(random_items), 3) if random_items else 0.0,
            "shutdown_peer_closed_ratio": round(peer_closed_count / len(shutdown_items), 3) if shutdown_items else 0.0,
            "avg_random_rtt_ms": round(mean(random_rtt), 3) if random_rtt else None,
            "avg_split_rtt_ms": round(mean(split_rtt), 3) if split_rtt else None,
            "avg_shutdown_rtt_ms": round(mean(shutdown_rtt), 3) if shutdown_rtt else None,
            "avg_connect_only_latency_ms": round(mean(connect_latency), 3) if connect_latency else None,
        })

    summaries.sort(key=lambda x: x["target"])
    return summaries


def infer_stage2_subfamily(summary: Dict[str, Any]) -> Dict[str, Any]:
    """
    第二层细分：
    对 unknown_encrypted_binary 目标做实验室内“候选家族”细分评分。
    说明：
    - 只做实验室行为簇细分，不代表协议确认。
    - 若分值接近，则保持 manual_review。
    """
    scores = {
        "native_aead_like": 0.20,
        "outline_like": 0.20,
        "ss2022_like": 0.20,
    }
    evidence: List[str] = []

    timeout_ratio = summary.get("random_timeout_ratio", 0.0)
    peer_closed_ratio = summary.get("shutdown_peer_closed_ratio", 0.0)
    avg_split_rtt = summary.get("avg_split_rtt_ms")
    avg_random_rtt = summary.get("avg_random_rtt_ms")
    avg_shutdown_rtt = summary.get("avg_shutdown_rtt_ms")
    avg_connect = summary.get("avg_connect_only_latency_ms")

    if timeout_ratio >= 0.95:
        scores["outline_like"] += 0.12
        scores["ss2022_like"] += 0.12
        evidence.append("随机探针超时比例高（>=95%），偏向静默型候选")

    if peer_closed_ratio >= 0.95:
        scores["native_aead_like"] += 0.14
        scores["outline_like"] += 0.08
        evidence.append("半关闭写端后 peer_closed 稳定出现（>=95%）")

    if avg_split_rtt is not None and avg_random_rtt is not None:
        split_gap = avg_split_rtt - avg_random_rtt
        if split_gap >= 180:
            scores["native_aead_like"] += 0.06
            scores["outline_like"] += 0.06
            evidence.append("分片探针相对随机探针存在显著额外时延")

    if avg_split_rtt is not None:
        # 基于当前实验室样本库的经验分界，建议后续按真实样本动态校准
        if avg_split_rtt <= 3304.8:
            scores["outline_like"] += 0.25
            evidence.append("split_random_32 平均 RTT 偏低，倾向 outline_like")
        else:
            scores["native_aead_like"] += 0.20
            evidence.append("split_random_32 平均 RTT 偏高，倾向 native_aead_like")

    if avg_connect is not None:
        if avg_connect <= 0.35:
            scores["outline_like"] += 0.12
            evidence.append("connect_only 平均连接时延较低")
        elif avg_connect >= 0.50:
            scores["native_aead_like"] += 0.12
            evidence.append("connect_only 平均连接时延较高")

    if avg_shutdown_rtt is not None:
        if avg_shutdown_rtt <= 100.95:
            scores["outline_like"] += 0.08
            evidence.append("shutdown 后关闭时延偏低")
        elif avg_shutdown_rtt >= 101.00:
            scores["native_aead_like"] += 0.08
            evidence.append("shutdown 后关闭时延偏高")

    total = sum(max(v, 0.0) for v in scores.values())
    if total <= 0:
        normalized = {k: 0.0 for k in scores}
    else:
        normalized = {k: round(max(v, 0.0) / total, 4) for k, v in scores.items()}

    ranked = sorted(normalized.items(), key=lambda kv: kv[1], reverse=True)
    top_family, top_score = ranked[0]
    second_score = ranked[1][1] if len(ranked) > 1 else 0.0
    margin = round(top_score - second_score, 4)

    needs_manual_review = (top_score < 0.50) or (margin < 0.10)
    return {
        "subfamily_scores": normalized,
        "stage2_top_family": top_family,
        "stage2_top_score": top_score,
        "stage2_margin": margin,
        "stage2_needs_manual_review": needs_manual_review,
        "stage2_evidence": evidence,
    }


def print_stage2_subdivision(rows: List[Dict[str, Any]]) -> None:
    summaries = summarize_stage2_by_target(rows)
    print("=" * 170)
    print("STAGE2 SUBDIVISION (for unknown_encrypted_binary candidates)")
    print("=" * 170)
    print(
        f"{'target':<18} {'real_label':<18} {'pred_subfamily':<22} {'score':<8} "
        f"{'margin':<8} {'manual_review':<14} {'native':<8} {'outline':<8} {'ss2022':<8}"
    )
    for summary in summaries:
        infer = infer_stage2_subfamily(summary)
        scores = infer["subfamily_scores"]
        print(
            f"{summary['target']:<18} "
            f"{summary['real_label']:<18} "
            f"{infer['stage2_top_family']:<22} "
            f"{infer['stage2_top_score']:<8} "
            f"{infer['stage2_margin']:<8} "
            f"{str(infer['stage2_needs_manual_review']):<14} "
            f"{scores.get('native_aead_like', 0.0):<8} "
            f"{scores.get('outline_like', 0.0):<8} "
            f"{scores.get('ss2022_like', 0.0):<8}"
        )

        if infer["stage2_evidence"]:
            print(f"  evidence: {'; '.join(infer['stage2_evidence'])}")


def print_one_result_brief(row: Dict[str, Any]) -> None:
    print("-" * 120)
    print(
        f"round={row.get('round_id')} "
        f"target={row.get('target')} "
        f"real_label={row.get('real_label')} "
        f"probe={row.get('probe_name')}"
    )
    print(
        f"connected={row.get('connected')} "
        f"connect_latency_ms={row.get('connect_latency_ms')} "
        f"roundtrip_ms={row.get('roundtrip_ms')} "
        f"sent_len={row.get('sent_len')} "
        f"recv_len={row.get('recv_len')} "
        f"recv_error={row.get('recv_error')} "
        f"shutdown_wr_after_send={row.get('shutdown_wr_after_send')}"
    )
    print(
        f"recv_preview_hex={row.get('recv_preview_hex')} "
        f"recv_preview_ascii={row.get('recv_preview_ascii')}"
    )


def flatten_run_result(
    target: str,
    real_label: str,
    round_id: int,
    run_result: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    rows = []

    for probe_name, probe_result in run_result.items():
        flat = {
            "target": target,
            "real_label": real_label,
            "round_id": round_id,
            "probe_name": probe_name,
        }
        flat.update(probe_result)
        rows.append(flat)

    return rows


def main():
    profiler = Stage2SilentBinaryProfiler(timeout=3.0)

    targets = [
        ("native_aead_like", "127.0.0.1", 8381),
        ("native_aead_like", "127.0.0.1", 8389),
        ("outline_like", "127.0.0.1", 8390),
    ]

    output_file = "stage2_results.jsonl"
    if os.path.exists(output_file):
        os.remove(output_file)

    all_rows: List[Dict[str, Any]] = []

    for round_id in range(1, 6):
        print(f"\n######## STAGE2 ROUND {round_id} ########\n")
        for real_label, ip, port in targets:
            target = f"{ip}:{port}"
            run_result = profiler.run_all_probes(ip, port)
            rows = flatten_run_result(target, real_label, round_id, run_result)

            for row in rows:
                print_one_result_brief(row)
                save_result_jsonl(output_file, row)
                all_rows.append(row)

    summaries = summarize_stage2(all_rows)
    print()
    print_stage2_summary(summaries)
    print()
    print_stage2_subdivision(all_rows)


if __name__ == "__main__":
    main()
