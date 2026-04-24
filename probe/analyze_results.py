import json
from collections import defaultdict, Counter
from statistics import mean


def load_jsonl(path: str):
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def safe_get(d, *keys, default=None):
    cur = d
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur


def summarize_by_target(rows):
    grouped = defaultdict(list)
    for row in rows:
        grouped[row["target"]].append(row)

    summaries = []

    for target, items in grouped.items():
        real_label = items[0].get("real_label", "-")

        top_family_counter = Counter(item.get("top_family", "-") for item in items)
        manual_review_counter = Counter(item.get("needs_manual_review", False) for item in items)

        connect_latencies = [
            item.get("connect_latency_ms")
            for item in items
            if item.get("connect_latency_ms") is not None
        ]

        http_positive = sum(
            1 for item in items
            if safe_get(item, "observations", "http", "looks_like_http", default=False)
        )
        tls_success = sum(
            1 for item in items
            if safe_get(item, "observations", "tls", "tls_handshake_success", default=False)
        )
        socks5_positive = sum(
            1 for item in items
            if safe_get(item, "observations", "socks5", "looks_like_socks5", default=False)
        )
        idle_silent = sum(
            1 for item in items
            if safe_get(item, "observations", "idle", "silent", default=False)
        )
        random_timeout = sum(
            1 for item in items
            if safe_get(item, "observations", "random_probe", "recv_error", default=None) == "timeout"
        )

        top_scores = [item.get("top_score", 0.0) for item in items]

        summaries.append({
            "target": target,
            "real_label": real_label,
            "rounds": len(items),
            "top_family_mode": top_family_counter.most_common(1)[0][0],
            "top_family_count": top_family_counter.most_common(1)[0][1],
            "manual_review_true_count": manual_review_counter.get(True, 0),
            "avg_connect_latency_ms": round(mean(connect_latencies), 3) if connect_latencies else None,
            "avg_top_score": round(mean(top_scores), 3) if top_scores else None,
            "http_positive_count": http_positive,
            "tls_success_count": tls_success,
            "socks5_positive_count": socks5_positive,
            "idle_silent_count": idle_silent,
            "random_timeout_count": random_timeout,
        })

    summaries.sort(key=lambda x: x["target"])
    return summaries


def print_summary_table(summaries):
    print("=" * 150)
    print("TARGET SUMMARY")
    print("=" * 150)
    print(
        f"{'target':<18} {'real_label':<20} {'rounds':<6} {'pred_mode':<26} "
        f"{'pred_cnt':<8} {'manual_T':<9} {'avg_score':<10} {'avg_conn_ms':<12} "
        f"{'http+':<6} {'tls+':<6} {'socks5+':<8} {'idle_silent':<12} {'rand_timeout':<13}"
    )
    for s in summaries:
        print(
            f"{s['target']:<18} "
            f"{s['real_label']:<20} "
            f"{s['rounds']:<6} "
            f"{s['top_family_mode']:<26} "
            f"{s['top_family_count']:<8} "
            f"{s['manual_review_true_count']:<9} "
            f"{s['avg_top_score']:<10} "
            f"{s['avg_connect_latency_ms']:<12} "
            f"{s['http_positive_count']:<6} "
            f"{s['tls_success_count']:<6} "
            f"{s['socks5_positive_count']:<8} "
            f"{s['idle_silent_count']:<12} "
            f"{s['random_timeout_count']:<13}"
        )


def main():
    path = "lab_results.jsonl"
    rows = load_jsonl(path)
    summaries = summarize_by_target(rows)
    print_summary_table(summaries)


if __name__ == "__main__":
    main()
