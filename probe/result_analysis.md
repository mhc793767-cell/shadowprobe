# 结果文档分析（lab + stage2）

## 1. 样本与实验结构
- `lab_results.jsonl` 共 30 条记录，覆盖 6 个目标端口，每个目标 5 轮。
- `stage2_results.jsonl` 共 90 条记录，覆盖 3 个目标端口（8381、8389、8390），每个目标 5 轮、每轮 6 种探针。

## 2. Lab 结果（分类层）

### 2.1 可明确识别的服务
从 `analyze_results.py` 的汇总口径看：
- `127.0.0.1:8080` 稳定识别为 `plain_http`（5/5），平均分约 0.95。
- `127.0.0.1:8443` 稳定识别为 `tls_service`（5/5），平均分约 0.85。
- `127.0.0.1:1080` 稳定识别为 `socks5_service`（5/5），平均分约 0.95。

这说明明文协议（HTTP/TLS/SOCKS5）的探测特征足够强，分类器区分度高。

### 2.2 加密类服务的现状
- `127.0.0.1:8381`（real_label: native_aead_like）
- `127.0.0.1:8389`（real_label: native_aead_like）
- `127.0.0.1:8390`（real_label: outline_like）

以上 3 个目标在 5/5 轮都被归到 `unknown_encrypted_binary`，且全部被标记 `needs_manual_review=true`。

这说明当前探针可可靠判断“不是 HTTP/TLS/SOCKS5，且表现为加密二进制协议”，但无法在 `native_aead_like` 与 `outline_like` 之间做自动细分。

## 3. Stage2 结果（行为层）

### 3.1 高一致性的行为模式
三个目标（8381/8389/8390）在 Stage2 中行为几乎一致：
- `connect_only`: 始终连接成功。
- `random_1_byte` / `random_8_bytes` / `random_64_bytes` / `split_random_32`: 全部表现为 `recv_error=timeout`。
- `random_32_then_shutdown_wr`: 全部表现为 `recv_error=peer_closed`，且 roundtrip 约 100ms。

结论：这 3 个目标在“随机字节刺激 + 半关闭写端”下的响应形态高度同质，难以仅凭当前 active probe 区分协议家族。

### 3.2 时延特征
- `connect_latency_ms` 整体较低（大多 <1ms，首轮个别点略高）。
- timeout 类探针 roundtrip 稳定在约 3.1s（split 版本约 3.3s）。
- shutdown 写端后 peer closed 的 roundtrip 稳定在约 100ms。

这些数值稳定，说明测试环境噪声较小、复现实验可靠，但也侧面说明“现有特征不具可分性”。

## 4. 关键结论
1. **第一层检测能力已具备**：可稳定识别并排除 HTTP/TLS/SOCKS5。
2. **第二层细分能力不足**：`native_aead_like` 与 `outline_like` 在当前特征空间里重叠严重。
3. **手工复核机制是必要兜底**：对于加密二进制流量，`needs_manual_review` 触发逻辑目前合理。

## 5. 下一步优化建议（按优先级）
1. **扩展 challenge-response 探针**：增加更接近真实握手前置字节模式的“结构化无效报文”，观测是否出现差异化关闭策略。
2. **引入连接生命周期特征**：例如连续小包节奏、RST/FIN 时序、首个可见关闭方向与延迟分布。
3. **做多轮统计判别而非单轮阈值**：以目标为单位汇聚 5~10 轮，使用方差/分位数而非均值单点判断。
4. **将 stage2 特征反馈到分类器**：把 timeout/peer_closed 的模式稳定性编码为新特征，形成“可解释 + 可学习”的二阶段模型。

## 6. 风险提示
- 结果基于本地回环环境（`127.0.0.1`），在真实公网链路上可能出现更大时延抖动、丢包重传与中间设备行为，需要复测后再固化阈值。
