# baseline_samples 目录说明

本目录用于存放统一基线样例（`baseline_skeletons_*.json`）。

## 结构总览

- 文件顶层：数组，每个元素表示一个端点样本。
- 样本顶层字段：`meta`、`status`、`request`、`validation`。

## 字段说明（当前实现）

### 1) `meta`

- `id`：端点 ID（如 `aes`、`signdataserver`）。
- `url` / `method` / `trigger_function`：端点基础信息。
- `crypto_algorithms`：静态分析识别到的算法标签。
- `source_analysis_file`：来源静态分析文件名。
- `execution_flow`：可执行步骤数组（`init`/`derive_*`/`encrypt`/`sign`/`pack` 等）。
- `hints`：排障辅助上下文。

### 2) `request`

- `payload`：业务明文字段模板（用户填值）。
- `headers`：默认请求头模板。

### 3) `validation`

- `verified`：阶段4校验状态。
- `runtime_params`：运行时关键参数（key/iv/nonce/timestamp/signature/message 等）。
- `trace`：动态捕获轨迹（重点是 `FETCH`）。
- `captured_ciphertext`：浏览器侧捕获密文（如有）。
- `handler_ciphertext`：本地 handler 生成密文（如有）。
- `comparison_result`：阶段4比对结果。
- `dynamic`：动态端点两段式判定信息。
  - `hint`（阶段2静态提示）
    - `is_dynamic`
    - `needs_server_intermediate`
    - `dynamic_fields`
    - `reasons`
    - `server_intermediate_calls`
    - `hint_version`
  - `observed`（阶段3动态实证）
    - `observed`
    - `observed_dynamic_fields`
    - `strong_dynamic_fields`
    - `runtime_param_keys`
    - `fetch_urls`
    - `has_server_intermediate_fetch`
    - `capture_types`
    - `captured_at`
    - `observe_version`

## 字段复用与去重建议（谨慎）

以下字段看起来“重复”，但当前仍有不同用途，建议先保留：

1. `validation.dynamic.hint` vs `validation.dynamic.observed`
- 前者是静态提示（阶段2），后者是动态实证（阶段3）。
- 阶段5应同时使用，避免仅凭单侧信息误判。
- 实践中建议把 `nonce/timestamp/signature/token/random` 视为强动态字段；`key/iv/message` 视为弱动态字段，需要结合 hint/observed 共同判定。

2. `validation.runtime_params` vs `validation.trace`
- `runtime_params` 便于计算与快速读取。
- `trace` 用于回溯与请求体回退构造。

3. `captured_ciphertext` vs `handler_ciphertext`
- 分别表示浏览器真实产物与本地模拟产物，不能互相替代。

## 可安全精简的方向（不建议立即删除）

- `hints` 可做长度裁剪（不影响功能，仅影响可读性）。
- `trace` 可在归档时做瘦身（保留 `FETCH` + 摘要），但在线评估阶段建议保留全量。

> 建议采用“先标记弃用、后迁移删除”的策略，不要直接删字段。

