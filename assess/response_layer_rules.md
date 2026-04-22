# 三层判定规则说明（阶段5）

本文档说明 `assess/assess_endpoint.py` 中阶段5的响应判定规则，包含：
- 协议层（Protocol）
- 结构层（Structure）
- 语义层（Semantic）
- 三层融合后的 `response_mode`
- 与场景预期（`expected_outcome`）的命中关系

补充：阶段5现已采用统一门控口径，不再区分“严格/非严格”模式。

---

## 1. 判定入口与执行顺序

阶段5每个场景在远程请求后，会生成 `remote_result`，随后按以下顺序判定：

1. `build_response_layers(remote_result)`
   - 协议层：`_response_protocol_layer`
   - 结构层：`_response_structure_layer`
   - 语义层：`_response_semantic_layer`
2. `classify_response_mode(remote_result)`
   - 三层融合得到最终 `response_mode`
3. `evaluate_scenario_expectation(...)`
   - 将实际结果与场景 `expected_outcome` 对比，生成 `matched`

---

## 2. 协议层规则（Protocol）

输入：`remote_result`

判定逻辑：

- `attempted != true` -> `NOT_ATTEMPTED`
- `error` 非空 -> `TRANSPORT_ERROR`
- `status_code >= 500` -> `SERVER_5XX`
- `status_code >= 400` -> `HTTP_4XX`
- `status_code >= 200` -> `HTTP_2XX`
- 其他状态码 -> `HTTP_OTHER`
- 无可用状态码 -> `HTTP_UNKNOWN`

说明：
- 协议层只看传输与 HTTP，不看业务语义。

---

## 3. 结构层规则（Structure）

输入：`remote_result.body_preview`

判定逻辑：

- 空响应体 -> `BODY_EMPTY`
- 可解析为 JSON 对象：
  - 若 key 集合包含 `success/error/code/message` 任一 -> `JSON_APP_STRUCTURED`
  - 否则 -> `JSON_OBJECT`
- 可解析为 JSON 数组 -> `JSON_ARRAY`
- 非 JSON：
  - 包含 `<html` 或 `<body` -> `HTML_TEXT`
  - 其他文本 -> `PLAIN_TEXT`

说明：
- 结构层用于描述“长什么样”，不直接代表安全结论。

---

## 4. 语义层规则（Semantic）

输入：`remote_result.body_preview`

### 4.1 优先匹配的失败关键词

按优先级依次匹配（先命中先返回）：

1. `APP_INVALID_INPUT`
   - 命中关键词：
     - `invalid input`
     - `invalid username`
     - `signature mismatch`
2. `APP_MISSING_DATA`
   - 命中关键词：
     - `no data`
     - `missing`
3. `APP_DECRYPT_FAIL`
   - 命中关键词：
     - `decrypt`
     - `解密失败`
     - `解密`

### 4.2 JSON 结构化语义

若响应体可解析为 JSON 对象：

- `success is True` -> `APP_SUCCESS`
- `success is False` -> `APP_REJECTED`
- `code in {0, "0", 200, "200"}` -> `APP_SUCCESS`
- `status in {ok, success, passed}` -> `APP_SUCCESS`
- `message/msg` 包含 `success/ok/passed/成功` -> `APP_SUCCESS`

### 4.3 非 JSON 兜底

- 文本包含 `"success":true` -> `APP_SUCCESS`
- 文本包含 `"success":false` -> `APP_REJECTED`
- 文本包含 `ok` 或 `passed` -> `APP_SUCCESS`
- 否则 -> `UNKNOWN`

说明：
- 当前版本已明确把 `{"success":false}` 归类为 `APP_REJECTED`，避免误判为成功。

---

## 5. 三层融合规则（response_mode）

函数：`classify_response_mode(remote_result)`

融合优先级：

1. 协议硬失败优先返回：
   - `NOT_ATTEMPTED`
   - `TRANSPORT_ERROR`
   - `SERVER_5XX`
2. 若语义层可判定（非 `UNKNOWN`），返回语义层结果
3. 若语义未知：
   - 协议层是 `HTTP_4XX` -> `HTTP_4XX`
   - 协议层是 `HTTP_2XX` -> `HTTP_OK_OTHER`
4. 其他情况 -> `UNKNOWN`

---

## 6. 与场景预期的命中规则

函数：`evaluate_scenario_expectation(...)`

对比项：

1. 远程模式匹配
   - `remote_mode_match = actual_remote_mode in expected_remote_modes`
2. 三层规则匹配（可选）
   - `response_layer_match = OR(response_layer_any_of)`

最终命中：

- 若两者都配置：`matched = remote_mode_match OR response_layer_match`
- 若只配置其一：以该项为准
- 若都未配置：`matched = None`

说明：
- 当前项目口径中，本地失败类型仅做备注，不直接参与 `matched` 判定。

---

## 6.1 场景门控状态（发送前）

阶段5先进行门控，再决定是否发送：

- `UNMUTATABLE`：场景无法变异，不发送，不计预期未命中。
- `MUTATION_NOT_EFFECTIVE`：变异未落地到最终请求包，不发送，不计预期未命中。
- `RUNTIME_DEP_MISSING`：动态端点允许基于阶段3 capture 请求体继续发送；发送后按远程命中规则判定，未命中可扣分。

---

## 7. 推荐配置建议（面向泛化）

为了兼顾不同站点响应风格，建议：

- 变异场景 `expected_remote_modes` 至少包含：
  - `APP_INVALID_INPUT`
  - `APP_MISSING_DATA`
  - `APP_DECRYPT_FAIL`
  - `APP_REJECTED`
  - `HTTP_4XX`
  - `HTTP_OK_OTHER`
- 若目标站点业务语义明显，可增加 `response_layer_any_of` 作为补充命中条件。

---

## 8. 调试建议

建议结合 `scripts/debug_endpoint_packets.py` 查看：

- `scenario_packets[*].response_packet.remote_result.response_layers`
- `scenario_packets[*].response_packet.remote_result.response_mode`
- `scenario_packets[*].response_packet.expectation`
- `scenario_packets[*].response_packet.judgement`

这样可以快速定位：
- 是请求没发出去（协议层）
- 还是响应可解析但语义未命中（结构/语义层）
- 还是预期配置过严（expected_outcome）

