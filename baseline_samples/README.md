# baseline_samples 目录说明

本目录用于存放自动生成的基线样例文件（如 baseline_skeletons_*.json）。

## 文件结构

- baseline_skeletons_*.json：数组，每个元素为一个 API 端点基线样本。

## 主要字段详细说明

- `endpoint_id`：API 端点唯一标识。
- `meta`：静态分析与执行流元信息。
  - `id`：样本唯一标识。
  - `url`：目标接口 URL。
  - `method`：HTTP 方法（如 GET/POST）。
  - `trigger_function`：前端触发函数名。
  - `crypto_algorithms`：涉及的加密算法列表。
  - `source_analysis_file`：来源静态分析文件。
  - `generated_at`：样本生成时间。
- `request`：请求体结构与 payload 字段。
  - `headers`：请求头字典。
  - `params`：URL 查询参数。
  - `body`：请求体内容（如 JSON、表单等）。
- `execution_flow`：加密与打包操作步骤（数组，每步含类型、算法、库、行号、上下文、运行参数等）。
- `runtime_args`：动态回填参数（如密钥、IV、随机数、时间戳、签名材料等）。
- `baseline_ciphertext`：基线密文（由真实前端生成）。
- `handler_ciphertext`：本地 Handler 生成密文。
- `comparison_result`：密文比对结果（如是否一致、差异说明等）。
- `status`：基线验证状态（如 success/failed/partial 等）。

> 详细字段和评分规则请参考 configs/scoring_profiles.md 或主 README。
