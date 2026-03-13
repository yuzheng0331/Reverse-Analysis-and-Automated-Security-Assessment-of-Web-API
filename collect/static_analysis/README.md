# collect/static_analysis 目录说明

本目录用于存放静态分析阶段的结果产物。

## 文件结构

- static_analysis_*.json：每份为一次静态分析的详细 JSON 结果。

## 主要字段详细说明

- `target_url`：分析目标的主 URL。
- `analyzed_at`：分析时间。
- `summary`：分析摘要统计。
  - `total_files`：分析的文件数。
  - `total_endpoints`：识别的端点数。
  - `total_crypto_patterns`：识别的加密模式数。
  - `total_functions`：识别的函数数。
  - `total_security_findings`：发现的安全问题数。
- `collected_files`：收集到的 JS 文件信息（数组，每项含 type/url/file_path/size/hash 等）。
- `endpoints`：识别到的 API 端点信息（数组，每项含 URL、方法、参数、加密模式等）。
- `crypto_patterns`：识别到的加密模式（如算法、调用链、关键参数等）。
- `functions`：分析到的函数信息（如名称、位置、调用关系等）。
- `security_findings`：静态分析发现的安全问题（如弱加密、硬编码密钥、可疑调用等）。
- `analysis_flow`：静态分析执行流程（如 AST 步骤、依赖关系等）。

> 详细字段和算法映射请参考主 README 或 configs/scoring_profiles.md。
