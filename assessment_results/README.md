# assessment_results 目录说明

本目录用于存放安全评估阶段的结果产物，主要为各类评估报告的 JSON 文件。

## 文件结构

- assessment_profile_*.json：每份为一次评估的完整结构化结果。

## 主要字段详细说明

- `report_id`：报告唯一标识。
- `generated_at`：报告生成时间。
- `source`：评估所用的输入源信息。
  - `baseline_file`：基线样本文件路径。
  - `static_analysis_file`：静态分析结果文件路径。
  - `send_requests`：阶段5是否真实发包。
  - `timeout_seconds`：请求超时时间。
  - `scoring_profile`：评分配置名。
  - `scoring_config_file`：评分配置文件路径。
- `scoring`：评分相关配置与参数。
  - `profile`：评分模型名。
  - `description`：评分模型说明。
  - `config_file`：评分配置文件路径。
  - `base_score`：基础分。
  - `risk_thresholds`：风险等级阈值（low/medium/high）。
  - `severity_penalties`：各严重性扣分（critical/high/medium/low/info）。
  - `finding_category_multipliers`：各类发现项分数系数。
- `endpoint_results`：各端点评估结果（数组，每个元素为单端点评估详情）。
  - `endpoint_id`：端点唯一标识。
  - `score`：端点得分。
  - `findings`：发现项列表（含类型、描述、严重性、建议等）。
  - `test_cases`：各类测试用例结果（如重放、变异、边界值等）。
- `summary`：评估摘要统计。
  - `overall_score`：总体得分。
  - `protocol_score`：协议安全得分。
  - `business_score`：业务安全得分。
  - `assessed_endpoints`：评估端点数量。
  - `findings_total`：发现问题总数。
  - `verified_entries`：已验证条目数。
- `workflow_summary`：评估流程摘要（含输入文件、模式、配置等）。
- `remote_summary`：远程验证摘要（场景数、响应数、错误数、状态码统计等）。

> 详细字段和评分规则请参考 configs/scoring_profiles.md 或主 README。
