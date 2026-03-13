# report 目录说明

本目录用于存放最终报告及可视化产物。

## 文件结构

- report_profile_*.json：结构化报告结果，每份为一次完整评估的详细 JSON。
- report_profile_*.md / report_*.md：Markdown 格式的报告文本。
- report_profile_*.html：可视化 HTML 报告。
- charts/：评估相关的图表图片（如覆盖率、风险分布等）。

## 主要字段详细说明（以 report_profile_*.json 为例）

- `report_id`：报告唯一标识。
- `generated_at`：报告生成时间。
- `executive_summary`：总体摘要说明。
- `overall_score`：总体得分。
- `protocol_score`：协议安全得分。
- `business_score`：业务安全得分。
- `assessed_endpoints`：评估端点数量。
- `findings_total`：发现问题总数。
- `verified_entries`：已验证条目数。
- `workflow_summary`：评估流程摘要（含输入文件、模式、配置等）。
- `remote_summary`：远程验证摘要（场景数、响应数、错误数、状态码统计等）。
- `endpoint_details`：各端点详细评估结果（数组，每项含端点 ID、得分、发现项、建议等）。
- `findings`：全局发现项列表（含类型、描述、严重性、建议等）。
- `charts`：图表数据（如覆盖率、风险分布等）。

> 详细字段和评分规则请参考 configs/scoring_profiles.md 或主 README。
