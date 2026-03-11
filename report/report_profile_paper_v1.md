# Web API 前端加密逆向与安全评估报告

- **报告 ID**: ASM-20260311175234
- **生成时间**: 2026-03-11T17:52:34.701522+00:00

## 执行摘要

共评估 8 个已验证端点。本次评估共发现 3 个严重问题，需要优先修复。从当前自动化结果看，整体风险处于中等水平。

## 工作流摘要

- Baseline: `D:\Reverse Analysis and Automated Security Assessment of Web API\baseline_samples\baseline_skeletons_20260311_175214.json`
- Static Analysis: `D:\Reverse Analysis and Automated Security Assessment of Web API\collect\static_analysis\static_analysis_20260311_175214.json`
- 真实请求发送: False
- 超时设置: 10.0 秒
- 评分 Profile: `paper_v1`
- 评分配置文件: `D:\Reverse Analysis and Automated Security Assessment of Web API\configs\scoring_profiles.yaml`

## 评分配置

- Profile: `paper_v1`
- 说明: 论文展示版评分模型，平衡密码学缺陷、场景执行质量与结构化基线完整性。
- 配置文件: `D:\Reverse Analysis and Automated Security Assessment of Web API\configs\scoring_profiles.yaml`
- 基础分: 100.0
- 基线缺口惩罚: 每项 2.5，累计上限 12.0

**风险阈值**
- `low`: 85.0
- `medium`: 65.0
- `high`: 45.0

**严重级别扣分**
- `critical`: 28.0
- `high`: 18.0
- `medium`: 9.0
- `low`: 4.0
- `info`: 0.0

**发现类别系数**
- `default`: 1.0
- `cryptography`: 1.3
- `authentication`: 1.15
- `configuration`: 0.9

**场景状态扣分**
- `LOCAL_FAILED`: 1.8
- `SKIPPED`: 1.6
- `LOCAL_OK`: 0.0
- `REMOTE_SENT`: 0.0

**场景类别系数**
- `default`: 1.0
- `baseline_replay`: 0.9
- `plaintext_mutation`: 1.15
- `boundary_anomaly`: 0.85
- `payload_structure_variation`: 0.95
- `crypto_protocol_tamper`: 1.25
- `auth_context_variation`: 1.05

## 基线验证摘要

- 总基线数: 8
- 验证通过: 8

**Status 分布**
- VERIFIED: 8

**Comparison 分布**
- 严格匹配: 4
- RSA/AESRSA 非确定性密文，逻辑验证通过: 2
- 无前端加密，仅完成请求打包: 2

## 静态分析上下文

- 目标页面: `http://encrypt-labs-main/easy.php`
- 分析时间: 2026-03-11T17:52:08.659711+00:00
- 端点总数: 8
- 加密模式数: 20
- 安全发现数: 2

## 评估统计

| 指标 | 数值 |
|---|---:|
| 总体评分 | 77.98 |
| 评估端点数 | 8 |
| 发现总数 | 4 |
| 验证通过 | 8 |

## 端点结果

| Endpoint ID | URL | 评分 | 风险 | 算法 | 发现 | 场景状态 |
|---|---|---:|---|---|---|---|
| aes | http://encrypt-labs-main/encrypt/aes.php | 34.2 | critical | AES, PayloadPacking | 前端存在硬编码密钥或固定密钥材料<br>存在固定或可预测的 IV | baseline_replay:LOCAL_OK<br>plaintext_mutation_sqli:LOCAL_OK<br>boundary_empty_string:LOCAL_OK<br>boundary_long_string:LOCAL_OK<br>special_chars_payload:LOCAL_OK<br>auth_context_variation:LOCAL_OK<br>payload_type_confusion:LOCAL_OK<br>payload_missing_field:LOCAL_OK<br>crypto_remove_security_field:LOCAL_OK<br>crypto_stale_timestamp:SKIPPED<br>crypto_signature_corruption:SKIPPED<br>crypto_ciphertext_truncate:LOCAL_OK<br>crypto_duplicate_timestamp:SKIPPED |
| aesserver | http://encrypt-labs-main/encrypt/aesserver.php | 94.0 | low | AES, PayloadPacking | 无 | baseline_replay:LOCAL_OK<br>plaintext_mutation_sqli:LOCAL_OK<br>boundary_empty_string:LOCAL_OK<br>boundary_long_string:LOCAL_OK<br>special_chars_payload:LOCAL_OK<br>auth_context_variation:LOCAL_OK<br>payload_type_confusion:LOCAL_OK<br>payload_missing_field:LOCAL_OK<br>crypto_remove_security_field:LOCAL_OK<br>crypto_stale_timestamp:SKIPPED<br>crypto_signature_corruption:SKIPPED<br>crypto_ciphertext_truncate:LOCAL_OK<br>crypto_duplicate_timestamp:SKIPPED |
| rsa | http://encrypt-labs-main/encrypt/rsa.php | 92.47 | low | PayloadPacking, RSA | 无 | baseline_replay:LOCAL_OK<br>plaintext_mutation_sqli:LOCAL_OK<br>boundary_empty_string:LOCAL_OK<br>boundary_long_string:LOCAL_FAILED<br>special_chars_payload:LOCAL_OK<br>auth_context_variation:LOCAL_OK<br>payload_type_confusion:LOCAL_OK<br>payload_missing_field:LOCAL_OK<br>crypto_remove_security_field:LOCAL_OK<br>crypto_stale_timestamp:SKIPPED<br>crypto_signature_corruption:SKIPPED<br>crypto_ciphertext_truncate:LOCAL_OK<br>crypto_duplicate_timestamp:SKIPPED |
| aesrsa | http://encrypt-labs-main/encrypt/aesrsa.php | 94.0 | low | AES, PayloadPacking, RSA | 无 | baseline_replay:LOCAL_OK<br>plaintext_mutation_sqli:LOCAL_OK<br>boundary_empty_string:LOCAL_OK<br>boundary_long_string:LOCAL_OK<br>special_chars_payload:LOCAL_OK<br>auth_context_variation:LOCAL_OK<br>payload_type_confusion:LOCAL_OK<br>payload_missing_field:LOCAL_OK<br>crypto_remove_security_field:LOCAL_OK<br>crypto_stale_timestamp:SKIPPED<br>crypto_signature_corruption:SKIPPED<br>crypto_ciphertext_truncate:LOCAL_OK<br>crypto_duplicate_timestamp:SKIPPED |
| des | http://encrypt-labs-main/encrypt/des.php | 55.6 | high | DES, PayloadPacking | 使用弱加密算法 DES | baseline_replay:LOCAL_OK<br>plaintext_mutation_sqli:LOCAL_OK<br>boundary_empty_string:LOCAL_OK<br>boundary_long_string:LOCAL_OK<br>special_chars_payload:LOCAL_OK<br>auth_context_variation:LOCAL_OK<br>payload_type_confusion:LOCAL_OK<br>payload_missing_field:LOCAL_OK<br>crypto_remove_security_field:SKIPPED<br>crypto_stale_timestamp:SKIPPED<br>crypto_signature_corruption:SKIPPED<br>crypto_ciphertext_truncate:LOCAL_OK<br>crypto_duplicate_timestamp:SKIPPED |
| signdata | http://encrypt-labs-main/encrypt/signdata.php | 61.6 | high | HmacSHA256, HmacSHA256(), PayloadPacking | 前端存在硬编码密钥或固定密钥材料 | baseline_replay:LOCAL_OK<br>plaintext_mutation_sqli:LOCAL_OK<br>boundary_empty_string:LOCAL_OK<br>boundary_long_string:LOCAL_OK<br>special_chars_payload:LOCAL_OK<br>auth_context_variation:LOCAL_OK<br>payload_type_confusion:LOCAL_OK<br>payload_missing_field:LOCAL_OK<br>crypto_remove_security_field:LOCAL_OK<br>crypto_stale_timestamp:LOCAL_OK<br>crypto_signature_corruption:LOCAL_OK<br>crypto_ciphertext_truncate:LOCAL_OK<br>crypto_duplicate_timestamp:SKIPPED |
| signdataserver | http://encrypt-labs-main/encrypt/signdataserver.php | 98.0 | low | PayloadPacking | 无 | baseline_replay:LOCAL_OK<br>plaintext_mutation_sqli:LOCAL_OK<br>boundary_empty_string:LOCAL_OK<br>boundary_long_string:LOCAL_OK<br>special_chars_payload:LOCAL_OK<br>auth_context_variation:LOCAL_OK<br>payload_type_confusion:LOCAL_OK<br>payload_missing_field:LOCAL_OK<br>crypto_remove_security_field:LOCAL_OK<br>crypto_stale_timestamp:LOCAL_OK<br>crypto_signature_corruption:LOCAL_OK<br>crypto_ciphertext_truncate:LOCAL_OK<br>crypto_duplicate_timestamp:SKIPPED |
| norepeater | http://encrypt-labs-main/encrypt/norepeater.php | 94.0 | low | PayloadPacking | 无 | baseline_replay:LOCAL_OK<br>plaintext_mutation_sqli:LOCAL_OK<br>boundary_empty_string:LOCAL_OK<br>boundary_long_string:LOCAL_OK<br>special_chars_payload:LOCAL_OK<br>auth_context_variation:LOCAL_OK<br>payload_type_confusion:LOCAL_OK<br>payload_missing_field:LOCAL_OK<br>crypto_remove_security_field:LOCAL_OK<br>crypto_stale_timestamp:SKIPPED<br>crypto_signature_corruption:SKIPPED<br>crypto_ciphertext_truncate:LOCAL_OK<br>crypto_duplicate_timestamp:SKIPPED |

## 基线缺口与回溯建议

未检测到明显的基线结构缺口。

## 局限性与后续建议

- 本次评估默认未发起真实请求，场景结果以本地重建能力与基线缺口分析为主。
