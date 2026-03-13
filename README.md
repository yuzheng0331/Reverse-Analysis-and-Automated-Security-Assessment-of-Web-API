# 🔒 Reverse Analysis and Automated Security Assessment of Web API

一个面向毕业设计场景的 Web API 前端加密逆向与自动化安全评估流水线。

当前项目采用**统一基线 JSON** 作为主线数据结构，完整闭环为：

**静态分析 → 基线骨架生成 → Payload 预填 → Playwright 动态捕获 → Handler 本地验证 → 安全性评估 → 报告与图表生成**

最终答辩版对外口径统一为：
- **项目统一入口**：`main.py`
- **内部阶段编排层**：`phases/`
- **核心实现层**：`collect/`、`scripts/`、`handlers/`、`assess/`、`runtime/`

---

## 1. 项目目标

本项目主要解决以下问题：

1. 收集并规范化前端 JavaScript，识别页面触发的 API 与加密逻辑。
2. 通过 AST 静态分析提取原语级步骤，包括 `init`、`setkey`、`setiv`、`encrypt`、`sign`、`derive_*`、`pack` 等。
3. 基于静态分析结果生成统一基线文件，一个静态分析结果对应一个 `baseline_skeletons_*.json`，其中包含多个 API 基线记录。
4. 在基线中预填有效 Payload，使后续浏览器捕获与 Handler 验证使用同一输入源。
5. 通过 Playwright Hook 捕获真实运行时参数与密文，回填 Key / IV / Nonce / 时间戳 / 签名材料等信息。
6. 用本地 Handler 逐步模拟加密过程并校验正确性。
7. 在已验证基线上执行多场景安全评估，覆盖重放、参数变异、边界值、协议参数篡改等测试；评估模式分为**本地预评估**与**真实目标验证**两种。
8. 输出结构化报告与图表，供毕业设计展示与论文撰写使用；报告会同时区分离线预评估结果与在线验证结果。

---

## 2. 当前推荐架构

当前代码层面采用**两层结构**：

### 2.1 统一阶段入口层
集中放在 `phases/` 目录，负责：
- 按阶段编排
- 统一参数入口
- 串行执行完整链路
- 降低脚本散落带来的使用成本

### 2.2 核心实现层
核心实现继续保留在以下目录中：
- `collect/`
- `scripts/`
- `handlers/`
- `assess/`
- `runtime/`

这样做的好处是：
- 不需要大规模迁移旧代码
- 兼容当前已有实现
- 对外入口统一，对内职责仍清晰

---

## 3. 工作流总览

```mermaid
graph TD
    A[阶段1: 静态分析] --> B[collect/static_analysis/static_analysis_*.json]
    B --> C[阶段2: 基线骨架生成与Payload预填]
    C --> D[baseline_samples/baseline_skeletons_*.json]
    D --> E[阶段3: Playwright动态捕获]
    E --> F[回填 captured_ciphertext / runtime_params]
    F --> G[阶段4: Handler验证]
    G --> H{是否验证通过}
    H -->|是| I[VERIFIED 基线]
    H -->|否| J[修正 Handler / 静态分析 / 基线]
    I --> K[阶段5: 安全评估]
    K --> K1[5A: 本地预评估]
    K --> K2[5B: 真实目标验证]
    K1 --> L[assessment_results/*.json]
    K2 --> L
    L --> M[阶段6: 报告与图表生成]
    M --> N[report/*.html / *.md / *.json / charts/*.png]
```

---

## 4. 推荐入口

### 4.1 一键全链路（推荐）
```bash
python main.py --url http://encrypt-labs-main/easy.php --username admin --password 123456
```

说明：
- 这是**最终答辩版推荐说法**：从项目根目录 `main.py` 进入。
- `main.py` 内部会转发到 `phases/run_full_pipeline.py`。

### 4.1.1 推荐日志方式（避免 PowerShell 重定向乱码）
```bash
python main.py --url http://encrypt-labs-main/easy.php --username admin --password 123456 --log-file runtime/full_pipeline_utf8.log
```

说明：
 - 推荐使用 `--log-file` 让总控入口在 Python 内部按 **UTF-8** 写日志。
 - 不建议依赖 PowerShell 的 `>` / `2>&1` 做主日志，因为 Windows 下这类重定向常会生成 UTF-16/控制台编码混杂日志，看起来像“中文乱码”或夹杂空字符。

### 4.1.2 启用阶段5真实目标验证（可选）
```bash
python main.py --url http://encrypt-labs-main/easy.php --username admin --password 123456 --phase5-send --phase5-timeout 10
```

说明：
- 默认情况下，阶段5运行**本地预评估**，不会把评估场景真正发送到目标 API。
- 开启 `--phase5-send` 后，阶段5会进入**真实目标验证**模式，把本地重建/变异后的请求真正发往目标端点。
- `--phase5-timeout` 用于控制阶段5真实发包的超时时间。

### 4.1.3 内部阶段入口（用于开发与调试）
```bash
python phases/run_full_pipeline.py --url http://encrypt-labs-main/easy.php --username admin --password 123456
```

说明：
- `phases/` 是**内部阶段编排层**。
- 日常开发、单阶段调试可以直接使用 `phases/` 下入口。

---

## 5. 各阶段入口与核心实现映射

| 阶段 | 推荐入口 | 核心实现 |
|---|---|---|
| Phase 0 | `phases/phase0_setup_env.ps1` | `scripts/setup_env.ps1` |
| Phase 1 | `phases/phase1_static_analysis.py` | `collect/static_analyze.py` |
| Phase 2 | `phases/phase2_prepare_baseline.py` | `scripts/init_baselines.py` |
| Phase 3 | `phases/phase3_capture.py` | `scripts/capture_baseline_playwright.py` |
| Phase 4 | `phases/phase4_verify_handlers.py` | `scripts/verify_handlers.py` |
| Phase 5 | `phases/phase5_assess.py` | `assess/assess_endpoint.py` |
| Phase 6 | `phases/phase6_generate_report.py` | `assess/report_gen.py`、`runtime/generate_profile_charts.py` |

说明：
- `phases/` 目录是新的**统一阶段入口层**。
- 原来的 `collect/`、`scripts/`、`assess/`、`runtime/` 中脚本现在主要作为**核心实现层**保留。

---

## 6. 验证口径说明

### 6.1 确定性算法
如：
- AES
- DES
- HMAC

要求：
- `handler_ciphertext` 与 `captured_ciphertext` 严格一致
- 验证结果标记为 `MATCH`

### 6.2 非确定性密文算法
如：
- RSA
- AESRSA

要求：
- 不强求逐字节密文一致
- 只要原语链路、输入、公钥和打包流程正确，就可标记为：
  - `RSA_NONDETERMINISTIC_LOGIC_VALIDATED`

### 6.3 服务端签名 / 前端仅打包端点
如：
- `signdataserver`
- `norepeater`

要求：
- 不按“本地重算签名值”验证
- 重点验证最终请求体字段组装与运行时参数回填
- 验证结果标记为：
  - `NO_CRYPTO`

补充说明：
- `PayloadPacking` 在报告中按“流水线步骤”处理，不作为加密算法展示。

---

## 7. 安全评估说明

基于已验证的基线进行多场景测试，当前重点包括：

- 基线重放
- 明文参数注入 / 语义变异
- 空值 / 超长值 / 特殊字符 / 类型错配 / 缺字段
- 协议参数篡改（IV / Nonce / 时间戳 / 签名 / 密文字段）
- 请求体回退篡改（必要时回退使用 `validation.trace` 中捕获的 `FETCH body`）

RSA 场景补充：
- 本地 Handler 对超长 RSA 明文采用分块加密，避免因 `Plaintext is too long` 直接导致场景本地失败。
- 分块仅用于评估阶段提升覆盖率；是否被服务端接受仍以后续真实响应为准。

### 7.1 阶段5双模式：本地预评估 vs 真实目标验证

当前项目对阶段5采用双模式口径：

1. **5A：本地预评估（默认）**
   - 不真实发网。
   - 重点验证：场景是否可构造、协议字段是否可篡改、请求是否可被本地稳定重建。
   - 适合做：协议层脆弱性分析、自动化覆盖率分析、基线缺口识别。

2. **5B：真实目标验证（启用 `--send` / `--phase5-send`）**
   - 将阶段5构造出的场景真正发送到目标 API。
   - 重点观察：HTTP 状态码、响应体、错误模式、耗时差异、服务端是否接受重放/篡改请求。
   - 适合做：真实漏洞确认、服务端校验行为验证、在线攻击场景效果判断。

因此：
- 前四个阶段的核心价值，是建立“**合法请求重构能力**”。
- 阶段5A回答“**这个攻击请求我能否稳定构造出来**”。
- 阶段5B回答“**服务器是否真的会接受或拒绝这个攻击请求**”。

### 7.2 “动态验证” 与 “真实请求发送” 的区别

这两个概念在当前项目里不是一回事：

1. **阶段 3 Playwright 动态捕获**
   - 一定运行在真实浏览器页面环境中。
   - 目的是触发前端 JS，加密、签名、组包，并捕获密文与运行时参数。
   - 这一阶段属于**动态验证 / 动态捕获**，并不是报告里 `send_requests` 字段的含义。

2. **阶段 5 安全评估真实请求发送**
   - 指的是评估阶段是否把本地重建或变异后的请求，真正发送到目标 API。
   - 由 `assess/assess_endpoint.py --send` 控制。
   - 如果未开启，则报告中会显示：`安全评估阶段真实请求发送: False`。

因此：
- 你看到“动态验证成功”，说明阶段 3 已经在真实浏览器中拿到了运行时密文/参数。
- 你看到报告里“真实请求发送: False”，只表示阶段 5 默认没有把评估场景真正发到服务器。

### 7.3 SKIPPED 的含义

报告中的 `SKIPPED` 不是泛泛地“没跑”，而是**当前场景具备明确跳过原因**，例如：
- JSON 请求体无法表达重复字段
- 当前请求体里找不到要篡改的目标字段
- 缺少可用请求体，无法执行协议篡改

最终报告的场景状态会直接显示为：
- `crypto_duplicate_timestamp: SKIPPED（原因: JSON 请求体无法自然表达重复字段。）`

评分配置来自：
- `configs/scoring_profiles.yaml`

当前内置 profile：
- `default`
- `crypto_focus`
- `paper_v1`

论文展示推荐：
- `paper_v1`

评分说明文档：
- `configs/scoring_profiles.md`

双分制评分补充：
- 评估结果除 `overall_score` 外，还会输出：
  - `protocol_score`（协议层风险分）
  - `business_score`（业务层风险分）
- 双分制权重来自 `configs/scoring_profiles.yaml` 的 `layer_score_weights`。

错误语义聚类补充：
- 阶段5会对响应模式做语义归类（如 `APP_INVALID_INPUT`、`APP_MISSING_DATA`、`APP_DECRYPT_FAIL`、`APP_SUCCESS`），并输出端点级失败画像。

---

## 8. 图表输出

阶段 6 会同步生成 9 张图表，输出到：
- `report/charts/`

包括：
1. `workflow_overview.png`
2. `validation_comparison_distribution.png`
3. `endpoint_security_scores.png`
4. `profile_score_comparison.png`
5. `scenario_status_distribution.png`
6. `remote_execution_overview.png`
7. `remote_http_status_distribution.png`
8. `endpoint_remote_coverage.png`
9. `scenario_response_mode_heatmap.png`

其中新增的在线评估图表重点对应阶段5真实目标验证：
- `remote_execution_overview.png`：在线验证执行总览
- `remote_http_status_distribution.png`：HTTP 状态码分布
- `endpoint_remote_coverage.png`：各端点在线验证覆盖情况
- `scenario_response_mode_heatmap.png`：场景类别到响应模式的热力图

---

## 9. 目录结构

```text
.
├── assess/                         # 安全评估与报告生成核心实现
├── baseline_samples/               # 统一基线文件
├── collect/                        # 静态分析与 AST 检测核心实现
├── configs/                        # 全局配置、阶段配置、评分配置
├── handlers/                       # 本地 Handler 与流水线执行框架
├── phases/                         # 统一阶段入口层（推荐从这里执行）
│   ├── common.py
│   ├── phase0_setup_env.ps1
│   ├── phase1_static_analysis.py
│   ├── phase2_prepare_baseline.py
│   ├── phase3_capture.py
│   ├── phase4_verify_handlers.py
│   ├── phase5_assess.py
│   ├── phase6_generate_report.py
│   └── run_full_pipeline.py
├── report/                         # 最终报告与图表输出
├── replay/                         # 参数变异与请求重放辅助模块
├── runtime/                        # 运行时辅助文件（Playwright Hook、图表脚本、UTF-8 日志）
│   ├── playwright_hook.js
│   ├── generate_profile_charts.py
│   └── full_pipeline_utf8.log
├── scripts/                        # 仍被 phases 调用的核心实现脚本（非推荐直接入口）
│   ├── init_baselines.py
│   ├── capture_baseline_playwright.py
│   ├── verify_handlers.py
│   └── setup_env.ps1
├── main.py                         # 项目对外统一入口（最终答辩版从这里进入）
├── plan-reverseAnalysisPipeline.prompt.md
├── README.md
└── requirements.txt
```

---

## 9.1 脚本功能说明（用于“内容与实施方案”撰写）

### 顶层入口

- `main.py`
  - 项目对外统一入口。
  - 内部调用 `phases/run_full_pipeline.py` 组织全流程执行。

### 阶段编排层（`phases/`）

- `phases/phase0_setup_env.ps1`
  - 环境初始化入口，安装依赖并准备运行环境。
- `phases/phase1_static_analysis.py`
  - 执行静态分析，产出 `collect/static_analysis/static_analysis_*.json`。
- `phases/phase2_prepare_baseline.py`
  - 基于最新静态分析生成统一基线骨架（多端点同文件）。
- `phases/phase3_capture.py`
  - 调用 Playwright 动态捕获，回填运行时参数与密文。
- `phases/phase4_verify_handlers.py`
  - 使用本地 Handler 对基线逐端点进行正确性验证。
- `phases/phase5_assess.py`
  - 执行安全评估场景（本地预评估 / 在线真实发送）。
- `phases/phase6_generate_report.py`
  - 汇总 assessment 结果，生成报告与图表。
- `phases/run_full_pipeline.py`
  - 一键串联阶段1-6，供全链路执行。

### 核心实现层（`scripts/`、`collect/`、`assess/`、`runtime/`）

- `scripts/init_baselines.py`
  - 读取 `collect/static_analysis/` 最新结果，生成 `baseline_samples/baseline_skeletons_*.json`。
  - 负责 `packing_info` 的结构归一化（含 `field_sources`、`value_derivations`）。
- `scripts/capture_baseline_playwright.py`
  - 浏览器端触发各 API，捕获加密过程与 `fetch` 请求体，回填基线验证区。
- `scripts/verify_handlers.py`
  - 以统一基线为输入运行 Handler 流水线，并回写验证状态与比对结果。

- `collect/ast_detect_crypto.js`
  - AST 级别识别加密原语步骤与请求打包逻辑。
  - 输出 `details`，供后续构造 `execution_flow` 使用。
- `collect/static_analyze.py`
  - 聚合静态分析结果，建立“端点 -> 算法/操作/调用痕迹”映射。

- `assess/assess_endpoint.py`
  - 评估引擎核心：场景构造、请求篡改、可选真实发送、风险评分。
  - 产出双分制评分（`overall_score`、`protocol_score`、`business_score`）与错误语义聚类。
- `assess/report_gen.py`
  - 读取 assessment + baseline + static analysis，生成 HTML/Markdown/JSON 报告。

- `runtime/playwright_hook.js`
  - 浏览器注入 Hook，捕获前端加密输入输出、密钥材料与网络请求信息。
- `runtime/generate_profile_charts.py`
  - 从评估结果生成论文展示图表（含响应模式热力图）。

### Handler 执行层（`handlers/`）

- `handlers/pipeline.py`
  - 将单端点基线转为可执行流水线，按 step 执行。
- `handlers/operations.py`
  - 各原语实现（AES/DES/RSA/HMAC 等）与派生逻辑执行。
- `handlers/validator.py`
  - 校验流程产物与规则约束，支撑阶段4验证。
- `handlers/registry.py`
  - 原语注册与查找中心。
- `handlers/handlers.md`
  - Handler 设计说明、验证口径与边界条件文档。

---

## 10. 环境准备

### Python / Node / Playwright
```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
npm install
python -m playwright install chromium
```

### PowerShell 快速初始化
```powershell
.\phases\phase0_setup_env.ps1
```

---

## 11. 当前建议的使用方式

如果你只是想跑毕业设计主链路，推荐固定使用：

- 用户名：`admin`
- 密码：`123456`
- URL：`http://encrypt-labs-main/easy.php`

直接执行：
```bash
python main.py --url http://encrypt-labs-main/easy.php --username admin --password 123456
```
 
 如果需要保存可读日志，推荐：
```bash
python main.py --url http://encrypt-labs-main/easy.php --username admin --password 123456 --log-file runtime/full_pipeline_utf8.log
```

---

## 12. 当前注意事项

1. `baseline_samples/` 中可能存在临时验证文件（如 `.tmp_verify.json`），正式运行时优先使用正式基线文件。
2. 对外展示时推荐统一表述为：`main.py` 是项目入口，`phases/` 是内部阶段编排层。
3. 旧脚本目录仍保留，是为了兼容与复用核心实现；日常答辩展示不建议直接从 `scripts/` 进入。
4. 如果某个阶段失败，应优先回溯前一阶段产物，而不是跳过继续执行。
5. 如果需要保留运行日志，请优先使用 `--log-file runtime/full_pipeline_utf8.log`，不要把 PowerShell 重定向日志作为主日志来源。
6. 阶段5默认是**本地预评估**；若需要得到服务器响应并做真实目标验证，必须显式开启 `--phase5-send` 或在 `phases/phase5_assess.py` 中使用 `--send`。
7. 如果 Markdown/IDE 对 README 的目录锚点有警告，一般不影响项目实际运行。

---

## 13. 相关说明文档

- 总体阶段计划：`plan-reverseAnalysisPipeline.prompt.md`
- Handler 说明：`handlers/handlers.md`
- 评分配置说明：`configs/scoring_profiles.md`

---

## 14. 一句话总结

现在推荐的实际使用方式是：
 
> **对外从 `main.py` 进入；内部由 `phases/` 串行编排完整链路；旧目录中的脚本继续作为核心实现保留。**

---

## 产物结构说明

本项目各阶段产物结构与字段解释，详见各目录下的说明文档：

- [assessment_results/README.md](assessment_results/README.md)：安全评估结果产物结构说明
- [baseline_samples/README.md](baseline_samples/README.md)：基线样本产物结构说明
- [collect/static_analysis/README.md](collect/static_analysis/README.md)：静态分析产物结构说明
- [report/README.md](report/README.md)：最终报告与图表产物结构说明

如需了解各阶段产物的详细结构、字段含义及用途，请查阅对应目录下的说明文档。

---

