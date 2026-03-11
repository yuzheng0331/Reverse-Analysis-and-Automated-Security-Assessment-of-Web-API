任务说明：为逆向分析工作流的 0‑6 阶段创建编号操作计划；方法：先概述配置优先级，然后逐阶段详细说明目标、产物、I/O、配置、依赖和校验门（verification gates）。

## 计划：逆向分析流水线 阶段 0–6

TL;DR：建立一个以 **Python** 为主控制器、**Node.js** 为 AST 分析引擎的轻量化逆向分析与安全评估流水线。当前项目的核心闭环为：**静态分析 → 基线骨架生成 → Payload 预填 → Playwright 动态捕获 → Handler 本地验证 → 安全性评估 → 报告生成**。该方案更适合毕业设计场景，避免引入过多未落地的企业级中间层。

当前代码层面建议采用**两层结构**：
- **统一阶段入口层**：集中放在 `phases/` 目录，负责按阶段编排、传参和全链路一键执行；
- **核心实现层**：继续保留在 `collect/`、`scripts/`、`handlers/`、`assess/`、`runtime/` 中，减少大规模迁移风险。

### 步骤
1. 在 `configs/global.yaml` 中定义默认配置。
2. 完善阶段 0‑2，打通环境准备、JavaScript 收集/规范化和 AST 加密识别。
3. **基线构建（阶段 3）**：脚本读取最新静态分析报告，生成统一的基线文件 `baseline_skeletons_{timestamp}.json`，并在 Handler 介入前完成有效 Payload 的填入（人工或半自动）。
4. **Handler 验证（阶段 4）**：Playwright 从基线读取 Payload，在浏览器中执行真实加密并回填密文与运行时参数；本地 Handler 读取同一份基线进行模拟，比对一致后将该 API 基线标记为 `VERIFIED`。
5. **安全评估（阶段 5）**：直接基于已验证基线开展多场景安全测试，不再额外拆分“用例引擎阶段”。
6. **报告生成（阶段 6）**：汇总静态分析、Handler 验证与安全评估结果，生成最终报告；人工分析作为报告附录或补充说明，而不是独立阶段。

### 进一步考虑
1. 明确目标页面、登录方式、可测试 API 范围与合法边界。
2. 明确报告输出格式（Markdown/HTML/JSON）以及毕业设计最终展示形式。

## 配置优先级（适用于所有阶段）
1. 从 `configs/global.yaml` 加载默认值（如日志级别、输出目录、基础超时）。
2. 读取 `configs/phases_config.yaml` 中的阶段性配置或开关（如是否启用浏览器捕获、是否启用重放评估）。
3. 最后使用 `.env` 中的敏感/运行时值覆盖（如目标地址、登录凭据、代理信息）。
4. 有效顺序：`.env` > `configs/phases_config.yaml` > `configs/global.yaml`。
5. 对于**运行日志**，推荐统一通过 `phases/run_full_pipeline.py --log-file runtime/full_pipeline_utf8.log` 由 Python 内部落盘为 UTF-8；不建议把 PowerShell 的 `>` 重定向作为主日志渠道。

## 阶段 0 – 环境设置

1. 目标 — 配置 Python 与 Node.js 运行环境，安装依赖，确保 Playwright 浏览器可用。
2. 统一入口 — `phases/phase0_setup_env.ps1`。
3. 关键脚本/模块 — `scripts/setup_env.ps1`、`requirements.txt`、`package.json`。
4. 输入 / 输出 — 输入：项目源码与依赖清单；输出：`.venv/`、`node_modules/`、Playwright 浏览器运行环境。
5. 配置与依赖 — Python 侧安装 `requests`、`playwright`、`rich`、`python-dotenv` 等；Node.js 侧安装 Babel/AST 相关依赖。
6. 测试与校验 — 验证 `python --version`、`node --version`、`python -m playwright install chromium` 可正常执行。

## 阶段 1 – JavaScript 收集与解混淆规范化

1. 统一入口 — `phases/phase1_static_analysis.py`。
2. 关键脚本/模块 — `collect/static_analyze.py`、`collect/deobfuscator.js`。
3. 输入 / 输出 — 输入为目标 URL；输出为下载的原始 JS 与规范化后的 JS，存储于 `collect/collected_js/raw/` 与 `collect/collected_js/normalized/`。
4. 配置与依赖 — 支持字符串数组展开、常量折叠、基础格式化等解混淆策略。
5. 测试与校验 — 确保规范化后代码可读性提升，并可继续进入 AST 分析阶段。

## 阶段 2 – AST 指纹与结构化加密识别

1. 关键脚本/模块 — `collect/ast_detect_crypto.js`、`collect/static_analyze.py`。
2. 输入 / 输出 — 输入为阶段 1 的规范化 JS；输出为 `collect/static_analysis/static_analysis_{timestamp}.json`。
3. 配置与依赖 — 完全使用 AST 模式匹配，识别算法、原语操作、硬编码 Key/IV、派生逻辑、数据结构与端点映射。
4. 测试与校验 — 验证 AES、DES、RSA、签名、混合加密等典型模式均能输出结构化 `details`。

## 阶段 3 – 基线骨架生成与 Payload 预填

1. **目标** — 将静态分析结果整理为统一的、可直接供 Handler 与评估模块消费的基线文件。
2. **基线骨架生成** — 运行 `scripts/init_baselines.py`。
   - 推荐统一入口：`phases/phase2_prepare_baseline.py`。
   - **输入源**：`collect/static_analysis/static_analysis_{timestamp}.json`（默认读取最新文件）。
   - **动作**：解析 `endpoints` 与 `endpoint_crypto_map`，从各 API 的 `operations[].details[]` 中提取原语级步骤、运行时参数槽位、推断出的 Payload 字段以及辅助提示信息。
   - **输出**：`baseline_samples/baseline_skeletons_{timestamp}.json`。
   - **内容结构**：每个 API 对应一条基线记录，至少包含 `meta`、`request`、`validation`，其中 `meta.execution_flow` 保存精细化流水线步骤，初始状态为 `PENDING_PAYLOAD`。
3. **Payload 填充**
   - **操作**：开发者根据推断出的字段结构，在 `request.payload` 中填入有效测试数据。
   - **原则**：Payload 预填发生在 Handler 验证之前，避免 Handler 再去依赖静态分析 JSON 或额外 YAML 配置。
   - **CLI 检查**：若 `request.payload` 缺失或仍为占位值，后续脚本应提示补全或拒绝执行。
   - **状态流转**：Payload 完成后，记录可视为 `READY_FOR_VERIFICATION`。
4. **架构意义** — 统一输入源，后续 Playwright 与本地 Handler 只围绕基线 JSON 工作，降低耦合度。

## 阶段 4 – 动态捕获与 Handler 正确性验证

1. **目标** — 验证本地 Python Handler 与浏览器真实执行结果是否一致。
2. **统一输入源** — Playwright 动态脚本与 Handler 本地验证均读取阶段 3 生成的统一基线 JSON，不再额外依赖 YAML。
3. **步骤 A：浏览器端真实密文捕获**
   - 运行 `scripts/capture_baseline_playwright.py`。
   - 读取基线中的 `meta.url`、`meta.trigger_function` 和 `request.payload`。
   - Playwright 打开页面、注入输入值、触发对应 API 的前端加密逻辑，并 Hook 关键加密调用。
   - 捕获浏览器实际使用的 Key、IV、Nonce、时间戳、签名输入、最终密文等，并回填到基线 JSON 的 `meta.execution_flow.runtime_args` 与 `validation` 区域。
4. **步骤 B：本地 Handler 模拟与验证**
   - 运行 `scripts/verify_handlers.py`。
   - 读取同一份基线中的 `request.payload`、`meta.execution_flow`、`validation.captured_ciphertext`。
   - `BaselinePipelineRunner` 在本地逐步执行原语流水线，生成 `handler_ciphertext`。
   - 对 **AES / DES / HMAC** 等确定性算法，要求 `handler_ciphertext` 与 `captured_ciphertext` 一致，才将 `validation.verified` 设为 `true`。
   - 对 **RSA / AESRSA** 等包含随机填充的算法，不要求逐字节密文一致；若本地步骤链、输入、公钥与打包链路可稳定重建，则标记为 `RSA_NONDETERMINISTIC_LOGIC_VALIDATED` 并视为验证通过。
   - 对 **signdataserver** 这类“服务端返回 signature，前端只负责打包提交”的端点，不存在本地可重算的签名原语；其验证口径应为 `NO_CRYPTO`，即**最终请求体字段与运行时参数捕获正确、可重放、可篡改**。
5. **产物** — 一个包含有效 Payload、真实运行时参数、真实密文样本且经过 Handler 验证的可信基线文件。

## 阶段 5 – 安全性评估（多场景）

1. **目标** — 基于已验证的基线与本地 Handler，对 API 进行自动化安全测试，评估的不仅是 Fuzzing，还包括重放、篡改、边界值与业务异常场景。
2. **实现约束** — 保持轻量化，不引入复杂用例引擎；仅新增 `assess/common.py` 作为评估/报告共享工具层。
3. **输入基础** — 仅处理 `VERIFIED` 的基线记录，确保加密流程正确、评估结果可信。
4. **为什么需要 Handler？** — 只有请求在加密层面通过，服务器才会继续处理业务逻辑。Handler 的作用是让测试脚本能在本地重建合法加密请求，从而把攻击载荷真正送达服务端业务层。
   - 对 `signdataserver` 这类服务端签名端点，本地评估重点不在“重算 signature”，而在于：复用已捕获的 `timestamp/signature` 与最终请求体结构，继续执行协议层篡改测试。
5. **评估场景（建议至少覆盖以下几类）**
   - **场景 A：基线重放与一致性检查** — 使用原始 Payload 与运行时参数重新构造请求，确认本地模拟与线上请求结构一致。
   - **场景 B：明文参数变异/注入** — 对字段做 SQL 注入、身份替换、逻辑绕过值替换等变异。
   - **场景 C：边界值与异常值测试** — 发送空字符串、超长字符串、特殊字符、类型错配、缺字段等。
   - **场景 D：协议与加密参数篡改** — 测试 IV/Nonce/时间戳/签名/Ciphertext 的缺失、复用、旧值重放、截断、重复参数与格式破坏。
   - **场景 E：请求体回退篡改** — 若本地因基线缺口无法重建完整请求体，则回退使用 `validation.trace` 中捕获的 `FETCH body` 进行协议层篡改。
6. **执行方式**
   - 推荐统一入口：`phases/phase5_assess.py`。
   - 读取 `baseline_samples/baseline_skeletons_*.json` 中已验证的 API。
   - 对 `request.payload` 生成多种测试场景。
   - 使用本地 Handler 重新加密，并在必要时从捕获 trace 回退构造请求预览。
   - 可选择仅本地重建，或在显式启用时发送到目标端点。
   - 记录响应码、响应体、耗时、错误模式与异常行为。
7. **结果分析** — 基于响应差异、异常信息、状态码变化、时间延迟、错误提示以及业务返回结果判断潜在漏洞。
8. **说明** — 对于动态 Key/IV/Nonce 场景，可根据实际端点选择“复用捕获到的运行时参数”或“按相同步骤重新获取/刷新运行时参数”，但不再单独拆成额外阶段。
9. **评分模型** — 阶段 5 的输出应支持从 `configs/scoring_profiles.yaml` 读取可配置评分 profile，至少包含：`severity_penalties`、`finding_category_multipliers`、`scenario_status_penalties`、`scenario_category_multipliers`、`baseline_gap_penalty`。

## 阶段 6 – 报告生成与结果整理

1. **目标** — 将静态分析、Handler 验证与安全评估结果整理为毕业设计可直接引用的结果文档。
2. **关键脚本/模块** — `assess/report_gen.py`。
   - 推荐统一入口：`phases/phase6_generate_report.py`。
   - 图表生成补充脚本：`runtime/generate_profile_charts.py`。
3. **输入 / 输出**
   - 输入：静态分析结果、基线文件中的验证结果、安全评估输出。
   - 输出：Markdown / HTML / JSON 报告，以及必要的附录材料。
4. **报告建议内容**
   - 目标页面与 API 概览。
   - 已识别加密实现与关键原语流程。
   - Handler 正确性验证结果（哪些端点已通过、哪些未通过、原因是什么）。
   - 安全评估结果（按场景分类展示）。
   - 本次使用的评分 profile、权重配置快照，以及为什么采用该口径（如 `paper_v1` 用于论文展示）。
   - 人工补充分析、局限性与后续工作建议。
5. **说明** — 人工复核不再作为独立“阶段 8”，而是作为最终报告中的补充章节。

## 就绪检查表（每阶段）

1. 阶段 0 — `scripts/setup_env.ps1` 可完成依赖安装，Python / Node / Playwright 环境可用。
2. 阶段 1 — `collect/static_analyze.py` 成功收集并规范化目标 JS。
3. 阶段 2 — `collect/ast_detect_crypto.js` 可输出带 `details` 的静态分析 JSON。
4. 阶段 3 — `scripts/init_baselines.py` 能基于最新静态分析生成统一基线文件，且每个 API 均有独立记录。
5. 阶段 4 — `scripts/capture_baseline_playwright.py` 与 `scripts/verify_handlers.py` 能围绕同一份基线 JSON 完成捕获与验证。
6. 阶段 5 — `assess/assess_endpoint.py` 能读取已验证基线，完成多场景安全评估并输出结果。
7. 阶段 6 — `assess/report_gen.py` 能基于评估结果生成最终报告。
8. 一键运行 — `phases/run_full_pipeline.py` 能按阶段顺序串行执行阶段 1–6，并支持传入 `--url`、`--username`、`--password`。
9. 日志输出 — `phases/run_full_pipeline.py` 支持 `--log-file`，并能生成可直接阅读的 UTF-8 中文日志文件。

草案已更新为更适合毕业设计实现的版本；后续若继续重构代码实现，应优先保持脚本输入输出与本计划一致。
