任务说明：为逆向分析工作流的 0‑8 阶段创建编号操作计划；方法：先概述配置优先级，然后逐阶段详细说明目标、产物、I/O、配置、依赖和校验门（verification gates）。

## 计划：逆向分析流水线 阶段 0–8

TL;DR：建立一个基于配置的混和架构流水线。**Python** 作为控制器（Orchestrator），负责文件管理、HTTP 请求、流程编排和报告生成；**Node.js** 作为专用引擎，利用其丰富的生态（Babel, AST Explorer）处理 JavaScript 的解析、解混淆和结构化匹配。两者通过 `subprocess` 或本地 IPC 通信。

### 步骤
1. 在 `configs/global.yml` 中定义默认配置。
2. 完善阶段 0‑3，连接环境引导、JS 收集/解析与分析。**阶段 2 将完全采用 AST（抽象语法树）进行特征识别**。
3. **基线构建 (阶段 3)**: 脚本读取静态分析报告，生成统一的基线文件 `baseline_skeletons_{timestamp}.json`。并在 Handler 介入前完成有效 Payload 的填入（人工或自动）。
4. **Handler 验证 (阶段 4)**: 运行 Playwright 动态 Hook 读取基线中的 Payload，在浏览器中触发加密并回填真实密文；本地 Handler 读取同一基线模拟加密，比对验证通过后将基线标记为 `VERIFIED`。
5. **安全评估 (阶段 5+)**: 读取已验证的基线文件，进行变异 Fuzzing。

### 进一步考虑
1. 明确捕获目标及凭据。
2. 报告格式确认。

## 配置优先级（适用于所有阶段）
1. 从 `configs/global.yml` 加载默认值（如日志级别、存储根目录）。
2. 覆盖可选的 `configs/phases/phaseN.yml` 以进行阶段特定的调整（超时、策略开关）。
3. 最后使用 `ENV/.env` 中的敏感/运行时值进行覆盖（API 密钥、凭据、代理信息）。有效顺序：`ENV/.env` > 每阶段覆盖 > `configs/global.yml`。下面的每个脚本都应初始化共享的配置加载器（例如 `analysis/config_loader.py`）以在执行前强制此顺序。

## 阶段 0 – 环境设置

1. 目标 — 配置 Python 与 Node.js 环境，安装依赖（requests、Playwright、rich、pyyaml、@babel/parser、@babel/traverse），配置 Playwright 浏览器。
2. 关键脚本/模块 — `scripts/setup_env.ps1`（Windows）及 `scripts/setup_node.ps1`。q=
3. 输入 / 输出 — 输入：`configs/global.yml`；输出：`.venv/`、`node_modules/`（含 AST 工具）、Playwright 浏览器。
4. 配置与依赖 — 增加 Node.js 依赖管理（`npm install`）；Python 端增加 AST 互操作库（可选）。
5. 测试与校验 — 验证 `node --version`；验证 AST 解析器能否解析简单 JS；验证 Py/Node 桥接正常。

## 阶段 1 – JavaScript 收集与解混淆规范化

1. 关键脚本/模块：collect/static_analyze.py（集成解混淆流），collect/deobfuscator.js（Node 模块，负责 AST 变换）。
2. 输入/输出：输入为目标 URL；输出为**规范化/格式化后**的 JS 文件（AST Simplified），存储在 collected_js/normalized/。
3. 配置与依赖：增加解混淆策略配置（如：是否展开字符串数组、是否折叠常量）。
4. 测试与校验：确保混淆样本在经过处理后，字符串可读性提升，代码结构可被解析。

## 阶段 2 – AST 指纹与结构化加密识别

1. 关键脚本/模块：collect/ast_detect_crypto.js（Node 端 AST 匹配器），collect/static_analyze.py（集成调用）。
2. 输入/输出：输入为阶段 1 的**规范化 JS**；输出为基于 AST 节点位置的加密原语报告（含置信度）。
3. 配置与依赖：**完全使用 AST 模式匹配**（摒弃正则）。利用 Babel 遍历器识别变量流向、CryptoJS/JSEncrypt 调用特征及硬编码密钥。
4. 测试与校验：验证混淆后的 AES/RSA 算法结构能否被 AST 规则正确命中，确保无作用域误报。

## 阶段 3 – 基线骨架生成与 Payload 预填 (流程重构)

1. **目标** — 将静态分析的离散结果转换为可执行、可维护的单一基线文件，并完成测试数据的准备。
2. **基线骨架生成** — 运行 `scripts/generate_test_skeletons.py`。
   - **输入源**：`collect/static_analysis/static_analysis_{timestamp}.json` (确保使用最新分析结果)。
   - **动作**：解析 analyze 结果中的 `endpoints` 和 `endpoint_crypto_map`，提取 `details` 中的加密原语序列。
   - **输出**：`baseline_samples/baseline_skeletons_{timestamp}.json`。
   - **内容结构**：包含 `meta` (ID, URL, 算法, Hints), `pipeline_steps` (具体的加密操作链), `request` (Payload 占位符), `validation` (验证数据存储区)。初始状态 `status: "PENDING_PAYLOAD"`。
3. **Payload 填充** — Handler 验证的前提是拥有有效的输入数据。
   - **操作**：开发人员或辅助脚本编辑上述 JSON 文件，在 `request.payload` 字段填入符合 API 业务逻辑的 JSON 数据。
   - **CLI 检查**：后续工具运行时，如果发现 Payload 为空，应通过 CLI 提示用户补全，或者拒绝执行。
   - **状态流转**：Payload 填入后，状态视为 `READY_FOR_VERIFICATION`。
4. **架构意义** — 解耦了静态分析与 Handler 开发。Handler 开发者只需关注基线 JSON 文件中的 `meta` 提示和 `payload` 输入，不再需要去翻阅原始的分析日志或编写复杂的 YAML 配置。

## 阶段 4 – 动态捕获与 Handler 正确性验证

1. **目标** — 验证本地 Python Handler (还原的加密逻辑) 与浏览器端行为完全一致。
2. **输入变更** — 无论是 Playwright 动态脚本还是本地 Handler，**输入源均为阶段 3 生成的基线 JSON 文件**。不再使用 YAML 配置文件。
3. **步骤 A: 浏览器端真实密文捕获 (Truth Generation)**
   - 运行 `scripts/capture_baseline_playwright.py`。
   - 读取基线文件，提取 `url` 和 `request.payload`。
   - Playwright 打开页面，注入数据，触发加密函数，Hook 加密原语。
   - **关键动作**：捕获浏览器实际使用的 Key, IV, Nonce 以及最终生成的 **密文 (Ciphertext)**，并将其回填到基线文件的 `meta.execution_flow` (runtime_args) 和 `validation.captured_ciphertext` 字段。
   - **意义**：这一步确立了“标准答案”。即使服务器报错，只要浏览器端的加密函数执行完毕，我们就能获得用于验证本地 Handler 的数据。
4. **步骤 B: 本地 Handler 模拟与验证 (Simulation & Verify)**
   - 运行 `scripts/verify_handlers.py`。
   - 读取基线文件中的 `pipeline_steps`、`request.payload` (明文)、`meta.execution_flow` (Key/IV) 和 `validation.captured_ciphertext` (预期结果)。
   - **执行**：`BaselinePipelineRunner` 在本地复现加密流程，生成 `handler_ciphertext`。
   - **比对**：`ValidationEngine` 比较 `handler_ciphertext` 与 `captured_ciphertext`。如果一致，将基线文件的 `validation.verified` 设为 `True`，状态更新为 `VERIFIED`。这证明了本地 Handler 逻辑正确。
5. **产物** — 一个包含有效 Payload、真实密文样本且经过验证的基线文件。这是阶段 5 安全评估的信任基础。

## 阶段 5 – 安全性评估与 Fuzzing

1. **目标** — 基于已验证的 Handler（即使 Key 是动态的），构建自动化攻击载荷，探测服务器端的业务逻辑漏洞（如 SQL 注入、越权、溢出）。
2. **为什么需要 Handler？** — 服务器只有在成功解密 Payload 后才会执行 SQL/命令。如果不经加密直接发 Payload，或加密错误，请求会在网关层被拒，永远测不到业务漏洞。Handler 让我们能“合法地”发送“恶意”数据。
3. **动态 Key 处理** — 脚本需模拟浏览器的 Key 获取流程（如先发一个 `GET /token` 获取 Key，或从 HTML 解析），然后用本地 Handler + 动态 Key 加密 Payload。
4. **变异引擎 (Fuzzing)** — 读取 `VERIFIED` 的基线。
   - **载荷变异**：保持加密结构不变，修改 `payload_cleartext`（如注入 `' OR 1=1`）。
   - **重新加密**：使用 Handler 将变异后的明文重新加密。
   - **发送请求**：通过 Python `requests` 发送。无需浏览器参与，速度极快。
5. **响应分析** — 监控服务器响应（500 错误、时间延迟、异常数据），判断是否触发漏洞。

## 阶段 6 – 用例引擎与场景编排

1. 目标 — 提供可重用的场景定义（正向、负向、模糊），驱动流水线端到端执行。
2. 关键脚本/模块 — `testing/case_engine.py`（新）及 `testing/cases/*.yaml` 的场景清单；与 `replay/mutate_params.py` 和阶段 5 的输出集成。
3. 输入 / 输出 — 输入：用例定义、`configs/phases/phase6.yml`、环境切换；输出：`testing/results/{case}.json`，以及需要时的聚合 junit 风格报告。
4. 配置与依赖 — 通过 `pyyaml` 解析 YAML，调用 `pytest` 自动执行，用 `rich` 显示 CLI 界面；需要认证的用例使用 `ENV/.env` 中的令牌。
5. 测试与校验 — 添加解析用例的 pytest 测试；运行 `pytest testing/test_case_engine.py`；支持 `--list-cases` 的 dry-run 列表功能。

## 阶段 7 – 报告与利益相关方交付物

1. 目标 — 将评估数据转换为带有评分、修复建议和处理器来源的信息性 HTML/Markdown/JSON 报告。
2. 关键脚本/模块 — `report/report_builder.py`（新），统一格式化并复用 `assess/report_gen.py`；可使用 `jinja2` 模板（如需则加入依赖）。
3. 输入 / 输出 — 输入：评估结果（`assessment_results/`）、差异报告、用例输出、`configs/phases/phase7.yml`；输出：`report/reports/{timestamp}/report.{html,md,json}`，及附件（截图/HAR）。
4. 配置与依赖 — 使用 `pyyaml` 控制格式开关，`rich` 提供 CLI 预览，可选 `jinja2` 做模板化；敏感字段（如匿名化密钥）从 `ENV/.env` 获取。
5. 测试与校验 — 做快照测试（`pytest report/tests/test_report_builder.py`）；CLI 运行 `python report/report_builder.py --format all --dry-run`；通过切换阶段覆盖验证配置优先级。

## 阶段 8 – 自动化与人工比对（可选）

1. 目标 — 量化自动化发现与人工分析笔记之间的差距，并标记需跟进的差异。
2. 关键脚本/模块 — `analysis/comparison.py`（新），合并自动化输出与人工 JSON/CSV 注释；将摘要加入阶段 7 的报告。
3. 输入 / 输出 — 输入：自动化评估（`report/reports/...`）、人工注释（`docs/manual_findings.json`）、`configs/phases/phase8.yml`；输出：`analysis/comparison_summary.json`，并将差异表附加到报告中。
4. 配置与依赖 — 使用 `pyyaml` 配置加权策略，`rich` 显示控制台差异；如需更复杂分析可引入 `pandas`（在批准后加入依赖）；从 `ENV/.env` 获取分类相关密钥。
5. 测试与校验 — 使用固定数据集做单元测试；CLI 运行 `python analysis/comparison.py --auto path --manual path`；在模式不匹配时应抛出错误。

## 就绪检查表（每阶段）

1. 阶段 0 — `scripts/setup_env` 成功完成，依赖安装，`.env` 验证通过，Playwright 浏览器已配置。
2. 阶段 1 — `collect/static_analyze.py` 下载、解混淆并规范目标 JS，生成清单，配置覆盖生效。
3. 阶段 2 — `collect/ast_detect_crypto.js` 经由 `static_analyze.py` 调用生成确定性指纹，pytest 夹具通过。
4. 阶段 3 — `handlers/aes_handler.py` 通过加密向量测试，注册表导出，秘密从 `ENV/.env` 获取。
5. 阶段 4 — `runtime/playwright_hook.py` 捕获 HAR/日志并注入处理器，无头运行通过。
6. 阶段 5 — `validate/diff_harness.py` 比较基线与回放并生成明确退出码，样本差异报告存储完毕。
7. 阶段 6 — `testing/case_engine.py` 枚举并运行场景，结果归档，pytest 套件通过。
8. 阶段 7 — `report/report_builder.py` 输出 HTML/MD/JSON 报告，整合差异与用例，模板测试通过。
9. 阶段 8 — `analysis/comparison.py` 导入人工数据，生成比较摘要并回填报告。

草案已准备好—如需调整任一阶段细节或工具选择，请告知。
