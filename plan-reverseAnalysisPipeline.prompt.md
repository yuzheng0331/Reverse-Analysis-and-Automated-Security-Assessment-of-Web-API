任务说明：为逆向分析工作流的 0‑8 阶段创建编号操作计划；方法：先概述配置优先级，然后逐阶段详细说明目标、产物、I/O、配置、依赖和校验门（verification gates）。

## 计划：逆向分析流水线 阶段 0–8

TL;DR：建立一个基于配置的流水线，每个阶段（从环境设置到自动化与人工对比）产生结构化产物，消费前一阶段输出，并由明确的脚本、依赖和校验门支撑。强调 ENV > 每阶段 > 全局 的优先级，以便每个模块知道读取哪个配置，并为每个阶段配备轻量的 pytest 或命令检查以保持工作流可靠。

### 步骤
1. 在 `configs/global.yml` 中定义默认配置，在 `configs/phases/phaseN.yml` 中提供每阶段的覆盖，并在 `ENV/.env` 中加载敏感信息。所有脚本（如 `scripts/setup_env.ps1`、`collect/fetch_js.py`、`analysis/fingerprint.py` 等）应遵循此顺序加载配置。
2. 完善阶段 0‑3，连接环境引导、JS 收集/解析与指纹提取，确保 `handlers/aes_handler.py` 原型消费阶段 2 的输出。
3. 实现运行时拦截与校验（阶段 4‑5），通过 `runtime/playwright_hook.py` 与 `validate/diff_harness.py` 将捕获的流量与处理程序逻辑连接。
4. 完成下游编排（阶段 6‑8），包括 `testing/case_engine.py`、`report/report_builder.py` 和 `analysis/comparison.py`，为每个阶段边界添加 pytest 套件和 CLI 冒烟测试。

### 进一步考虑
1. 明确捕获目标及凭据？选项 A：本地演示目标 / 选项 B：预发布域 / 选项 C：每次运行由用户提供。
2. 在自动化阶段 7–8 导出前，确认偏好的报告格式（HTML/Markdown/JSON）和存储保留策略。

## 配置优先级（适用于所有阶段）

1. 从 `configs/global.yml` 加载默认值（如日志级别、存储根目录）。
2. 覆盖可选的 `configs/phases/phaseN.yml` 以进行阶段特定的调整（超时、策略开关）。
3. 最后使用 `ENV/.env` 中的敏感/运行时值进行覆盖（API 密钥、凭据、代理信息）。有效顺序：`ENV/.env` > 每阶段覆盖 > `configs/global.yml`。下面的每个脚本都应初始化共享的配置加载器（例如 `analysis/config_loader.py`）以在执行前强制此顺序。

## 阶段 0 – 环境设置

1. 目标 — 配置 Python 环境，安装依赖（requests、beautifulsoup4、pycryptodome、Playwright、rich、pyyaml、pytest、jsbeautifier），配置 Playwright 浏览器，生成并填充 `.env`。
2. 关键脚本/模块 — `scripts/setup_env.ps1`（Windows）/ `scripts/setup_env.sh`（POSIX）；可选帮助 `scripts/setup_common.py`。
3. 输入 / 输出 — 输入：`configs/global.yml`、`configs/phases/phase0.yml`、来自 `ENV/.env` 的秘密；输出：`.venv/`、已安装的浏览器（`playwright install`）、生成的 `.env` 模板验证日志、依赖锁定快照。
4. 配置与依赖 — 脚本通过 `pyyaml` 读取配置；通过 `dotenv` 或直接 `os.environ` 读取秘密；使用 `subprocess` 执行 pip/Playwright 任务。
5. 测试与校验 — 运行 `python -m pytest --collect-only` 确认环境正常；检查 `playwright --version`；验证 `.venv/Scripts/activate` 并确保 `pip list` 包含所需依赖。

## 阶段 1 – JavaScript 收集与解析

1. 目标 — 爬取目标 URL，下载内联/外部 JS，根据需要美化/压缩，并存储规范化的代码包以供后续分析。
2. 关键脚本/模块 — `collect/fetch_js.py`（使用 requests 进行 HTTP 获取，配合 beautifulsoup4 解析 DOM）和 `collect/parse_js.py`（AST/标记分析）；可选 `analysis/fingerprint.py` 在后续调用，确保原始数据已准备好。
3. 输入 / 输出 — 输入：来自 `configs/global.yml` 的 URL（`target.url`）或 `configs/phases/phase1.yml` 的覆盖；可选来自 `baseline_samples/` 的种子；输出：`collected_js/` 目录树，记录源 URL 与哈希的元数据清单（JSON）。
4. 配置与依赖 — `collect/fetch_js.py` 使用优先级规则加载配置；使用 `requests`、`beautifulsoup4`、在 `--beautify` 标志下使用 `jsbeautifier`；代理配置来自 `ENV/.env`。
5. 测试与校验 — 添加使用 HTTP 模拟的 pytest 夹具；CLI 冒烟运行 `python collect/fetch_js.py --url ... --dry-run` 验证下载数量；确保日志记录配置层次。

## 阶段 2 – 指纹与加密签名提取

1. 目标 — 为收集到的脚本生成确定性指纹（哈希、AST 签名），检测加密原语并跟踪版本。
2. 关键脚本/模块 — `analysis/fingerprint.py`（新），利用 `hashlib`、`pycryptodome` 进行加密检测，使用 `analysis/signature_db.py`；更新 `analysis/detect_crypto.py` 以使用指纹输出。
3. 输入 / 输出 — 输入：阶段 1 的 `collected_js/`，`configs/phases/phase2.yml` 的配置；输出：`analysis/fingerprints.json`，以及在 `analysis_results/` 中丰富的节点。
4. 配置与依赖 — 使用 `pyyaml` 读取配置，`rich` 显示进度，`pycryptodome` 做算法检查；环境秘密（例如分类开关）来自 `ENV/.env`。
5. 测试与校验 — 使用 `testing/data/` 的合成 JS 夹具对 `analysis/fingerprint.py` 进行单元测试；确认指纹可确定性复现；确保在缺少签名数据库时脚本失败并给出清晰错误。

## 阶段 3 – 处理器（Handler）原型开发

1. 目标 — 构建模块化处理器，能够复刻客户端加密（先从 AES 原型开始），并为其他算法准备存根。
2. 关键脚本/模块 — `handlers/aes_handler.py`（实现与检测到模式相匹配的加解密），`handlers/__init__.py` 注册表，以及在 `analysis/detect_crypto.py` 中的集成钩子。
3. 输入 / 输出 — 输入：阶段 2 的指纹与检测到的配置，`configs/phases/phase3.yml`；输出：处理器注册表元数据，以及序列化的处理器配置 `runtime/handlers.json`。
4. 配置与依赖 — 处理器从 `ENV/.env`（最高优先级）加载 key/IV 种子，使用 `pycryptodome` 实现 AES，使用 `pyyaml` 做覆盖配置；日志路径来自 `configs/global.yml`。
5. 测试与校验 — 添加 `testing/test_aes_handler.py` 的 pytest 测试验证示例 JS 的加解密往返；通过 `pytest -k handler` 做静态集成；手动 CLI `python -m handlers.aes_handler --vector sample.json` 做快速验证。

## 阶段 4 – Playwright 钩子与运行时拦截

1. 目标 — 拦截浏览器流量，注入处理器，并捕获用于回放的实时参数。
2. 关键脚本/模块 — `runtime/playwright_hook.py`（基于 Playwright，监听 request/response 事件），并与 `replay/replay_request.py` 集成。
3. 输入 / 输出 — 输入：阶段 3 的处理器配置，来自 `configs/phases/phase4.yml` 的 URL 覆盖；输出：`runtime/session_logs/`、捕获的 HAR 文件、以及丰富的基线样本。
4. 配置与依赖 — 使用 Playwright API（`async_playwright`），从 `ENV/.env` 读取代理/认证；对回退检查使用 `requests` 的 HEAD 请求；通过配置加载器遵循配置优先级。
5. 测试与校验 — 运行无头冒烟测试 `python runtime/playwright_hook.py --dry-run`；捕获示例 HAR 并确保存储；添加 `pytest-asyncio` 的异步测试模拟 Playwright 事件；与基线进行差异确认。

## 阶段 5 – 差异（Diff）测试台与回放验证

1. 目标 — 对比基线与变异的请求/响应，验证处理器输出一致性。
2. 关键脚本/模块 — `validate/diff_harness.py`（新），协调差异比对，钩入 `replay/replay_request.py` 和 `replay/mutate_params.py`。
3. 输入 / 输出 — 输入：基线（`baseline_samples/`）、回放产物（`replay_results/`）、配置 `configs/phases/phase5.yml`；输出：带有通过/失败元数据的 `validate/diff_reports/`，以及控制台摘要。
4. 配置与依赖 — 使用 `pyyaml` 配置运行阈值，`rich` 表格显示差异，必要时加入 `deepdiff`；从 `ENV/.env` 获取需要忽略的敏感字段（如 auth tokens）。
5. 测试与校验 — 使用样本基线/响应进行单元测试；CLI 运行 `python validate/diff_harness.py --baseline ... --replay ...`；确保退出代码反映差异状态以便 CI 使用。

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
2. 阶段 1 — `collect/fetch_js.py` 与 `collect/parse_js.py` 下载并规范目标 JS，生成清单，配置覆盖生效。
3. 阶段 2 — `analysis/fingerprint.py` 生成确定性指纹并正确使用签名数据库，pytest 夹具通过。
4. 阶段 3 — `handlers/aes_handler.py` 通过加密向量测试，注册表导出，秘密从 `ENV/.env` 获取。
5. 阶段 4 — `runtime/playwright_hook.py` 捕获 HAR/日志并注入处理器，无头运行通过。
6. 阶段 5 — `validate/diff_harness.py` 比较基线与回放并生成明确退出码，样本差异报告存储完毕。
7. 阶段 6 — `testing/case_engine.py` 枚举并运行场景，结果归档，pytest 套件通过。
8. 阶段 7 — `report/report_builder.py` 输出 HTML/MD/JSON 报告，整合差异与用例，模板测试通过。
9. 阶段 8 — `analysis/comparison.py` 导入人工数据，生成比较摘要并回填报告。

草案已准备好—如需调整任一阶段细节或工具选择，请告知。
