# handlers 模块职责与协作流程

结合当前项目实现，`handlers` 模块的定位已经明确为：**读取统一基线 JSON，按原语级步骤在本地重放前端加密流程，并与浏览器真实捕获结果做比对验证**。

最终答辩版对外口径统一为：
- **项目对外统一入口**：`main.py`
- **内部阶段编排层**：`phases/`
- **核心执行层之一**：`handlers/`

在当前重组后的架构中：
- **对外统一入口**：`main.py`
- **内部推荐入口**：`phases/phase4_verify_handlers.py` 与 `phases/run_full_pipeline.py`
- **核心实现层**：`handlers/` 目录本身

也就是说，`handlers` 不直接承担“项目入口”或“阶段编排”的职责，而是作为 `main.py → phases/` 之后的核心执行引擎。

---

## 1. 各脚本职责概览

### `base.py`（基类与上下文定义）
- **职责**：定义 Handler 体系的基础协议。
- **核心内容**：
  - `CryptographicOperation`：所有加密原语操作的统一接口。
  - `EncryptionContext`：在流水线执行过程中保存明文、中间结果、Key/IV/Nonce、签名输入等上下文数据。
- **意义**：保证不同操作在执行时使用统一的数据结构。

### `registry.py`（操作注册表）
- **职责**：管理所有已实现的操作原语。
- **核心能力**：根据算法/操作类型返回对应处理器。
- **协作方式**：`pipeline.py` 在逐步执行时，从这里查找具体操作实现。

### `operations.py`（具体原语实现）
- **职责**：提供真实的加密/签名/编码操作实现。
- **常见内容**：AES、DES、RSA、HMAC、哈希、编码转换等。
- **协作方式**：继承 `base.py` 中定义的接口，并注册到 `registry.py`。

### `providers.py`（底层能力封装）
- **职责**：封装底层密码库或通用工具能力。
- **意义**：将原语执行逻辑与第三方库解耦，便于后续替换实现。

### `pipeline.py`（流水线编排核心）
- **职责**：读取统一基线 JSON 中的 `meta.execution_flow`，逐步执行每个 API 的原语级步骤。
- **当前模式**：**不再依赖 YAML 配置文件**，也不再直接读取静态分析 JSON。
- **输入来源**：`baseline_samples/baseline_skeletons_*.json`。
- **粒度说明**：一个 API 对应一条流水线，流水线内部由多个 step 构成，step 粒度精确到 `init`、`setkey`、`setiv`、`encrypt`、`sign`、`derive_*`、`pack` 等原语动作。

### `validator.py`（结果验证）
- **职责**：比较本地 Handler 生成结果与浏览器真实捕获结果是否一致。
- **判定标准**：
  - 对 **AES / DES / HMAC / 哈希** 等确定性结果，要求 `handler_ciphertext` 与 `captured_ciphertext` **严格一致**。
  - 对 **RSA / AESRSA** 这类包含随机填充的场景，不要求逐字节密文一致；只要原语步骤、输入、Key/IV/PublicKey、打包字段链路正确，即标记为 `RSA_NONDETERMINISTIC_LOGIC_VALIDATED`。
  - 对 **signdataserver** 这类由服务端返回 `signature`、前端仅执行请求打包的端点，不属于“本地签名原语复现”；此类记录应归类为 `NO_CRYPTO`，验证通过意味着：最终请求体字段、`timestamp/signature` 等运行时参数回填正确，后续可用于协议篡改评估。
- **展示口径补充**：`PayloadPacking` 属于流水线步骤，不属于加密算法；报告算法列会过滤该项，仅展示 AES / DES / RSA / HMAC 等真实算法。
- **关键说明**：
  - **不要求服务器一定返回 200 OK**。只要浏览器端真实执行了前端加密逻辑并成功产出密文，就可以用于 Handler 验证。
  - **这里的“真实执行”指阶段 3 浏览器动态捕获，不等于阶段 5 安全评估真实发包。**

---

## 2. 当前工作流：统一基线 JSON 驱动

对外展示时，这套工作流建议统一描述为：

`main.py`
→ `phases/run_full_pipeline.py`
→ 静态分析 / 基线生成 / 动态捕获 / Handler 验证 / 安全评估 / 报告生成
→ 其中 `handlers/` 负责“本地重放与正确性验证”这一核心环节。

### 阶段 1：静态分析
- 运行 `collect/static_analyze.py`。
- 输出：`collect/static_analysis/static_analysis_*.json`。
- 作用：识别端点、算法、原语步骤、硬编码 Key/IV、派生逻辑、数据结构提示等信息。

### 阶段 2：基线骨架生成
- 运行 `scripts/init_baselines.py`。
- 输入：最新的 `collect/static_analysis/static_analysis_*.json`。
- 输出：`baseline_samples/baseline_skeletons_*.json`。
- 结果：同一个基线文件中包含本次静态分析识别到的多个 API 记录。

每条 API 基线通常包含：
- `meta`：端点信息、触发函数、算法列表、`execution_flow` 等。
- `request`：待发送请求的 Payload、Header。
- `validation`：浏览器捕获密文、本地模拟密文、验证结果等。

### 阶段 3：Payload 预填
- 在 `baseline_skeletons_*.json` 中补全每个 API 的 `request.payload`。
- 这一步发生在 Handler 验证之前。
- 如果 Payload 缺失或仍为占位值，CLI 应提示补全。

### 阶段 4：浏览器动态捕获
- 运行 `scripts/capture_baseline_playwright.py`。
- 这是**真实浏览器环境中的动态验证**：会真正打开页面、填入 Payload、触发前端 JS。
- Playwright 会读取基线中的：
  - `meta.url`
  - `meta.trigger_function`
  - `request.payload`
- 然后在真实页面环境中执行前端逻辑，捕获：
  - Key
  - IV
  - Nonce
  - 时间戳
  - 签名输入
  - 最终密文
- 这些数据会回填到：
  - `meta.execution_flow[*].runtime_args`
  - `validation.captured_ciphertext`

### 阶段 5：本地 Handler 验证
- 推荐运行 `phases/phase4_verify_handlers.py`。
- 底层核心脚本仍为 `scripts/verify_handlers.py`。
- `BaselinePipelineRunner` 读取同一份基线 JSON。
- 按 `meta.execution_flow` 中的步骤逐步执行。
- 得到 `handler_ciphertext` 后，与 `validation.captured_ciphertext` 比对，或按端点类型采用对应验证口径：
  - 确定性算法：严格比对。
  - RSA/AESRSA：标记 `RSA_NONDETERMINISTIC_LOGIC_VALIDATED`。
  - 服务端签名类 PayloadPacking 端点：标记 `NO_CRYPTO`。
- 只要满足对应口径，即将该记录标记为 `VERIFIED`。

---

## 3. handlers 在整套系统中的意义

`handlers` 的作用不是“替代浏览器”，而是：

1. **把前端 JS 的加密过程变成可重复执行的本地流水线**。
2. **在不依赖浏览器的情况下，重新构造合法密文请求**。
3. **为后续安全评估提供稳定、可编排、可批量执行的能力**。

也就是说：
- 浏览器负责给出一次真实执行结果，用来建立“标准答案”;
- Handler 负责在本地稳定复现这条加密链;
- 安全评估阶段再利用已验证的 Handler 去构造多种测试载荷。

---

## 4. 安全评估阶段与 handlers 的关系

当某个 API 已经通过 Handler 验证后，就可以进入安全评估阶段。

典型流程为：
1. 基于 `VERIFIED` 基线读取原始 Payload。
2. 生成测试场景（如注入、边界值、字段缺失、旧 Nonce 重放等）。
3. 调用本地 Handler 重新加密。
4. 将构造后的请求发送到目标 API。
5. 根据响应码、响应体、时间差异、错误模式判断是否存在安全问题。

### 阶段5双模式说明

当前实现中，阶段5已经明确拆分为两种运行口径：

1. **5A 本地预评估（默认）**
   - 只验证：场景是否可构造、请求体是否可稳定重建、协议字段是否可被篡改。
   - 适用于：离线协议层风险分析、自动化能力检查、基线缺口排查。

2. **5B 真实目标验证（显式启用）**
   - 通过 `phases/phase5_assess.py --send` 或总控入口 `main.py --phase5-send` 启用。
   - 在本地 Handler 已经重建出合法请求的前提下，把场景真正发送到目标 API。
   - 关注：HTTP 状态码、响应体、错误模式、耗时差异、服务端是否接受重放/篡改请求。

### 报告口径补充

- 报告中的 `阶段5评估模式` 会明确显示：`本地预评估` 或 `真实目标验证`。
- 报告中的 `安全评估阶段真实请求发送` 只表示：**阶段 5 是否把评估场景真正发到目标 API**。
- 如果该值为 `False`，并不表示没有做动态验证；它只说明阶段 5 采用了“本地重建 + 变异分析”模式。
- 阶段6报告会新增：
  - **在线验证摘要**（已发场景数、已响应数、错误数、平均耗时/P95、状态码分布）
  - **端点级在线验证概览**（每个端点的在线覆盖情况）
- `SKIPPED` 场景会在报告中直接展示原因，例如：
  - JSON 请求体无法自然表达重复字段
  - URL 编码 / JSON 请求体中未找到可篡改目标字段
  - 缺少可用请求体，无法执行协议篡改场景

在当前实现中，安全评估结果还会进一步进入**可配置评分模型**：
- 评分配置文件位置：`configs/scoring_profiles.yaml`
- 支持通过 CLI 选择 `default`、`crypto_focus`、`paper_v1` 等 profile
- 评分模型会综合：
  1. 漏洞严重级别扣分
  2. 发现类别系数
  3. 场景执行结果（`LOCAL_FAILED` / `SKIPPED`）的惩罚
  4. 场景类别系数
  5. 基线缺口惩罚

也就是说，`handlers` 负责提供**可验证、可重建、可批量运行**的基础能力，而最终报告中的风险分数则由评估层依据 profile 进行解释性汇总。

### RSA 超长明文处理

- 在评估阶段，`rsa_encrypt` 已支持对超长明文进行 PKCS#1 v1.5 分块加密，避免本地流程因 `Plaintext is too long` 直接失败。
- 该策略用于提升“本地可重放性”和场景覆盖率，不代表服务端一定支持分块后的请求格式。
- 是否存在真实可利用风险，仍以阶段5真实目标验证（`--send`）的响应行为为最终依据。

---

## 5. 当前架构下需要记住的关键点

1. **统一输入源是基线 JSON，不是 YAML，不是静态分析 JSON。**
2. **最终答辩版对外入口是 `main.py`，`phases/` 是内部阶段编排层。**
3. **`handlers/` 是核心实现层，不是项目入口，也不是阶段编排层。**
4. **一个 API 对应一条基线记录，也对应一条本地流水线。**
5. **流水线步骤保存在 `meta.execution_flow` 中，而不是旧的 `pipeline_steps`。**
6. **验证标准不是一刀切：确定性算法要求密文一致，RSA/AESRSA 允许“非确定性密文但逻辑验证通过”，服务端签名类端点则验证最终请求打包与运行时参数回填。**
7. **只有通过验证的基线，才适合进入后续自动化安全评估。**
8. **安全评估分数不是写死常量，而是由 `configs/scoring_profiles.yaml` 中的 profile 驱动。**

如果后续继续扩展 `handlers`，优先保持这套“基线驱动 + 原语级 step + 动态捕获回填 + 本地验证”的核心模式不变。
