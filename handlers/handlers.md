基于你提供的文件列表和 `__init__.py` 内容，结合我们之前确认的架构策略（静态骨架+动态血肉），以下是 `handlers` 模块下各脚本的**职责分工**及**协作流程**：

### 1. 各脚本职责概览

*   **`base.py` (基石/协议定义)**
    *   **职责**：定义所有 Handler 必须遵守的“法律”。
    *   **核心类**：
        *   `CryptographicOperation`：所有加密操作的父类。规定了必须实现 `execute(data, context)` 方法。
        *   `EncryptionContext`：**数据载体**。它就像一个篮子，装着静态分析得到的配置（算法名、模式）和运行时捕获的动态数据（Key, IV）。
    *   **协作**：被所有其他模块引用，确保数据格式统一。

*   **`registry.py` (调度中心/工厂)**
    *   **职责**：管理所有的加密算法实现。
    *   **核心功能**：提供装饰器（如 `@register_operation("AES")`）将具体实现注册进来，并提供 `get_operation("AES")` 方法供外部调用。
    *   **协作**：`pipeline.py` 会询问它：“给我一个 AES 的处理器”。

*   **`operations.py` (具体工种)**
    *   **职责**：这是真正干活的地方。包含具体的标准算法实现（如 `AESOperation`, `RSAOperation`, `HMACSha256Operation`）。
    *   **协作**：继承自 `base.py` 的类，并注册到 `registry.py` 中。

*   **`providers.py` (底层工具箱)**
    *   **职责**：封装具体的 Python 加密库（如 `pycryptodome` 或 `cryptography`）。
    *   **目的**：将业务逻辑与底层库解耦。如果以后换库，只需改这里。
    *   **协作**：`operations.py` 调用这里的函数来执行底层的字节运算。

*   **`pipeline.py` (流水线/编排者)**
    *   **职责**：处理复杂的加密链。
    *   **新模式**：**不再依赖 YAML 配置文件**。而是通过 `BaselinePipelineRunner` 直接读取 `baseline_skeletons_*.json` 中的 `pipeline_steps` 构建流水线。
    *   **协作**：它是外部调用的入口。它接收一个基线对象，提取其中的操作步骤和运行时参数 (`runtime_args`)，依次从 `registry.py` 获取 Handler 并执行。

*   **`validator.py` (质检员)**
    *   **职责**：验证 Handler 算出来的结果是否正确。
    *   **逻辑**：它拿着 `handler_ciphertext`（你的模拟计算结果）和从浏览器 Hooks 捕获到的 `captured_ciphertext`（真实基线密文）进行比对。
    *   **关键点**：只要本地模拟的密文与浏览器生成的密文一致，即认为 Handler 逻辑正确。无需依赖服务器的 200 OK 响应，这解决了服务器在重放攻击等场景下可能报错的问题。
    *   **协作**：通常在 `verify_handlers.py` 中被调用。

---

### 2. 它们是如何配合工作的？（新工作流：基线骨架驱动）

假设我们要复现一个流程：**静态分析发现某端点使用 AES 加密**。

1.  **基线骨架生成 (Skeleton Generation)**:
    *   运行 `scripts/generate_test_skeletons.py` (之前为 `init_baselines.py`)。
    *   **输入源**：`collect/static_analysis/static_analysis_*.json`。
    *   **自动化推断**: 脚本会自动识别 `Encrypt`, `SetKey` 等操作步骤，从 `details` 字段提取硬编码信息，生成 `baseline_skeletons_*.json`。
    *   **状态**: 此时基线状态为 `PENDING_PAYLOAD`，`request.payload` 为空。

2.  **Payload 填充与动态捕获 (Payload & Capture)**:
    *   **Payload 填充**: 开发者或脚本在 `baseline_skeletons_*.json` 中填入符合业务逻辑的 `request.payload`（例如 `{"username": "admin", "password": "123"}`）。
    *   **真实数据捕获**: 运行 `scripts/capture_baseline_playwright.py`。
    *   **Playwright Action**: 脚本启动浏览器，Hook 页面上的加密函数（如 `AES.encrypt`, `RSA.encrypt`），自动注入填好的 Payload 并触发前端加密逻辑。
    *   **数据回填**: 捕获脚本会将浏览器实际使用的 **Key**, **IV**, **Nonce** 以及生成的 **密文 (Ciphertext)** 回填到 JSON 文件的 `meta.execution_flow` (runtime_args) 和 `validation.captured_ciphertext` 字段。
    *   **目的**: 获取“标准答案” (Truth)。即使服务器端校验失败，只要浏览器加密过程执行完成，我们就能获得用于验证本地 Handler 的基准数据。

3.  **Handler 验证 (Handler Verification)**:
    *   运行 `scripts/verify_handlers.py`。
    *   **加载数据**: 读取已填充了 Payload 和 `runtime_args` 的 JSON 文件。
    *   **模拟执行**: `BaselinePipelineRunner` 使用 JSON 中的 `pipeline_steps` 和捕获到的 Key/IV，在本地 Python 环境中完全复刻加密过程。
    *   **比对验证**: `ValidationEngine` 比较 `handler_ciphertext` (本地生成) 和 `captured_ciphertext` (浏览器捕获)。
    *   **判定标准**: **密文一致 (Ciphertext Match) = Pass**。这证明了本地 Python Handler 精确还原了前端 JS 的加密逻辑。

4.  **安全性评估 (Security Assessment)**:
    *   运行 `assess/assess_endpoint.py`。
    *   **基于验证**: 既然 Handler 已经验证正确，我们就可以利用它来构造任意攻击载荷（如 SQL 注入 payload）。
    *   **过程**: 修改 Payload -> 本地 Handler 加密 -> 发送给服务器 -> 检查业务响应。
