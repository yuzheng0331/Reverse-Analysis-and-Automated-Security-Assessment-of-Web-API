# 🔒 Reverse Analysis and Automated Security Assessment of Web API

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A comprehensive pipeline for reverse engineering front-end crypto implementations and automated security assessment of web APIs.

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Pipeline Phases](#pipeline-phases)
- [Directory Structure](#directory-structure)
- [Usage Examples](#usage-examples)
- [Configuration](#configuration)
- [Development](#development)
- [Acceptance Criteria Checklist](#acceptance-criteria-checklist)
- [Contributing](#contributing)
- [License](#license)

## 🎯 Overview

This project provides a skeleton framework for:

1. **Capturing** baseline API requests from web applications
2. **Collecting** and analyzing JavaScript files for crypto patterns
3. **Detecting** cryptographic implementations (AES, RSA, HMAC, etc.)
4. **Replaying** requests with regenerated crypto parameters
5. **Mutating** parameters for security testing
6. **Assessing** endpoint security vulnerabilities
7. **Generating** comprehensive security reports

### Key Features

- 🔍 Automated JavaScript crypto pattern detection
- 🔐 Support for common crypto libraries (CryptoJS, JSEncrypt, etc.)
- 📊 Security scoring and vulnerability classification
- 📝 Multi-format report generation (HTML, Markdown, JSON)
- 🛠️ Extensible architecture with plugin support

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         静态分析阶段（一次完成）                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  static_analyze.py ──────────────► static_analysis.json                 │
│  (合并 fetch + parse + detect)      (完整的静态分析结果)                 │
│                                                                         │
│  输出内容：                                                              │
│  • 加密库识别（CryptoJS, JSEncrypt...）                                  │
│  • 加密模式检测（AES, RSA, HMAC...）                                     │
│  • 函数名提取（sendDataAes, encryptData...）                             │
│  • API 端点发现（/encrypt/aes.php...）                                   │
│  • 安全弱点标记（硬编码密钥、弱算法...）                                   │
│  • 端点-函数-加密 三方映射                                                │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         动态采集阶段                                     │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Playwright + Hook ──────────────► baseline_samples/                    │
│                                                                         │
│  • 根据静态分析发现的端点，针对性采集                                      │
│  • Hook 加密函数，捕获明文/密钥/密文                                      │
│  • 生成真实请求基线                                                      │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         验证与测试阶段                                   │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Handler 验证 ──► 参数变异 ──► 安全评估 ──► 报告生成                      │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## 🚀 Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager
- Git

### Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/yuzheng0331/Reverse-Analysis-and-Automated-Security-Assessment-of-Web-API.git
   cd Reverse-Analysis-and-Automated-Security-Assessment-of-Web-API
   ```

2. **Create virtual environment**
   ```bash
   python -m venv .venv
   
   # Windows
   .venv\Scripts\activate
   
   # Linux/macOS
   source .venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Install Playwright browsers** (for browser-based capture)
   ```bash
   python -m playwright install chromium
   ```

5. **Configure environment**
   ```bash
   cp .env .env
   # Edit .env with your configuration
   ```

### Automated Setup (Optional)

**Windows (PowerShell):**
```powershell
.\scripts\setup_env.ps1
```

**Linux/macOS:**
```bash
chmod +x scripts/setup_env.sh
./scripts/setup_env.sh
```

## ⚡ Quick Start

### 阶段 1: 静态分析（一步完成）
```bash
# 分析目标页面，获取完整的静态分析结果
python collect/static_analyze.py --url http://encrypt-labs-main/easy.php
```

### 阶段 2: 动态采集（基于静态分析结果）
```bash
# 使用 Playwright 捕获真实加密请求
python scripts/capture_baseline.py --url http://encrypt-labs-main/easy.php
```

### 阶段 3: 验证与测试
```bash
# 生成安全报告
python assess/report_gen.py --format all
```

## 📂 Pipeline Phases

### Phase 0: Environment Setup
**Scripts:** `scripts/setup_env.sh`, `scripts/setup_env.ps1`

Sets up the development environment including:
- Python virtual environment
- Dependencies installation
- Playwright browser setup
- Database connectivity check (optional)

### Phase 1: 静态分析（Static Analysis）
**Script:** `collect/static_analyze.py`

一体化静态分析工具，整合了原来的 fetch、parse、detect 功能：
- 收集 HTML 和 JavaScript 文件
- 提取 API 端点（从 onclick、form action、JS 代码）
- 检测加密库和算法（CryptoJS、JSEncrypt、WebCrypto 等）
- 提取函数定义和调用关系
- 建立端点 ↔ 函数 ↔ 加密算法的三方映射
- 标记安全弱点（硬编码密钥、弱算法等）

```bash
# 一步完成所有静态分析
python collect/static_analyze.py --url http://encrypt-labs-main/easy.php
```

输出：`static_analysis/static_analysis_YYYYMMDD_HHMMSS.json`，包含完整的静态分析结果。

### Phase 2: 动态采集（Dynamic Capture）
**Scripts:** `scripts/capture_baseline.py`

基于静态分析结果，使用 Playwright 进行动态采集：
- 根据发现的端点进行针对性采集
- Hook 加密函数，捕获明文/密钥/密文
- 生成真实请求基线样本

```bash
python scripts/capture_baseline.py --url http://encrypt-labs-main/easy.php
```

输出：`baseline_samples/` 目录下的 JSON 文件，包含真实的加密请求。

### Phase 3: Handler 验证
**Script:** `handlers/` 目录下的加密 Handler

基于静态分析和动态采集的结果，实现本地加密 Handler 并验证：
- 复现 JS 中的加密逻辑
- 对比本地输出与真实请求中的密文
- 验证加密参数的正确性

### Phase 4: Request Replay
**Script:** `replay/replay_request.py`

Replays requests with transformations, consuming baseline entries:
- Timestamp updates
- Signature regeneration
- Response comparison

```bash
python replay/replay_request.py --baseline baseline_samples/sample_request.json
```

### Phase 5: Parameter Mutation
**Script:** `replay/mutate_params.py`

Generates parameter mutations for testing:
- Boundary values
- Type confusion
- Injection payloads
- Crypto-specific mutations

```bash
python replay/mutate_params.py --params '{"username":"test","password":"123"}'
```

### Phase 7: Security Assessment
**Script:** `assess/assess_endpoint.py`

Assesses endpoint security:
- Vulnerability classification
- Security scoring
- Risk level determination

```bash
python assess/assess_endpoint.py --detection crypto_analysis/
```

### Phase 8: Report Generation
**Script:** `assess/report_gen.py`

Generates security reports:
- HTML with visual styling
- Markdown for documentation
- JSON for automation

```bash
python assess/report_gen.py --format all --output reports/
```

## 📁 Directory Structure

```
.
├── scripts/                  # Setup and utility scripts
│   ├── setup_env.ps1         # PowerShell setup script
│   ├── setup_env.sh          # Bash setup script
│   └── capture_baseline.py   # Baseline capture tool (Playwright)
│
├── collect/                  # 静态分析模块
│   ├── __init__.py
│   └── static_analyze.py     # 一体化静态分析工具（合并 fetch + parse + detect）
│
├── analysis/                 # 加密分析模块（保留用于高级分析）
│   ├── __init__.py
│   ├── detect_crypto.py      # Crypto detection engine（可选验证）
│   └── signature_db.py       # Crypto signature database
│
├── handlers/                 # 加密 Handler 实现
│   └── (crypto handlers here)
│
├── replay/                   # Request replay module
│   ├── __init__.py
│   ├── replay_request.py     # Request replayer
│   └── mutate_params.py      # Parameter mutator
│
├── assess/                   # Security assessment module
│   ├── __init__.py
│   ├── assess_endpoint.py    # Endpoint assessor
│   └── report_gen.py         # Report generator
│
├── configs/                  # Configuration files
│   ├── global.yaml           # Global configuration
│   └── phases_config.yaml    # Pipeline configuration
│
├── static_analysis/          # 静态分析结果输出
│   └── static_analysis_*.json
│
├── baseline_samples/         # 动态采集的基线样本
│   └── baseline_*.json
│
├── tests/                    # Test files
│   └── test_smoke.py
│
├── docs/                     # Documentation
│   └── (documentation here)
│
├── .env.example              # Environment template
├── requirements.txt          # Python dependencies
├── main.py                   # Main entry point
└── README.md                 # This file
```

## ⚙️ Configuration

### Environment Variables (`.env`)

Copy `.env.example` to `.env` and configure:

```bash
# Target application
TARGET_URL=https://example.com

# Database (optional)
DB_HOST=localhost
DB_PORT=3306
DB_NAME=api_assessment

# Playwright settings
PLAYWRIGHT_BROWSER=chromium
PLAYWRIGHT_HEADLESS=true
```

### Pipeline Configuration (`configs/phases_config.yaml`)

Configure pipeline phases, dependencies, and options in the YAML file.

## 🧪 Usage Examples

### Example 1: 完整分析流程

```bash
# 1. 静态分析：一步获取所有加密信息
python collect/static_analyze.py --url http://encrypt-labs-main/easy.php

# 2. 动态采集：基于静态分析结果捕获真实请求
python scripts/capture_baseline.py --url http://encrypt-labs-main/easy.php

# 3. 实现并验证 Handler（手动编写，基于静态分析结果）
# 创建 handlers/cryptojs_aes_handler.py

# 4. 生成报告
python assess/report_gen.py --format html
```

### Example 2: 仅静态分析

```bash
# 快速分析目标页面的加密实现
python collect/static_analyze.py --url http://target.com/login.php --output my_analysis/
```

### Example 3: Test Parameter Mutations

```bash
# Generate mutations for login parameters
python replay/mutate_params.py --params '{"username":"test","password":"pass123","sign":"abc"}'

# Apply specific strategies
python replay/mutate_params.py --params '{"id":123}' --strategy injection crypto
```

## 👥 Development

### Running Tests

```bash
pytest tests/
```

### Code Style

The project follows PEP 8 guidelines. Format code with:

```bash
black .
isort .
```

### Adding New Crypto Signatures

Add signatures to `analysis/signature_db.py` or create a custom `configs/signatures.json`:

```json
{
  "signatures": [
    {
      "id": "CUSTOM_001",
      "name": "Custom Crypto Pattern",
      "category": "symmetric",
      "patterns": ["customEncrypt\\s*\\("],
      "weakness_level": "medium",
      "description": "Custom encryption function"
    }
  ]
}
```

## ✅ Acceptance Criteria Checklist

After merging this PR, verify the following:

### Environment Setup
- [ ] Clone the repository successfully
- [ ] Create virtual environment: `python -m venv .venv`
- [ ] Install dependencies: `pip install -r requirements.txt`
- [ ] Copy `.env.example` to `.env`
- [ ] Run setup script without errors

### Phase 1: 静态分析
- [ ] `python collect/static_analyze.py --url http://target.com` 运行成功
- [ ] 生成 `static_analysis/static_analysis_*.json` 文件
- [ ] JSON 包含：端点列表、加密模式、函数信息、端点-加密映射
- [ ] 识别出常见加密库（CryptoJS、JSEncrypt 等）
- [ ] 检测到安全弱点（如硬编码密钥、弱算法）

### Phase 2: 动态采集
- [ ] `python scripts/capture_baseline.py --url http://target.com` 执行成功
- [ ] 生成 `baseline_samples/baseline_*.json` 文件
- [ ] 基线样本包含真实的请求和响应数据

### Phase 3-4: 验证与测试
- [ ] 基于静态分析结果实现 Handler
- [ ] Handler 输出与基线样本中的密文一致
- [ ] `python replay/mutate_params.py --params '{"test":"value"}'` 生成变异
- [ ] `python assess/report_gen.py --format html` 创建 HTML 报告

### Code Quality
- [ ] All Python files have docstrings
- [ ] No hardcoded credentials in code
- [ ] `.env.example` contains only placeholders
- [ ] Import statements are properly organized

### Documentation
- [ ] README.md is complete and accurate
- [ ] All scripts have `--help` documentation
- [ ] Configuration files are documented

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines before submitting PRs.

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-feature`
3. Commit changes: `git commit -m 'Add new feature'`
4. Push to branch: `git push origin feature/new-feature`
5. Submit a Pull Request

---

**Note:** This is a skeleton/template project. Many functions contain TODO placeholders that need to be implemented for production use. The framework provides the structure and examples to guide development.
