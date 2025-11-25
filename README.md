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
┌─────────────────────────────────────────────────────────────────┐
│                    API Security Assessment Pipeline              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Phase 0: Setup    ─────►  Phase 1: Capture  ─────►  Phase 2: Collect  │
│  (Environment)            (Baseline)               (JavaScript)        │
│                                                                  │
│       │                       │                        │         │
│       ▼                       ▼                        ▼         │
│                                                                  │
│  Phase 3: Parse   ◄─────  Phase 4: Detect  ─────►  Phase 5: Replay    │
│  (AST Analysis)           (Crypto)                (Requests)          │
│                                                                  │
│       │                       │                        │         │
│       ▼                       ▼                        ▼         │
│                                                                  │
│  Phase 6: Mutate  ─────►  Phase 7: Assess  ─────►  Phase 8: Report   │
│  (Parameters)             (Security)               (Generate)         │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
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
   cp .env.example .env
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

### 1. Create Sample Baseline
```bash
python scripts/capture_baseline.py --create-sample
```

### 2. Collect JavaScript (from a URL)
```bash
python collect/fetch_js.py --url https://example.com
```

### 3. Parse for Crypto Patterns
```bash
python collect/parse_js.py --input collected_js/
```

### 4. Detect Crypto Implementations
```bash
python analysis/detect_crypto.py
```

### 5. Generate Security Report
```bash
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

### Phase 1: Baseline Capture
**Script:** `scripts/capture_baseline.py`

Captures baseline API requests using:
- HTTP requests library for simple capture
- Playwright for JavaScript-heavy applications

```bash
# Capture from URL
python scripts/capture_baseline.py --url https://api.example.com/login

# Create sample baseline
python scripts/capture_baseline.py --create-sample
```

### Phase 2: JavaScript Collection
**Script:** `collect/fetch_js.py`

Collects JavaScript files from web applications:
- Extracts inline `<script>` content
- Downloads external JS files
- Quick-scans for crypto indicators

```bash
python collect/fetch_js.py --url https://example.com --output collected_js/
```

### Phase 3: JavaScript Parsing
**Script:** `collect/parse_js.py`

Parses JavaScript for crypto patterns:
- Regex-based pattern detection
- Function name extraction
- API call mapping

```bash
python collect/parse_js.py --input collected_js/ --output analysis_results/
```

### Phase 4: Crypto Detection
**Script:** `analysis/detect_crypto.py`

Analyzes crypto implementations:
- Algorithm identification
- Security level assessment
- Vulnerability detection

```bash
python analysis/detect_crypto.py --input analysis_results/ --baseline baseline_samples/
```

### Phase 5: Request Replay
**Script:** `replay/replay_request.py`

Replays requests with transformations:
- Timestamp updates
- Signature regeneration
- Response comparison

```bash
python replay/replay_request.py --baseline baseline_samples/sample_request.json
```

### Phase 6: Parameter Mutation
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
│   └── capture_baseline.py   # Baseline capture tool
│
├── collect/                  # JavaScript collection module
│   ├── __init__.py
│   ├── fetch_js.py           # JS file collector
│   └── parse_js.py           # JS AST parser
│
├── analysis/                 # Crypto analysis module
│   ├── __init__.py
│   ├── detect_crypto.py      # Crypto detection engine
│   └── signature_db.py       # Crypto signature database
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
│   ├── api_config.yaml       # API configuration
│   └── phases_config.yaml    # Pipeline configuration
│
├── baseline_samples/         # Captured baseline requests
│   └── sample_request.json   # Sample baseline file
│
├── tests/                    # Test files
│   └── (test files here)
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

### Example 1: Analyze a Login Endpoint

```bash
# 1. Capture the login request manually or with the tool
python scripts/capture_baseline.py --url https://api.example.com/login --method POST

# 2. Collect JavaScript from the login page
python collect/fetch_js.py --url https://example.com/login

# 3. Parse for crypto patterns
python collect/parse_js.py --input collected_js/

# 4. Run full analysis
python analysis/detect_crypto.py

# 5. Generate report
python assess/report_gen.py --format html
```

### Example 2: Test Parameter Mutations

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

### Phase 0-1: Setup & Capture
- [ ] `scripts/setup_env.sh` runs without errors (or `.ps1` on Windows)
- [ ] `python scripts/capture_baseline.py --create-sample` creates `baseline_samples/sample_request.json`
- [ ] Sample baseline file contains valid JSON structure

### Phase 2-3: Collection & Parsing
- [ ] `python collect/fetch_js.py --url https://example.com` collects JavaScript
- [ ] `python collect/parse_js.py --input collected_js/` generates parse results
- [ ] Parse results contain crypto pattern matches

### Phase 4: Detection
- [ ] `python analysis/detect_crypto.py` runs successfully
- [ ] Detection results include security assessments
- [ ] Signature database contains default patterns

### Phase 5-6: Replay & Mutation
- [ ] `python replay/replay_request.py --baseline baseline_samples/sample_request.json` executes
- [ ] `python replay/mutate_params.py --params '{"test":"value"}'` generates mutations
- [ ] Mutations include various strategies (injection, crypto, etc.)

### Phase 7-8: Assessment & Reporting
- [ ] `python assess/assess_endpoint.py` generates assessment results
- [ ] `python assess/report_gen.py --format html` creates HTML report
- [ ] Report contains summary, vulnerabilities, and recommendations

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
