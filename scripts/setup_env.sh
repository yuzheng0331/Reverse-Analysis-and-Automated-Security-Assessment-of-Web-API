#!/usr/bin/env bash
# =============================================================================
# Setup Environment Script (Bash)
# Phase 0: Environment Preparation
# =============================================================================
# Description: Initializes the development environment for API security assessment
# Prerequisites: Bash 4+, Python 3.8+, Optional: nginx/Apache
# Usage: ./scripts/setup_env.sh [--skip-db-check] [--verbose]
# =============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# -----------------------------------------------------------------------------
# Configuration - Replace with your actual paths/values
# -----------------------------------------------------------------------------
PYTHON_CMD="${PYTHON_CMD:-python3}"
VENV_PATH="${VENV_PATH:-.venv}"
SKIP_DB_CHECK=false
VERBOSE=false

# Parse arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --skip-db-check) SKIP_DB_CHECK=true ;;
        --verbose) VERBOSE=true ;;
        *) echo "Unknown parameter: $1"; exit 1 ;;
    esac
    shift
done

# -----------------------------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------------------------
log_info() {
    echo -e "${CYAN}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[⚠]${NC} $1"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
}

# -----------------------------------------------------------------------------
# Function: Check Python Installation
# -----------------------------------------------------------------------------
check_python() {
    echo ""
    log_info "[1/5] Checking Python installation..."
    
    if command -v "$PYTHON_CMD" &> /dev/null; then
        PYTHON_VERSION=$($PYTHON_CMD --version 2>&1)
        log_success "Python found: $PYTHON_VERSION"
        return 0
    else
        log_error "Python not found. Please install Python 3.8+"
        return 1
    fi
}

# -----------------------------------------------------------------------------
# Function: Setup Virtual Environment
# -----------------------------------------------------------------------------
setup_venv() {
    echo ""
    log_info "[2/5] Setting up virtual environment..."
    
    if [ ! -d "$VENV_PATH" ]; then
        log_info "Creating virtual environment at $VENV_PATH..."
        $PYTHON_CMD -m venv "$VENV_PATH"
        log_success "Virtual environment created"
    else
        log_success "Virtual environment already exists"
    fi
    
    # Activate and install dependencies
    # shellcheck disable=SC1091
    source "$VENV_PATH/bin/activate"
    
    log_info "Installing dependencies..."
    pip install -r requirements.txt --quiet
    log_success "Dependencies installed"
}

# -----------------------------------------------------------------------------
# Function: Start Web Server (nginx/Apache)
# -----------------------------------------------------------------------------
start_webserver() {
    echo ""
    log_info "[3/5] Checking web server..."
    
    # TODO: Uncomment and configure for your environment
    
    # Option 1: nginx
    # if command -v nginx &> /dev/null; then
    #     log_info "Starting nginx..."
    #     sudo systemctl start nginx || sudo nginx
    #     log_success "nginx started"
    # fi
    
    # Option 2: Apache
    # if command -v apache2 &> /dev/null; then
    #     log_info "Starting Apache..."
    #     sudo systemctl start apache2
    #     log_success "Apache started"
    # fi
    
    # Option 3: Python built-in server (for development)
    # log_info "Starting Python development server..."
    # $PYTHON_CMD -m http.server 8080 &
    
    log_warning "Web server setup skipped (configure in script)"
}

# -----------------------------------------------------------------------------
# Function: Check Database Connectivity
# -----------------------------------------------------------------------------
check_database() {
    echo ""
    
    if [ "$SKIP_DB_CHECK" = true ]; then
        log_info "[4/5] Database check skipped"
        return 0
    fi
    
    log_info "[4/5] Checking database connectivity..."
    
    # TODO: Implement actual database connectivity check
    # Load environment variables
    # if [ -f .env ]; then
    #     export $(grep -v '^#' .env | xargs)
    # fi
    
    # Example using Python:
    # $PYTHON_CMD -c "
    # import os
    # import sys
    # try:
    #     import pymysql
    #     conn = pymysql.connect(
    #         host=os.getenv('DB_HOST', 'localhost'),
    #         port=int(os.getenv('DB_PORT', 3306)),
    #         user=os.getenv('DB_USER', 'root'),
    #         password=os.getenv('DB_PASSWORD', ''),
    #         database=os.getenv('DB_NAME', 'api_assessment')
    #     )
    #     conn.close()
    #     print('Database connection successful')
    # except Exception as e:
    #     print(f'Database connection failed: {e}')
    #     sys.exit(1)
    # "
    
    log_warning "Database check placeholder (configure connection)"
    return 0
}

# -----------------------------------------------------------------------------
# Function: Install Playwright Browsers
# -----------------------------------------------------------------------------
install_playwright() {
    echo ""
    log_info "[5/5] Setting up Playwright browsers..."
    
    if $PYTHON_CMD -m playwright install chromium 2>/dev/null; then
        log_success "Playwright browsers installed"
    else
        log_warning "Playwright setup failed"
        log_warning "Run manually: python -m playwright install"
    fi
}

# -----------------------------------------------------------------------------
# Main Execution
# -----------------------------------------------------------------------------
main() {
    echo "============================================="
    echo -e "${CYAN}  API Security Assessment - Environment Setup${NC}"
    echo "============================================="
    
    check_python || exit 1
    setup_venv
    start_webserver
    check_database
    install_playwright
    
    echo ""
    echo "============================================="
    log_success "Environment setup complete!"
    echo ""
    echo "  Next steps:"
    echo "  1. Copy .env.example to .env and configure"
    echo "  2. Run: python scripts/capture_baseline.py"
    echo "============================================="
}

main "$@"
