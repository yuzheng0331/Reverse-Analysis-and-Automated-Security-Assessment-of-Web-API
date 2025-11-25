# =============================================================================
# Setup Environment Script (PowerShell)
# Phase 0: Environment Preparation
# =============================================================================
# Description: Initializes the development environment for API security assessment
# Prerequisites: PowerShell 5.1+, Python 3.8+, Optional: phpStudy/nginx
# =============================================================================

param(
    [switch]$SkipDbCheck,
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "  API Security Assessment - Environment Setup" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan

# -----------------------------------------------------------------------------
# Configuration - Replace with your actual paths/values
# -----------------------------------------------------------------------------
$CONFIG = @{
    # TODO: Update these paths to match your local environment
    PhpStudyPath    = "C:\phpstudy_pro\COM\phpstudy_pro.exe"  # Placeholder
    NginxPath       = "C:\nginx\nginx.exe"                     # Placeholder
    PythonPath      = "python"                                 # or "python3"
    VenvPath        = ".\.venv"
    
    # Database connectivity placeholders
    DbHost          = $env:DB_HOST ?? "localhost"
    DbPort          = $env:DB_PORT ?? "3306"
    DbName          = $env:DB_NAME ?? "api_assessment"
    DbUser          = $env:DB_USER ?? "root"
    # Note: DB_PASSWORD should be in .env file, never hardcoded
}

# -----------------------------------------------------------------------------
# Function: Check Python Installation
# -----------------------------------------------------------------------------
function Test-PythonInstallation {
    Write-Host "`n[1/5] Checking Python installation..." -ForegroundColor Yellow
    try {
        $pythonVersion = & $CONFIG.PythonPath --version 2>&1
        Write-Host "  ✓ Python found: $pythonVersion" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "  ✗ Python not found. Please install Python 3.8+" -ForegroundColor Red
        return $false
    }
}

# -----------------------------------------------------------------------------
# Function: Setup Virtual Environment
# -----------------------------------------------------------------------------
function Initialize-VirtualEnvironment {
    Write-Host "`n[2/5] Setting up virtual environment..." -ForegroundColor Yellow
    
    if (-not (Test-Path $CONFIG.VenvPath)) {
        Write-Host "  Creating virtual environment at $($CONFIG.VenvPath)..."
        & $CONFIG.PythonPath -m venv $CONFIG.VenvPath
        Write-Host "  ✓ Virtual environment created" -ForegroundColor Green
    }
    else {
        Write-Host "  ✓ Virtual environment already exists" -ForegroundColor Green
    }
    
    # Activate and install dependencies
    $activateScript = Join-Path $CONFIG.VenvPath "Scripts\Activate.ps1"
    if (Test-Path $activateScript) {
        Write-Host "  Installing dependencies..."
        & $activateScript
        & pip install -r requirements.txt --quiet
        Write-Host "  ✓ Dependencies installed" -ForegroundColor Green
    }
}

# -----------------------------------------------------------------------------
# Function: Start Web Server (phpStudy/nginx)
# -----------------------------------------------------------------------------
function Start-WebServer {
    Write-Host "`n[3/5] Checking web server..." -ForegroundColor Yellow
    
    # TODO: Uncomment and configure for your environment
    # Option 1: phpStudy
    # if (Test-Path $CONFIG.PhpStudyPath) {
    #     Write-Host "  Starting phpStudy..."
    #     Start-Process $CONFIG.PhpStudyPath -ArgumentList "start"
    #     Write-Host "  ✓ phpStudy started" -ForegroundColor Green
    # }
    
    # Option 2: nginx
    # if (Test-Path $CONFIG.NginxPath) {
    #     Write-Host "  Starting nginx..."
    #     Start-Process $CONFIG.NginxPath
    #     Write-Host "  ✓ nginx started" -ForegroundColor Green
    # }
    
    Write-Host "  ⚠ Web server setup skipped (configure paths in script)" -ForegroundColor Yellow
}

# -----------------------------------------------------------------------------
# Function: Check Database Connectivity
# -----------------------------------------------------------------------------
function Test-DatabaseConnection {
    if ($SkipDbCheck) {
        Write-Host "`n[4/5] Database check skipped" -ForegroundColor Yellow
        return $true
    }
    
    Write-Host "`n[4/5] Checking database connectivity..." -ForegroundColor Yellow
    
    # TODO: Implement actual database connectivity check
    # Example using Python:
    # $checkScript = @"
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
    #     print('OK')
    # except Exception as e:
    #     print(f'FAIL: {e}')
    #     sys.exit(1)
    # "@
    # $result = & $CONFIG.PythonPath -c $checkScript
    
    Write-Host "  ⚠ Database check placeholder (configure connection)" -ForegroundColor Yellow
    return $true
}

# -----------------------------------------------------------------------------
# Function: Install Playwright Browsers
# -----------------------------------------------------------------------------
function Install-PlaywrightBrowsers {
    Write-Host "`n[5/5] Setting up Playwright browsers..." -ForegroundColor Yellow
    
    try {
        & $CONFIG.PythonPath -m playwright install chromium
        Write-Host "  ✓ Playwright browsers installed" -ForegroundColor Green
    }
    catch {
        Write-Host "  ⚠ Playwright setup failed: $_" -ForegroundColor Yellow
        Write-Host "  Run manually: python -m playwright install" -ForegroundColor Yellow
    }
}

# -----------------------------------------------------------------------------
# Main Execution
# -----------------------------------------------------------------------------
function Main {
    $success = $true
    
    if (-not (Test-PythonInstallation)) { $success = $false }
    if ($success) { Initialize-VirtualEnvironment }
    if ($success) { Start-WebServer }
    if ($success) { Test-DatabaseConnection }
    if ($success) { Install-PlaywrightBrowsers }
    
    Write-Host "`n=============================================" -ForegroundColor Cyan
    if ($success) {
        Write-Host "  Environment setup complete!" -ForegroundColor Green
        Write-Host "  Next steps:" -ForegroundColor White
        Write-Host "  1. Copy .env.example to .env and configure" -ForegroundColor White
        Write-Host "  2. Run: python scripts/capture_baseline.py" -ForegroundColor White
    }
    else {
        Write-Host "  Setup completed with warnings" -ForegroundColor Yellow
        Write-Host "  Please review the messages above" -ForegroundColor White
    }
    Write-Host "=============================================" -ForegroundColor Cyan
}

Main
