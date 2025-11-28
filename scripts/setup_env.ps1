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
    PhpStudyPath    = "E:\phpStudy\phpstudy_pro\COM\phpstudy_pro.exe"  # Placeholder
    NginxPath       = "E:\phpStudy\phpstudy_pro\Extensions\Nginx1.25.2\nginx.exe"    # Placeholder
    PythonPath      = "D:\Reverse Analysis and Automated Security Assessment of Web API\.venv\Scripts\python.exe"     # or "python3"
    VenvPath        = "..\.venv"
    
    # Database connectivity placeholders
    DbHost          = $env:DB_HOST ?? "localhost"
    DbPort          = $env:DB_PORT ?? "3306"
    DbName          = $env:DB_NAME ?? "encryptdb"
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

    
    Write-Host "  ⚠ Database check placeholder (configure connection)" -ForegroundColor Yellow
    return $true
}

# -----------------------------------------------------------------------------
# Function: Install Playwright Browsers
# -----------------------------------------------------------------------------
function Install-PlaywrightBrowsers {
    Write-Host "`n[5/5] Setting up Playwright browsers..." -ForegroundColor Yellow

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
