param(
    [switch]$SkipDbCheck,
    [switch]$Verbose
)

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $scriptDir
$legacyScript = Join-Path $projectRoot "scripts\setup_env.ps1"

if (-not (Test-Path $legacyScript)) {
    throw "未找到环境初始化脚本: $legacyScript"
}

& $legacyScript @PSBoundParameters

