<#
.SYNOPSIS
    Check network connectivity for APKStudioAI
#>

# Test Ollama
try {
    iwr http://127.0.0.1:11434/api/tags -TimeoutSec 3 -OutFile $null
    Write-Host '[OK] localhost:11434 (Ollama)'
} catch {
    Write-Host '[FAIL] localhost:11434 (Ollama)'
}

# Test GitHub
try {
    iwr https://api.github.com -TimeoutSec 5 -OutFile $null
    Write-Host '[OK] github.com'
} catch {
    Write-Host '[WARN] github.com (may affect auto-updates)'
}