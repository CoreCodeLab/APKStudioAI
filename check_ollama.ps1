<#
.SYNOPSIS
    Check Ollama service and model availability for APKStudioAI
#>

try {
    $r = Invoke-WebRequest -Uri 'http://127.0.0.1:11434/api/tags' -TimeoutSec 5 -ErrorAction Stop
    if ($r.StatusCode -eq 200) {
        Write-Host '[OK] Ollama API responding'
        $data = $r.Content | ConvertFrom-Json
        $found = $false
        foreach ($m in $data.models) {
            if ($m.name -like '*qwen2.5-coder*') {
                Write-Host '[OK] Model qwen2.5-coder found:' $m.name
                $found = $true
            }
        }
        if (-not $found) {
            Write-Host '[WARN] Model qwen2.5-coder:3b NOT FOUND'
            Write-Host '       Run: ollama pull qwen2.5-coder:3b'
        }
    }
} catch {
    Write-Host '[ERROR] Ollama API not responding'
    Write-Host '        Make sure Ollama is running: ollama serve'
}