$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Assert-Equal {
    param(
        [Parameter(Mandatory = $true)][string]$Actual,
        [Parameter(Mandatory = $true)][string]$Expected,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ($Actual -ne $Expected) {
        throw "$Label mismatch.`nExpected:`n$Expected`nActual:`n$Actual"
    }
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("kali-mcp-powershell-{0}" -f [guid]::NewGuid().ToString("N"))
$cacheRoot = Join-Path $testRoot "cache"
$profileDirectory = Join-Path $cacheRoot "kali-mcp"
$profilePath = Join-Path $profileDirectory "chromium-seccomp.json"
$global:KaliMCPTestContainerExists = $false
$global:KaliMCPTestDockerRunCount = 0
$global:KaliMCPTestDockerRunArguments = @()

function global:docker {
    $received = @($args | ForEach-Object { [string]$_ })
    if ($received.Count -ge 2 -and $received[0] -eq "container" -and $received[1] -eq "inspect") {
        if ($global:KaliMCPTestContainerExists) {
            $global:LASTEXITCODE = 0
        } else {
            $global:LASTEXITCODE = 1
        }
        return
    }
    if ($received.Count -ge 3 -and $received[0] -eq "inspect") {
        if ($received[2] -match "Config.Labels") {
            "true"
        } elseif ($received[2] -match "State.Running") {
            "true"
        } else {
            $global:LASTEXITCODE = 1
            return
        }
        $global:LASTEXITCODE = 0
        return
    }
    if ($received.Count -ge 1 -and $received[0] -eq "run") {
        $global:KaliMCPTestDockerRunCount++
        $global:KaliMCPTestDockerRunArguments = $received
        $global:KaliMCPTestContainerExists = $true
        $global:LASTEXITCODE = 0
        "fake-container-id"
        return
    }
    if ($received.Count -ge 1 -and $received[0] -eq "exec") {
        $global:LASTEXITCODE = 0
        return
    }
    throw "unexpected docker command: $($received -join ' ')"
}

try {
    New-Item -ItemType Directory -Path $profileDirectory -Force | Out-Null
    $profileContent = [System.IO.File]::ReadAllText((Join-Path $repoRoot "chromium-seccomp.json"))
    $profileContent = $profileContent.Replace("`r`n", "`n")
    [System.IO.File]::WriteAllText($profilePath, $profileContent, [System.Text.UTF8Encoding]::new($false))
    $env:XDG_CACHE_HOME = $cacheRoot
    $env:KALI_MCP_DOCKER_IMAGE = "example.invalid/kali-mcp:test"
    $env:KALI_MCP_DOCKER_PULL = "never"
    $env:KALI_MCP_CONTAINER_NAME = "kali-mcp-windows-test"

    $installer = [scriptblock]::Create((Get-Content (Join-Path $PSScriptRoot "run-docker.ps1") -Raw))
    $firstOutput = (& $installer | Out-String)
    if ($firstOutput -notmatch "docker exec -i kali-mcp-windows-test mcp-client") {
        throw "installer output omitted the docker exec launcher"
    }
    if ($global:KaliMCPTestDockerRunCount -ne 1) {
        throw "docker run count=$global:KaliMCPTestDockerRunCount, want 1"
    }

    $tokenArgument = @($global:KaliMCPTestDockerRunArguments | Where-Object { $_ -like "KALI_MCP_API_TOKEN=*" })
    if ($tokenArgument.Count -ne 1 -or $tokenArgument[0] -notmatch '^KALI_MCP_API_TOKEN=[0-9a-f]{64}$') {
        throw "installer did not generate one 64-character API token"
    }
    $normalizedArguments = $global:KaliMCPTestDockerRunArguments | ForEach-Object {
        if ($_ -like "KALI_MCP_API_TOKEN=*") { "KALI_MCP_API_TOKEN=<generated>" } else { $_ }
    }
    $expectedArguments = @(
        "run", "--pull=never", "-d", "--name", "kali-mcp-windows-test",
        "--restart", "unless-stopped", "--init",
        "--add-host", "host.docker.internal:host-gateway", "--ipc=host",
        "--security-opt", "seccomp=$profilePath",
        "--label", "io.github.found-cake.kali-mcp.managed=true",
        "-e", "KALI_MCP_API_TOKEN=<generated>", "--entrypoint", "kali-server",
        "example.invalid/kali-mcp:test", "--ip", "127.0.0.1", "--port", "5000"
    )
    Assert-Equal ($normalizedArguments -join "`n") ($expectedArguments -join "`n") "docker arguments"

    $secondOutput = (& $installer | Out-String)
    if ($secondOutput -notmatch "docker exec -i kali-mcp-windows-test mcp-client") {
        throw "existing-container output omitted the docker exec launcher"
    }
    if ($global:KaliMCPTestDockerRunCount -ne 1) {
        throw "re-running the installer created another container"
    }
} finally {
    Remove-Item Function:\docker -ErrorAction SilentlyContinue
    Remove-Item Env:\XDG_CACHE_HOME -ErrorAction SilentlyContinue
    Remove-Item Env:\KALI_MCP_DOCKER_IMAGE -ErrorAction SilentlyContinue
    Remove-Item Env:\KALI_MCP_DOCKER_PULL -ErrorAction SilentlyContinue
    Remove-Item Env:\KALI_MCP_CONTAINER_NAME -ErrorAction SilentlyContinue
    Remove-Variable -Name KaliMCPTestContainerExists -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable -Name KaliMCPTestDockerRunCount -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable -Name KaliMCPTestDockerRunArguments -Scope Global -ErrorAction SilentlyContinue
    Remove-Item $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}
