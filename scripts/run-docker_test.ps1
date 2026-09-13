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
$global:KaliMCPTestDockerPullCount = 0
$global:KaliMCPTestDockerRemoveCount = 0
$global:KaliMCPTestDockerRenameCount = 0
$global:KaliMCPTestDockerCommands = @()
$global:KaliMCPTestDockerRunFails = $false
$global:KaliMCPTestExistingImageID = "sha256:current"
$global:KaliMCPTestDesiredImageID = "sha256:current"

function global:docker {
    $received = @($args | ForEach-Object { [string]$_ })
    $global:KaliMCPTestDockerCommands += ,($received -join " ")
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
        } elseif ($received[2] -match "\.Image") {
            $global:KaliMCPTestExistingImageID
        } else {
            $global:LASTEXITCODE = 1
            return
        }
        $global:LASTEXITCODE = 0
        return
    }
    if ($received.Count -ge 1 -and $received[0] -eq "pull") {
        $global:KaliMCPTestDockerPullCount++
        $global:LASTEXITCODE = 0
        return
    }
    if ($received.Count -ge 2 -and $received[0] -eq "image" -and $received[1] -eq "inspect") {
        $global:KaliMCPTestDesiredImageID
        $global:LASTEXITCODE = 0
        return
    }
    if ($received.Count -ge 1 -and $received[0] -eq "run") {
        $global:KaliMCPTestDockerRunCount++
        $global:KaliMCPTestDockerRunArguments = $received
        if ($global:KaliMCPTestDockerRunFails) {
            $global:LASTEXITCODE = 1
            return
        }
        $global:KaliMCPTestContainerExists = $true
        $global:LASTEXITCODE = 0
        "fake-container-id"
        return
    }
    if ($received.Count -ge 1 -and $received[0] -eq "exec") {
        $global:LASTEXITCODE = 0
        return
    }
    if ($received.Count -ge 1 -and $received[0] -eq "rm") {
        $global:KaliMCPTestDockerRemoveCount++
        $global:LASTEXITCODE = 0
        return
    }
    if ($received.Count -ge 1 -and $received[0] -eq "rename") {
        $global:KaliMCPTestDockerRenameCount++
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
        "--add-host", "host.docker.internal:host-gateway", "--shm-size=512m",
        "--security-opt", "seccomp=$profilePath",
        "--label", "io.github.found-cake.kali-mcp.managed=true",
        "-e", "KALI_MCP_API_TOKEN=<generated>", "--entrypoint", "kali-server",
        "example.invalid/kali-mcp:test", "--ip", "127.0.0.1", "--port", "5000"
    )
    Assert-Equal ($normalizedArguments -join "`n") ($expectedArguments -join "`n") "docker arguments"

    $env:KALI_MCP_DOCKER_PULL = "always"
    $secondOutput = (& $installer | Out-String)
    if ($secondOutput -notmatch "docker exec -i kali-mcp-windows-test mcp-client") {
        throw "existing-container output omitted the docker exec launcher"
    }
    if ($global:KaliMCPTestDockerRunCount -ne 1) {
        throw "re-running the installer created another container"
    }
    if ($global:KaliMCPTestDockerPullCount -ne 1) {
        throw "re-running the installer did not check for a newer image"
    }

    $global:KaliMCPTestDesiredImageID = "sha256:updated"
    $thirdOutput = (& $installer | Out-String)
    if ($thirdOutput -notmatch "docker exec -i kali-mcp-windows-test mcp-client") {
        throw "updated-container output omitted the docker exec launcher"
    }
    if ($global:KaliMCPTestDockerRunCount -ne 2 -or $global:KaliMCPTestDockerRemoveCount -ne 1 -or $global:KaliMCPTestDockerRenameCount -ne 2) {
        throw "new image did not replace the managed container"
    }
    if ($global:KaliMCPTestDockerRunArguments[1] -ne "--pull=never") {
        throw "pre-pulled image was pulled again during replacement"
    }
    $candidateName = $global:KaliMCPTestDockerRunArguments[4]
    if ($candidateName -notlike "kali-mcp-windows-test-candidate-*") {
        throw "replacement was not staged under a candidate container name"
    }
    if (-not ($global:KaliMCPTestDockerCommands | Where-Object { $_ -like "rename kali-mcp-windows-test kali-mcp-windows-test-previous-*" })) {
        throw "existing container was not staged under a backup name"
    }
    if (-not ($global:KaliMCPTestDockerCommands -contains "rename $candidateName kali-mcp-windows-test")) {
        throw "healthy replacement was not activated under the configured name"
    }

    $renameCountBeforeFailure = $global:KaliMCPTestDockerRenameCount
    $commandCountBeforeFailure = $global:KaliMCPTestDockerCommands.Count
    $global:KaliMCPTestExistingImageID = "sha256:updated"
    $global:KaliMCPTestDesiredImageID = "sha256:newer"
    $global:KaliMCPTestDockerRunFails = $true
    $failedAsExpected = $false
    try {
        & $installer | Out-Null
    } catch {
        $failedAsExpected = $true
    }
    if (-not $failedAsExpected) {
        throw "installer unexpectedly succeeded after replacement creation failed"
    }
    if ($global:KaliMCPTestDockerRenameCount -ne $renameCountBeforeFailure) {
        throw "failed replacement renamed the existing container"
    }
    $failureCommands = @($global:KaliMCPTestDockerCommands[$commandCountBeforeFailure..($global:KaliMCPTestDockerCommands.Count - 1)])
    if ($failureCommands -contains "rm -f kali-mcp-windows-test") {
        throw "failed replacement removed the existing container"
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
    Remove-Variable -Name KaliMCPTestDockerPullCount -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable -Name KaliMCPTestDockerRemoveCount -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable -Name KaliMCPTestDockerRenameCount -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable -Name KaliMCPTestDockerCommands -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable -Name KaliMCPTestDockerRunFails -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable -Name KaliMCPTestExistingImageID -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable -Name KaliMCPTestDesiredImageID -Scope Global -ErrorAction SilentlyContinue
    Remove-Item $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}
