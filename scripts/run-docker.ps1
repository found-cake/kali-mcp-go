& {
    $ErrorActionPreference = "Stop"
    Set-StrictMode -Version Latest

    $profileSha256 = "cc3e61cabda6bbc1e53e54d27ba4d55a9d3be829b6dd1a596f4a7b31b1cc7849"
    $profileUrl = "https://raw.githubusercontent.com/found-cake/kali-mcp-go/refs/heads/master/chromium-seccomp.json"
    $managedLabelName = "io.github.found-cake.kali-mcp.managed"

    function Get-InstallerSetting {
        param(
            [Parameter(Mandatory = $true)][string]$Name,
            [Parameter(Mandatory = $true)][string]$Default
        )

        $value = [Environment]::GetEnvironmentVariable($Name)
        if ([string]::IsNullOrWhiteSpace($value)) {
            return $Default
        }
        return $value.Trim()
    }

    function Test-SeccompProfile {
        param([Parameter(Mandatory = $true)][string]$Path)

        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            return $false
        }
        $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
        return $actual -eq $profileSha256
    }

    function Install-SeccompProfile {
        param(
            [Parameter(Mandatory = $true)][string]$Directory,
            [Parameter(Mandatory = $true)][string]$Path
        )

        New-Item -ItemType Directory -Path $Directory -Force | Out-Null
        $temporaryPath = Join-Path $Directory ([System.IO.Path]::GetRandomFileName())
        try {
            Invoke-WebRequest -UseBasicParsing -Uri $profileUrl -OutFile $temporaryPath
            if (-not (Test-SeccompProfile -Path $temporaryPath)) {
                throw "kali-mcp installer: Chromium seccomp profile checksum mismatch"
            }
            Move-Item -LiteralPath $temporaryPath -Destination $Path -Force
        } finally {
            Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
        }
    }

    function New-ApiToken {
        $bytes = New-Object byte[] 32
        $generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        try {
            $generator.GetBytes($bytes)
        } finally {
            $generator.Dispose()
        }
        return -join ($bytes | ForEach-Object { $_.ToString("x2") })
    }

    function Wait-KaliHealth {
        param([Parameter(Mandatory = $true)][string]$ContainerName)

        for ($attempt = 0; $attempt -lt 100; $attempt++) {
            & docker exec $ContainerName curl -fsS --max-time 1 http://127.0.0.1:5000/health *> $null
            if ($LASTEXITCODE -eq 0) {
                return $true
            }
            Start-Sleep -Milliseconds 100
        }
        return $false
    }

    function Write-Registration {
        param([Parameter(Mandatory = $true)][string]$ContainerName)

        @"
Kali MCP container '$ContainerName' is ready.

Register it with Codex:
  codex mcp add kali-mcp -- docker exec -i $ContainerName mcp-client --server http://127.0.0.1:5000 --timeout 3600

The MCP launcher command for other clients is:
  docker exec -i $ContainerName mcp-client --server http://127.0.0.1:5000 --timeout 3600
"@
    }

    if ($null -eq (Get-Command docker -ErrorAction SilentlyContinue)) {
        throw "kali-mcp installer: docker is required"
    }

    $imageName = Get-InstallerSetting -Name "KALI_MCP_DOCKER_IMAGE" -Default "ghcr.io/found-cake/kali-mcp-go:latest"
    $pullPolicy = Get-InstallerSetting -Name "KALI_MCP_DOCKER_PULL" -Default "always"
    $containerName = Get-InstallerSetting -Name "KALI_MCP_CONTAINER_NAME" -Default "kali-mcp"
    $localAppData = [Environment]::GetFolderPath([System.Environment+SpecialFolder]::LocalApplicationData)
    $cacheRoot = Get-InstallerSetting -Name "XDG_CACHE_HOME" -Default $localAppData
    if ([string]::IsNullOrWhiteSpace($cacheRoot)) {
        throw "kali-mcp installer: XDG_CACHE_HOME or LOCALAPPDATA is required"
    }
    $profileDirectory = Join-Path $cacheRoot "kali-mcp"
    $profilePath = Join-Path $profileDirectory "chromium-seccomp.json"
    $runPullPolicy = $pullPolicy
    $runContainerName = $containerName
    $replaceExisting = $false

    & docker container inspect $containerName *> $null
    if ($LASTEXITCODE -eq 0) {
        $existingLabel = (& docker inspect --format '{{ index .Config.Labels "io.github.found-cake.kali-mcp.managed" }}' $containerName 2>$null | Out-String).Trim()
        if ($existingLabel -ne "true") {
            throw "kali-mcp installer: container '$containerName' already exists and is not managed by this installer"
        }
        $reuseExisting = $true
        if ($pullPolicy -eq "always") {
            & docker pull $imageName | Out-Null
            if ($LASTEXITCODE -ne 0) {
                throw "kali-mcp installer: failed to pull image '$imageName'"
            }
            $existingImageID = (& docker inspect --format '{{ .Image }}' $containerName | Out-String).Trim()
            $desiredImageID = (& docker image inspect --format '{{ .Id }}' $imageName | Out-String).Trim()
            if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($desiredImageID)) {
                throw "kali-mcp installer: failed to inspect image '$imageName'"
            }
            if ($existingImageID -ne $desiredImageID) {
                $reuseExisting = $false
                $runPullPolicy = "never"
                $runContainerName = "{0}-candidate-{1}" -f $containerName, [guid]::NewGuid().ToString("N").Substring(0, 12)
                $replaceExisting = $true
            }
        }
        if ($reuseExisting) {
            $running = (& docker inspect --format '{{ .State.Running }}' $containerName | Out-String).Trim()
            if ($running -ne "true") {
                & docker start $containerName | Out-Null
                if ($LASTEXITCODE -ne 0) {
                    throw "kali-mcp installer: failed to start existing container '$containerName'"
                }
            }
            if (-not (Wait-KaliHealth -ContainerName $containerName)) {
                throw "kali-mcp installer: existing container '$containerName' failed its health check"
            }
            Write-Registration -ContainerName $containerName
            return
        }
    }

    if (-not (Test-SeccompProfile -Path $profilePath)) {
        Install-SeccompProfile -Directory $profileDirectory -Path $profilePath
    }

    $apiToken = New-ApiToken
    $dockerArguments = @(
        "run", "--pull=$runPullPolicy", "-d", "--name", $runContainerName,
        "--restart", "unless-stopped", "--init",
        "--add-host", "host.docker.internal:host-gateway", "--shm-size=512m",
        "--security-opt", "seccomp=$profilePath",
        "--label", "$managedLabelName=true",
        "-e", "KALI_MCP_API_TOKEN=$apiToken", "--entrypoint", "kali-server",
        $imageName, "--ip", "127.0.0.1", "--port", "5000"
    )
    & docker @dockerArguments | Out-Null
    if ($LASTEXITCODE -ne 0) {
        & docker rm -f $runContainerName *> $null
        throw "kali-mcp installer: failed to create replacement container"
    }

    if (-not (Wait-KaliHealth -ContainerName $runContainerName)) {
        & docker logs --tail 100 $runContainerName
        & docker rm -f $runContainerName *> $null
        throw "kali-mcp installer: new container failed its health check and was removed"
    }

    if ($replaceExisting) {
        $backupName = "{0}-previous-{1}" -f $containerName, [guid]::NewGuid().ToString("N").Substring(0, 12)
        & docker rename $containerName $backupName | Out-Null
        if ($LASTEXITCODE -ne 0) {
            & docker rm -f $runContainerName *> $null
            throw "kali-mcp installer: failed to stage the existing container for replacement"
        }
        & docker rename $runContainerName $containerName | Out-Null
        if ($LASTEXITCODE -ne 0) {
            & docker rename $backupName $containerName *> $null
            & docker rm -f $runContainerName *> $null
            throw "kali-mcp installer: failed to activate the replacement container"
        }
        & docker rm -f $backupName | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "kali-mcp installer: replacement is healthy, but the previous container '$backupName' could not be removed"
        }
    }

    Write-Registration -ContainerName $containerName
}
