$ErrorActionPreference = 'Stop'

# Configuration
$PythonUrl = "https://www.python.org/ftp/python/3.11.9/python-3.11.9-embed-amd64.zip"
$PythonDir = "$PSScriptRoot\python-runtime"
$AppDir = "$PSScriptRoot\src"
$ReqFile = "$PSScriptRoot\requirements.txt"

Write-Host "--- Monitorix Agent Bootstrap ---" -ForegroundColor Cyan

# 1. Check/Install Python
if (-not (Test-Path "$PythonDir\python.exe")) {
    Write-Host "Setting up local Python runtime..." -ForegroundColor Yellow
    New-Item -ItemType Directory -Force -Path $PythonDir | Out-Null
    
    # Download Embeddable Python
    $ZipPath = "$PythonDir\python.zip"
    Write-Host "Downloading Python Runtime (~25MB)..."
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $PythonUrl -OutFile $ZipPath -UseBasicParsing
    } catch {
        Write-Error "Failed to download Python: $_"
        exit 1
    }
    
    # Extract
    Write-Host "Extracting runtime..."
    Expand-Archive -Path $ZipPath -DestinationPath $PythonDir -Force
    Remove-Item -Path $ZipPath
    
    # Enable pip support (modify ._pth file to allow import site)
    $PthFile = Get-ChildItem "$PythonDir\*._pth" | Select-Object -First 1
    if ($PthFile) {
        $Content = Get-Content $PthFile.FullName
        $Content = $Content -replace "#import site", "import site"
        $Content | Set-Content $PthFile.FullName
    }
    
    # Install Pip
    Write-Host "Installing Pip..."
    Invoke-WebRequest "https://bootstrap.pypa.io/get-pip.py" -OutFile "$PythonDir\get-pip.py"
    & "$PythonDir\python.exe" "$PythonDir\get-pip.py" --no-warn-script-location
}

# 2. Install Dependencies
Write-Host "Installing dependencies..." -ForegroundColor Yellow
& "$PythonDir\python.exe" -m pip install -r $ReqFile --no-warn-script-location --disable-pip-version-check

# 3. Run Agent
Write-Host "Starting Monitorix Agent..." -ForegroundColor Green
$Env:PYTHONPATH = $AppDir
& "$PythonDir\python.exe" "$AppDir\main.py"
