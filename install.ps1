function Show-Banner($title, $width = 80) {
    $left = [math]::Floor(($width - $title.Length) / 2)
    Write-Host ("*" * $width) -ForegroundColor Green
    Write-Host ((" " * $left) + $title) -ForegroundColor Green
    Write-Host ("*" * $width) -ForegroundColor Green
}


Show-Banner "Windows installation"


if (-not (Get-Command "python" -ErrorAction SilentlyContinue)) {
    Write-Host "[!] python is not installed. Please install it (3.11+)." -ForegroundColor Red
    exit 1
}

python -c "import sys; sys.exit(sys.version_info < (3, 11))"
if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] Python 3.11 or newer is required." -ForegroundColor Red
    exit 1
}

if (-not (Get-Command "git" -ErrorAction SilentlyContinue)) {
    Write-Host "[!] git is not installed. Please install it." -ForegroundColor Red
    exit 1
}

Write-Host "[+] Creating the .venv virtual environment..." -ForegroundColor Green
python -m venv .venv
$VenvPython = ".\.venv\Scripts\python.exe"

Write-Host "[+] Installing the project and the Python tools..." -ForegroundColor Green
& $VenvPython -m pip install --quiet --upgrade pip
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $VenvPython -m pip install --quiet -e ".[dev,tools]"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "[+] Installing the binaries (pinned versions and SHA-256)..." -ForegroundColor Green
# kubesec has no Windows binary: the Kubernetes module will report it.
& ".\.venv\Scripts\securepipeline.exe" tools install --yes
$InstallStatus = $LASTEXITCODE

Write-Host("")
Write-Host ("*" * 80)
if ($InstallStatus -eq 0) {
    Write-Host "Installation completed successfully!" -ForegroundColor Green
}
else {
    Write-Host "Installation finished, but some tools failed (see above)." -ForegroundColor Yellow
}
Write-Host "To start the tool:"
Write-Host "  .\.venv\Scripts\securepipeline.exe"
