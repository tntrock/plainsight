# 建置 dist\PlainSight.exe
# 用法：powershell -ExecutionPolicy Bypass -File build.ps1
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Test-Path .venv)) {
    Write-Host "建立虛擬環境 .venv ..."
    $py = (Get-Command python -ErrorAction SilentlyContinue).Source
    $real = Join-Path $env:LOCALAPPDATA "Programs\Python\Python312\python.exe"
    if ((-not $py) -or ($py -like "*WindowsApps*")) { $py = $real }
    & $py -m venv .venv
}
$venvPy = ".\.venv\Scripts\python.exe"
& $venvPy -m pip install --quiet --upgrade pip
& $venvPy -m pip install --quiet -e . pyinstaller pillow
if ($LASTEXITCODE -ne 0) { throw "pip install 失敗" }

if (-not (Test-Path packaging\plainsight.ico)) { & $venvPy packaging\make_icon.py }

Get-Process PlainSight -ErrorAction SilentlyContinue | Stop-Process -Force
& $venvPy -m PyInstaller --noconfirm --clean --distpath dist --workpath build packaging\plainsight.spec
if ($LASTEXITCODE -ne 0) { throw "PyInstaller 失敗" }

$exe = Get-Item dist\PlainSight.exe
Write-Host ""
Write-Host ("完成：{0}  ({1:N1} MB, {2})" -f $exe.FullName, ($exe.Length / 1MB), $exe.LastWriteTime)
