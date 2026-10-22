# build_exe.ps1 - freeze tools\OreanOffline.py into one OreanOffline.exe
#
#   powershell -ExecutionPolicy Bypass -File GhidrOrean\tools\build_exe.ps1
#   powershell -ExecutionPolicy Bypass -File GhidrOrean\tools\build_exe.ps1 -Name XemDrop -OneDir
#
# The result is a drag & drop target: drop one or more sample files on the
# .exe and unpack -> decode -> dejunk run next to the sample (the exe pauses
# before closing so the summary stays readable).  It is written outside the
# repo on purpose - binaries do not belong in git; use -Out to place it.
#
# Only the CPython offline tools are frozen.  Orean.py itself needs a running
# Ghidra and cannot be an .exe; run it there (or through analyzeHeadless).
param(
    [string]$Name = "OreanOffline",
    [switch]$OneDir,
    [string]$Out = ""
)
$ErrorActionPreference = "Stop"
$tools = $PSScriptRoot
$repo = Split-Path -Parent $tools              # GhidrOrean: xrkdsm.py, thobfus.py, ...
if (-not $Out) { $Out = Join-Path $env:TEMP "oreans-exe" }
$work = Join-Path $env:TEMP "pyi-oreans-offline\build"
$spec = Join-Path $env:TEMP "pyi-oreans-offline\spec"

python -c "import PyInstaller" 2>$null
if ($LASTEXITCODE -ne 0) { throw "PyInstaller not installed: python -m pip install pyinstaller" }

# rebuild from scratch: a leftover module from an older build would shadow the
# one we ship (the same trap the old _analysis\py3 copies set)
Remove-Item $work, $spec -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $work, $spec, $Out | Out-Null

$mode = if ($OneDir) { "--onedir" } else { "--onefile" }
python -m PyInstaller --noconfirm --clean $mode --console --name $Name `
    --distpath $Out --workpath $work --specpath $spec `
    --paths $tools --paths $repo `
    --hidden-import xrkdsm --hidden-import xrkutil --hidden-import xrktbl `
    --hidden-import xrkopr --hidden-import xrkasm --hidden-import thobfus `
    (Join-Path $tools "OreanOffline.py")
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed (see $work)" }

$exe = if ($OneDir) { Join-Path $Out "$Name\$Name.exe" } else { Join-Path $Out "$Name.exe" }
"built: $exe ($([math]::Round((Get-Item $exe).Length / 1MB, 1)) MB)"
"try:   `"$exe`" <sample.xem> --out <dir>   (or drag a file onto it)"
# a successful build must not inherit a non-zero exit code from earlier probes
exit 0
