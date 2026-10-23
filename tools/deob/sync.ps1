# sync.ps1 - keep tools\deob byte-identical to the research tree
#
#   powershell -File tools\deob\sync.ps1                 # copy from ..\..\..\_analysis
#   powershell -File tools\deob\sync.ps1 -Check          # exit 1 if anything drifted
#   powershell -File tools\deob\sync.ps1 -From <dir>     # explicit source directory
#
# The files are developed in _analysis/ (parent of this repo) and published
# here; identical bytes mean one command proves they have not diverged.
param(
    [string]$From = "",
    [switch]$Check
)
$ErrorActionPreference = "Stop"
$here = $PSScriptRoot
if (-not $From) { $From = Join-Path $here "..\..\..\_analysis" }
$From = (Resolve-Path $From).Path

$files = @("autodeob.py", "cfgpass.py", "defus.py", "oreandec.py", "unpack.py",
           "peread.py", "cli.py", "vmtrace.py", "vmlift.py", "vminline.py",
           "vmfix.py")

$drift = @()
foreach ($f in $files) {
    $src = Join-Path $From $f
    $dst = Join-Path $here $f
    if (-not (Test-Path $src)) { throw "missing source: $src" }
    $a = (Get-FileHash $src -Algorithm SHA256).Hash
    $b = if (Test-Path $dst) { (Get-FileHash $dst -Algorithm SHA256).Hash } else { "" }
    if ($a -eq $b) { continue }
    $drift += $f
    if (-not $Check) { Copy-Item $src $dst -Force }
}

if ($Check) {
    if ($drift.Count) {
        "drift: $($drift -join ', ')  (run without -Check to copy)"
        exit 1
    }
    "in sync: $($files.Count) files"
    exit 0
}
if ($drift.Count) { "copied: $($drift -join ', ')" } else { "already in sync: $($files.Count) files" }
exit 0
