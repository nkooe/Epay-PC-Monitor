# 打包脚本：混淆编译 + 生成完整性校验 + 打 zip
#
# 用法：
#   .\build.ps1              编译当前版本
#   .\build.ps1 -Version 1.23
#
# 依赖：
#   garble（go install mvdan.cc/garble@latest）

param(
    [string]$Version = ""
)

$ErrorActionPreference = "Stop"
$dir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $dir

$env:PATH = "C:\Program Files\Go\bin;$env:USERPROFILE\go\bin;" + $env:PATH
$env:GOPROXY = "https://goproxy.cn,direct"
$env:GOSUMDB = "off"
$env:GOPATH = "$env:USERPROFILE\go"

# 版本号：不传就从 main.go 读
if ($Version -eq "") {
    $m = Select-String -Path "$dir\main.go" -Pattern 'AppVersion\s*=\s*"([^"]+)"' -Encoding UTF8
    if ($m) { $Version = $m.Matches[0].Groups[1].Value }
}
if ($Version -eq "") { throw "拿不到版本号" }
Write-Host "版本: v$Version" -ForegroundColor Cyan

# 1) 同步版本号到界面
$c = Get-Content "$dir\main.go" -Raw -Encoding UTF8
$c = [regex]::Replace($c, 'AppVersion\s*=\s*"[^"]+"', "AppVersion = `"$Version`"")
[System.IO.File]::WriteAllText("$dir\main.go", $c, (New-Object System.Text.UTF8Encoding($false)))

# 界面版本号由服务端用 __APP_VERSION__ 占位符替换，这里不再改 ui/index.html

# 2) garble 混淆编译
Write-Host "编译中（garble -literals -tiny）..." -ForegroundColor Yellow
$sw = [Diagnostics.Stopwatch]::StartNew()
& garble -literals -tiny build -ldflags="-H windowsgui -s -w" -o EasyMonitorPC.exe .
if ($LASTEXITCODE -ne 0) { throw "编译失败" }
$sw.Stop()
$sz = (Get-Item "$dir\EasyMonitorPC.exe").Length / 1MB
Write-Host ("  完成 {0:N2} MB  {1:N1}s" -f $sz, $sw.Elapsed.TotalSeconds) -ForegroundColor Green

# 3) 生成完整性校验
Write-Host "生成 integrity.dat..." -ForegroundColor Yellow
Remove-Item "$dir\integrity.dat" -Force -ErrorAction SilentlyContinue
& "$dir\EasyMonitorPC.exe" --write-integrity | Out-Null
if (-not (Test-Path "$dir\integrity.dat")) { throw "integrity.dat 生成失败" }
$hash = (Get-Content "$dir\integrity.dat" -Raw).Trim()
Write-Host "  $hash" -ForegroundColor DarkGray

# 4) 打两个 zip
$rel = "$dir\..\release_v$Version"
if (Test-Path $rel) { Remove-Item $rel -Recurse -Force }
New-Item -ItemType Directory -Path $rel -Force | Out-Null

Write-Host "打包 win64..." -ForegroundColor Yellow
$stage = "$env:TEMP\pkg_$Version"
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item -ItemType Directory -Path "$stage\native" -Force | Out-Null
Copy-Item "$dir\EasyMonitorPC.exe" "$stage\" -Force
Copy-Item "$dir\integrity.dat" "$stage\" -Force
Copy-Item "$dir\native\WCDB.dll" "$stage\native\" -Force
Copy-Item "$dir\native\wxtool_wcdb.dll" "$stage\native\" -Force
$hookDll = Get-ChildItem "$dir\native\easymon_hook*.dll","$dir\native\wxrt*.dll" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($hookDll) {
  # 发布用中性文件名，避免 native 目录里出现 hook 字样
  Copy-Item $hookDll.FullName "$stage\native\wxrt.dll" -Force
  $h = (Get-FileHash "$stage\native\wxrt.dll" -Algorithm SHA256).Hash.ToLower()
  Set-Content "$stage\native\wxrt.sha256" $h -Encoding ASCII -NoNewline
  Write-Host "  消息组件 $($hookDll.Name) -> wxrt.dll  sha256=$($h.Substring(0,16))..."
}
Compress-Archive -Path "$stage\*" -DestinationPath "$rel\EasyMonitorPC-v$Version-win64.zip" -Force
Remove-Item $stage -Recurse -Force

Write-Host "打包源码..." -ForegroundColor Yellow
$src = "$env:TEMP\src_$Version\EasyMonitorPC"
if (Test-Path "$env:TEMP\src_$Version") { Remove-Item "$env:TEMP\src_$Version" -Recurse -Force }
New-Item -ItemType Directory -Path "$src\native" -Force | Out-Null
Copy-Item "$dir\*.go" "$src\" -Force
Copy-Item "$dir\go.mod", "$dir\go.sum" "$src\" -Force -ErrorAction SilentlyContinue
Copy-Item "$dir\ui" "$src\ui" -Recurse -Force
Copy-Item "$dir\native\WCDB.dll" "$src\native\" -Force
Copy-Item "$dir\native\wxtool_wcdb.dll" "$src\native\" -Force
if (Test-Path "$dir\native\hookdll.c") { Copy-Item "$dir\native\hookdll.c" "$src\native\" -Force }
Compress-Archive -Path "$src" -DestinationPath "$rel\EasyMonitorPC-v$Version-src.zip" -Force
Remove-Item "$env:TEMP\src_$Version" -Recurse -Force

Write-Host ""
Write-Host "产物：" -ForegroundColor Cyan
Get-ChildItem $rel -File | ForEach-Object { Write-Host ("  {0}  {1:N2} MB" -f $_.Name, ($_.Length / 1MB)) }
Write-Host ""
Write-Host "SHA256 (exe): $hash" -ForegroundColor DarkGray
