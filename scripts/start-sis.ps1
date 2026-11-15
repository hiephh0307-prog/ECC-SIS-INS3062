param(
    [switch]$NoWait,
    [switch]$NoBrowser,
    [int]$PreferredPort = 8000
)

$ErrorActionPreference = "Stop"
[Console]::InputEncoding  = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13

$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location -LiteralPath $ProjectRoot

function Write-Banner {
    Write-Host ""
    Write-Host "  ======================================================================" -ForegroundColor Cyan
    Write-Host "     ECC-SIS  —  HE THONG THONG TIN BAO MAT (INS306202 - VNU-IS)       " -ForegroundColor Yellow
    Write-Host "     Trinh Khoi Chay Web 1 Cham (Python FastAPI + WebCrypto P-256)      " -ForegroundColor Gray
    Write-Host "  ======================================================================" -ForegroundColor Cyan
    Write-Host "  Thu muc du an : $ProjectRoot" -ForegroundColor DarkGray
    Write-Host ""
}

function Write-Step([string]$Step, [string]$Message) {
    Write-Host "  [$Step] " -ForegroundColor Cyan -NoNewline
    Write-Host $Message -ForegroundColor White
}

function Write-Ok([string]$Message) {
    Write-Host "  [OK] " -ForegroundColor Green -NoNewline
    Write-Host $Message -ForegroundColor Gray
}

function Write-Warn([string]$Message) {
    Write-Host "  [!]  " -ForegroundColor Yellow -NoNewline
    Write-Host $Message -ForegroundColor Yellow
}

function Start-DetachedProcess([string]$CommandLine, [string]$WorkingDir, [bool]$Hidden = $true) {
    try {
        $startup = New-CimInstance -ClassName Win32_ProcessStartup -Property @{
            ShowWindow = [uint16]($(if ($Hidden) { 0 } else { 1 }))
        } -ClientOnly
        $res = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{
            CommandLine               = $CommandLine
            CurrentDirectory          = $WorkingDir
            ProcessStartupInformation = $startup
        }
        if ($res.ReturnValue -eq 0 -and $res.ProcessId) {
            return [int]$res.ProcessId
        }
    } catch {}
    return 0
}

function Get-DefaultBrowserExecutable {
    foreach ($scheme in @("http", "https")) {
        try {
            $regPath = "HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\$scheme\UserChoice"
            $progId = (Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue).ProgId
            if ($progId) {
                $cmdRaw = (Get-ItemProperty -Path "Registry::HKEY_CLASSES_ROOT\$progId\shell\open\command" -ErrorAction SilentlyContinue).'(default)'
                if ($cmdRaw -and ($cmdRaw -match '^"([^"]+\.exe)"')) {
                    $exePath = $Matches[1]
                    if (Test-Path -LiteralPath $exePath) {
                        return [PSCustomObject]@{ ProgId = $progId; ExePath = $exePath }
                    }
                }
            }
        } catch {}
    }
    return $null
}

function Open-SisBrowser([string]$Url) {
    $defaultBrowser = Get-DefaultBrowserExecutable
    if ($defaultBrowser -and $defaultBrowser.ExePath) {
        $exe = $defaultBrowser.ExePath
        Write-Ok "Đang mở trình duyệt mặc định ($($defaultBrowser.ProgId)) tại: $Url"
        $pidOut = Start-DetachedProcess -CommandLine """$exe"" ""$Url""" -WorkingDir $ProjectRoot -Hidden $false
        if ($pidOut -gt 0) { return }
        try { Start-Process -FilePath $exe -ArgumentList $Url -ErrorAction Stop | Out-Null; return } catch {}
    }
    try {
        Start-Process -FilePath $Url -ErrorAction Stop | Out-Null
        Write-Ok "Đang mở trình duyệt mặc định Windows tại: $Url"
        return
    } catch {}

    $browserMatrix = @(
        @{ Name = "Brave";           Path = "$env:ProgramFiles\BraveSoftware\Brave-Browser\Application\brave.exe" },
        @{ Name = "Brave (x86)";     Path = "${env:ProgramFiles(x86)}\BraveSoftware\Brave-Browser\Application\brave.exe" },
        @{ Name = "Brave (User)";    Path = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\Application\brave.exe" },
        @{ Name = "Cốc Cốc";         Path = "$env:LOCALAPPDATA\CocCoc\Browser\Application\browser.exe" },
        @{ Name = "Google Chrome";   Path = "$env:ProgramFiles\Google\Chrome\Application\chrome.exe" },
        @{ Name = "Chrome (x86)";    Path = "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe" },
        @{ Name = "Microsoft Edge";  Path = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe" },
        @{ Name = "Edge (x64)";      Path = "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe" },
        @{ Name = "Mozilla Firefox"; Path = "$env:ProgramFiles\Mozilla Firefox\firefox.exe" },
        @{ Name = "Opera";           Path = "$env:LOCALAPPDATA\Programs\Opera\opera.exe" }
    )
    foreach ($b in $browserMatrix) {
        if ($b.Path -and (Test-Path -LiteralPath $b.Path)) {
            Write-Ok "Đang mở trình duyệt $($b.Name) tại: $Url"
            $pidOut = Start-DetachedProcess -CommandLine """$($b.Path)"" ""$Url""" -WorkingDir $ProjectRoot -Hidden $false
            if ($pidOut -eq 0) { Start-Process -FilePath $b.Path -ArgumentList $Url | Out-Null }
            return
        }
    }
    Start-Process "rundll32.exe" -ArgumentList "url.dll,FileProtocolHandler $Url" | Out-Null
}

function Test-PortInUse([int]$Port) {
    foreach ($hostAddr in @("127.0.0.1", "::1")) {
        $client = New-Object System.Net.Sockets.TcpClient
        try {
            $async = $client.BeginConnect($hostAddr, $Port, $null, $null)
            $wait = $async.AsyncWaitHandle.WaitOne(300, $false)
            if ($wait -and $client.Connected) { return $true }
        } catch {} finally { $client.Close() }
    }
    return $false
}

function Test-SisRunningOnPort([int]$Port) {
    foreach ($hostAddr in @("127.0.0.1", "localhost")) {
        try {
            $req = [System.Net.HttpWebRequest]::Create("http://${hostAddr}:$Port/api/users")
            $req.Proxy = $null
            $req.Timeout = 1500
            $resp = [System.Net.HttpWebResponse]$req.GetResponse()
            $code = [int]$resp.StatusCode
            $reader = New-Object System.IO.StreamReader($resp.GetResponseStream())
            $body = $reader.ReadToEnd()
            $reader.Close()
            $resp.Close()
            if ($code -eq 200 -and ($body -match '"users"')) { return $true }
        } catch {}
    }
    return $false
}

function Find-PythonExe {
    foreach ($name in @("python.exe", "python3.exe")) {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue
        if ($cmd -and $cmd.Source -and ($cmd.Source -notmatch "WindowsApps\\python")) {
            return $cmd.Source
        }
    }
    $searchDirs = @(
        "$env:LOCALAPPDATA\Programs\Python\Python312",
        "$env:LOCALAPPDATA\Programs\Python\Python311",
        "$env:LOCALAPPDATA\Programs\Python\Python313",
        "$env:LOCALAPPDATA\Programs\Python\Python310",
        "$env:ProgramFiles\Python312",
        "$env:ProgramFiles\Python311",
        "C:\Python312",
        "C:\Python311"
    )
    foreach ($d in $searchDirs) {
        $exe = Join-Path $d "python.exe"
        if (Test-Path -LiteralPath $exe) { return $exe }
    }
    return $null
}

Write-Banner

if (Test-SisRunningOnPort -Port $PreferredPort) {
    $activeUrl = "http://127.0.0.1:$PreferredPort"
    Write-Ok "Phát hiện máy chủ ECC-SIS đang chạy sẵn tại: $activeUrl"
    if (-not $NoBrowser) { Open-SisBrowser -Url $activeUrl }
    if (-not $NoWait) { Start-Sleep -Seconds 2 }
    exit 0
}

$pyExe = Find-PythonExe
if (-not $pyExe) {
    $winget = Get-Command winget.exe -ErrorAction SilentlyContinue
    if ($winget) {
        Write-Step "1/3" "Máy chưa cài Python. Đang tự động cài Python 3.12 qua Windows winget..."
        & winget install -e --id Python.Python.3.12 --silent --accept-package-agreements --accept-source-agreements
        $pyExe = Find-PythonExe
    }
    if (-not $pyExe) {
        Write-Warn "Máy tính chưa cài Python 3.10+. Vui lòng tải bản Windows 64-bit tại: https://www.python.org/downloads/ (tích chọn 'Add python.exe to PATH'), sau đó bấm lại run.bat!"
        exit 1
    }
}
Write-Ok "Sử dụng Python: $pyExe"

Write-Step "1/2" "Kiểm tra thư viện fastapi & uvicorn..."
$prevPref = $ErrorActionPreference
$ErrorActionPreference = "Continue"
& $pyExe -c "import fastapi, uvicorn" >$null 2>&1
$importRc = $LASTEXITCODE
$ErrorActionPreference = $prevPref
if ($importRc -ne 0) {
    Write-Warn "Đang tự động cài đặt fastapi và uvicorn từ requirements.txt..."
    & $pyExe -m pip install -r (Join-Path $ProjectRoot "requirements.txt")
    if ($LASTEXITCODE -ne 0) {
        throw "Không cài được fastapi/uvicorn. Hãy kiểm tra kết nối mạng."
    }
}

$targetPort = $PreferredPort
while (Test-PortInUse -Port $targetPort) {
    Write-Warn "Cổng $targetPort đang bận, tự động chuyển sang cổng $($targetPort + 1)..."
    $targetPort++
}
$targetUrl = "http://127.0.0.1:$targetPort"

Write-Step "2/2" "Khởi động máy chủ ECC-SIS ngầm tại $targetUrl ..."
$wmiCmd = """$pyExe"" -m uvicorn sis_app.main:app --host 127.0.0.1 --port $targetPort"
$spawnedPid = Start-DetachedProcess -CommandLine $wmiCmd -WorkingDir $ProjectRoot -Hidden $true
if ($spawnedPid -eq 0) {
    $p = Start-Process -FilePath $pyExe -ArgumentList @("-m", "uvicorn", "sis_app.main:app", "--host", "127.0.0.1", "--port", "$targetPort") -WorkingDirectory $ProjectRoot -WindowStyle Hidden -PassThru
    $spawnedPid = $p.Id
}

$ready = $false
for ($i = 0; $i -lt 50; $i++) {
    Start-Sleep -Milliseconds 300
    if (Test-SisRunningOnPort -Port $targetPort) {
        $ready = $true
        break
    }
}

if ($ready) {
    Write-Ok "Máy chủ ECC-SIS đã chạy ổn định tại $targetUrl (PID: $spawnedPid)!"
} else {
    Write-Warn "Máy chủ đang hoàn tất khởi động tại $targetUrl ..."
}

if (-not $NoBrowser) {
    Open-SisBrowser -Url $targetUrl
}

Write-Host ""
Write-Host "  ======================================================================" -ForegroundColor Green
Write-Host "   WEB ECC-SIS DA SAN SANG TAI : $targetUrl" -ForegroundColor Green
Write-Host "   (Hoạt động trọn vẹn 4 Tab: E2EE, Lab toán, Benchmark, Kiểm toán)" -ForegroundColor Yellow
Write-Host "  ======================================================================" -ForegroundColor Green
Write-Host ""

if (-not $NoWait) {
    Start-Sleep -Seconds 3
}
exit 0
