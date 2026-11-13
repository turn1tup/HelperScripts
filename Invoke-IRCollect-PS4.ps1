<#
.SYNOPSIS
    Windows Server 入侵排查信息采集脚本（只读、兼容 PowerShell 4.0 / 5.x）

.DESCRIPTION
    针对本次事件（PD-S96 入侵）编写的主机侧排查采集器。脚本只做枚举与读取，
    不修改系统、不执行任何可疑文件、不删除任何文件，可在生产机上安全运行。

    本文件是 Invoke-IRCollect.ps1 的 PowerShell 4.0 兼容版，与 5.1 版的差异仅在兼容性处理：
      - #Requires 降为 4.0，去掉 Windows PowerShell 5.0+ 专属语法与参数
      - Get-ChildItem -Depth（PS 5.0+ 才有）改为 .NET 目录遍历，深度语义保持一致
      - Compress-Archive（PS 5.0+ 才有）改为 .NET ZipFile 打包，失败不影响采集结果
      - 哈希表字面量中的 if 语句改为先赋值，避免低版本解析失败
    采集内容与输出文件命名与 5.1 版完全一致。

    采集内容：
      00 系统与主机信息 / 权限自检
      01 本地账号与管理员组（含新建账号识别）
      02 服务（非系统路径、未加引号路径、可疑启动账号）
      03 计划任务（非 Microsoft）
      04 注册表持久化（Run/RunOnce/Winlogon/IFEO/AppInit）
      05 WMI 事件订阅持久化
      06 网络连接 / 监听端口 / ARP / DNS 缓存
      07 共享、会话、已挂载网络驱动器
      08 近期新增可疑文件（含哈希与数字签名）
      09 Web 目录与 Webshell 扫描（JSP/ASPX/PHP）
      10 进程（路径、命令行、属主、签名）
      11 Kerberos 票据与会话
      12 关键事件日志（登录、票据、账号变更、服务安装、日志清空）
      13 PowerShell 历史命令
      14 Defender 与防火墙状态（含排除项）
      15 安全配置基线（SMB1/WinRM/RDP/LLMNR/NBT-NS/WPAD/hosts）
      16 本地 SQL Server 配置（xp_cmdshell、sysadmin、作业明文口令）
      17 IOC 定向扫描（本次事件已知文件名/目录特征）
      99 汇总报告 + 采集包哈希清单

.PARAMETER OutputPath
    采集结果根目录，默认 C:\IR_Collect。每个主机每次运行会生成一个独立子目录。

.PARAMETER Days
    回溯天数，默认 7。用于“近期文件”“事件日志”等时间过滤。

.PARAMETER MaxEvents
    单个事件 ID 最多读取条数，默认 3000，避免日志量过大拖慢主机。

.PARAMETER SkipWebScan
    跳过 Web 目录递归扫描（目录很大时可用）。

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\Invoke-IRCollect-PS4.ps1

.EXAMPLE
    .\Invoke-IRCollect-PS4.ps1 -OutputPath D:\IR -Days 14 -MaxEvents 5000

.NOTES
    适用 PowerShell 4.0 及以上（Windows Server 2012 R2 默认自带 4.0）。
    必须以“管理员”身份运行，否则事件日志、票据、服务路径等信息会缺失。
    建议先将脚本复制到目标机本地磁盘再执行，输出目录不要放在被排查的业务数据盘上。
#>

#Requires -Version 4.0
[CmdletBinding()]
param(
    [string]$OutputPath = 'C:\IR_Collect',
    [int]$Days = 7,
    [int]$MaxEvents = 3000,
    [switch]$SkipWebScan
)

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'
$WarningPreference     = 'SilentlyContinue'

# ============================================================
# 初始化
# ============================================================
$Stamp   = Get-Date -Format 'yyyyMMdd_HHmmss'
$HostTag = $env:COMPUTERNAME
$OutDir  = Join-Path $OutputPath ("IR_{0}_{1}" -f $HostTag, $Stamp)
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$LogFile  = Join-Path $OutDir '00_collect.log'
$StartAt  = Get-Date
$Summary  = New-Object System.Collections.Generic.List[string]

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $line = '[{0}] [{1}] {2}' -f (Get-Date -Format 'HH:mm:ss'), $Level, $Message
    Add-Content -Path $LogFile -Value $line -Encoding UTF8
    Write-Host $line
}

function Save-Csv {
    param($Data, [string]$Name)
    if ($null -eq $Data -or @($Data).Count -eq 0) {
        Add-Content -Path (Join-Path $OutDir $Name) -Value 'NoData' -Encoding UTF8
        return 0
    }
    $Data | Export-Csv -Path (Join-Path $OutDir $Name) -NoTypeInformation -Encoding UTF8
    return @($Data).Count
}

function Save-Text {
    param([string[]]$Lines, [string]$Name)
    Set-Content -Path (Join-Path $OutDir $Name) -Value $Lines -Encoding UTF8
}

function Save-Cmd {
    param([string]$Command, [string]$Name)
    $result = cmd.exe /c "$Command 2>&1"
    Save-Text -Lines @("### $Command", '') -Name $Name
    Add-Content -Path (Join-Path $OutDir $Name) -Value ($result | Out-String) -Encoding UTF8
}

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    return $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# PowerShell 4.0 的 Get-ChildItem 没有 -Depth 参数（5.0 才引入），
# 这里用 .NET 目录枚举实现同样的语义：$Depth=0 表示只取根目录下的文件，
# $Depth=4 表示向下最多 4 层。跳过重解析点，避免符号链接/挂载点导致死循环。
function Get-FileByDepth {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [int]$Depth = 1
    )
    $rootInfo = $null
    try { $rootInfo = New-Object System.IO.DirectoryInfo($Path) } catch { return }
    if (-not $rootInfo.Exists) { return }

    $queue = New-Object System.Collections.Queue
    $queue.Enqueue([pscustomobject]@{ Dir = $rootInfo; Level = 0 })

    while ($queue.Count -gt 0) {
        $cur   = $queue.Dequeue()
        $dir   = $cur.Dir
        $level = $cur.Level

        $files = $null
        try { $files = $dir.GetFiles() } catch { $files = @() }
        foreach ($f in $files) { $f }

        if ($level -ge $Depth) { continue }

        $subs = $null
        try { $subs = $dir.GetDirectories() } catch { $subs = @() }
        foreach ($sd in $subs) {
            if (($sd.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
            $queue.Enqueue([pscustomobject]@{ Dir = $sd; Level = ($level + 1) })
        }
    }
}

$IsAdmin = Test-IsAdmin
$Cutoff  = (Get-Date).AddDays(-$Days)
$SigCache = @{}

function Get-HashSafe {
    param([string]$Path, [long]$MaxBytes = 100MB)
    try {
        $len = (Get-Item $Path -ErrorAction Stop).Length
        if ($len -gt $MaxBytes) { return "SKIPPED_GT_$([int]($MaxBytes/1MB))MB" }
        return (Get-FileHash $Path -Algorithm SHA256 -ErrorAction Stop).Hash
    } catch {
        return ''
    }
}

function Get-SigInfo {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    if ($SigCache.ContainsKey($Path)) { return $SigCache[$Path] }
    $r = $null
    try {
        $s = Get-AuthenticodeSignature -FilePath $Path -ErrorAction Stop
        $signer = ''
        if ($s.SignerCertificate) { $signer = $s.SignerCertificate.Subject }
        $r = [pscustomobject]@{
            Status = $s.Status.ToString()
            Signer = $signer
        }
    } catch {
        $r = [pscustomobject]@{ Status = 'Unavailable'; Signer = '' }
    }
    $SigCache[$Path] = $r
    return $r
}

Write-Log "采集开始 host=$HostTag admin=$IsAdmin days=$Days out=$OutDir ps=$($PSVersionTable.PSVersion.ToString()) os=$([Environment]::OSVersion.Version)"
if (-not $IsAdmin) {
    Write-Log '非管理员运行，事件日志/票据/进程属主等信息将不完整' 'WARN'
}
$Summary.Add("# 主机排查报告 - $HostTag")
$Summary.Add('')
$Summary.Add("- 采集时间：$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
$Summary.Add("- 运行身份：$([Security.Principal.WindowsIdentity]::GetCurrent().Name)（管理员：$IsAdmin）")
$Summary.Add("- 回溯窗口：最近 $Days 天")
$Summary.Add("- 输出目录：``$OutDir``")
$Summary.Add('')

# ============================================================
# 00 系统与主机信息
# ============================================================
Write-Log '采集：系统信息'
$os   = Get-CimInstance Win32_OperatingSystem
$cs   = Get-CimInstance Win32_ComputerSystem
$bios = Get-CimInstance Win32_BIOS

$sysInfo = [pscustomobject]@{
    ComputerName     = $env:COMPUTERNAME
    Domain           = $cs.Domain
    PartOfDomain     = $cs.PartOfDomain
    OS               = $os.Caption
    Version          = $os.Version
    BuildNumber      = $os.BuildNumber
    Architecture     = $os.OSArchitecture
    InstallDate      = $os.InstallDate
    LastBootUpTime   = $os.LastBootUpTime
    UptimeDays       = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalDays, 1)
    TimeZone         = (Get-TimeZone).Id
    Manufacturer     = $cs.Manufacturer
    Model            = $cs.Model
    SerialNumber     = $bios.SerialNumber
    TotalMemoryGB    = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
    PSVersion        = $PSVersionTable.PSVersion.ToString()
    CurrentUser      = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    IsAdmin          = $IsAdmin
    SystemDrive      = $env:SystemDrive
}
Save-Csv -Data $sysInfo -Name '00_SystemInfo.csv' | Out-Null
Save-Cmd -Command 'systeminfo' -Name '00_systeminfo_raw.txt' | Out-Null

# 磁盘
$disks = Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' |
    Select-Object DeviceID,
        @{n='SizeGB';e={[math]::Round($_.Size/1GB,1)}},
        @{n='FreeGB';e={[math]::Round($_.FreeSpace/1GB,1)}},
        VolumeName
Save-Csv -Data $disks -Name '00_Disks.csv' | Out-Null

# 最近补丁
$hotfix = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 15 HotFixID, Description, InstalledOn
Save-Csv -Data $hotfix -Name '00_RecentHotfix.csv' | Out-Null

# ============================================================
# 01 本地账号与管理员组
# ============================================================
Write-Log '采集：本地账号'
$users = @()
try {
    $users = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" |
        Select-Object Name, SID, Disabled, Lockout, PasswordRequired, PasswordChangeable, Description
} catch {
    $users = @()
}
# 补充本地配置文件创建时间（用于识别新建账号）
$profiles = @()
$profReg = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
Get-ChildItem $profReg | ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    $created = $null
    if ($p.ProfileImagePath -and (Test-Path $p.ProfileImagePath)) {
        $created = (Get-Item $p.ProfileImagePath).CreationTime
    }
    $profiles += [pscustomobject]@{
        SID            = Split-Path $_.PSPath -Leaf
        ProfilePath    = $p.ProfileImagePath
        ProfileCreated = $created
    }
}
$userRows = foreach ($u in $users) {
    $pf = $profiles | Where-Object { $_.SID -eq $u.SID } | Select-Object -First 1
    $isNew = ''
    if ($pf.ProfileCreated -and $pf.ProfileCreated -gt $Cutoff) { $isNew = 'YES' }
    [pscustomobject]@{
        Name             = $u.Name
        SID              = $u.SID
        Disabled         = $u.Disabled
        Lockout          = $u.Lockout
        Description      = $u.Description
        ProfilePath      = $pf.ProfilePath
        ProfileCreated   = $pf.ProfileCreated
        CreatedRecently  = $isNew
    }
}
Save-Csv -Data $userRows -Name '01_LocalUsers.csv' | Out-Null

# 管理员组（Get-LocalGroupMember 仅 PS 5.1+/新版系统可用，低版本自动回退 net localgroup）
$admins = @()
if (Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue) {
    try {
        $admins = Get-LocalGroupMember -Group 'Administrators' |
            Select-Object Name, ObjectClass, PrincipalSource
    } catch {
        $admins = @()
    }
}
if (@($admins).Count -eq 0) {
    $admins = net localgroup Administrators 2>$null |
        Where-Object { $_ -and $_ -notmatch '^Alias name|^Comment|^Members|^-----|^The command completed|^别名|^注释|^成员|^命令成功完成' } |
        ForEach-Object {
            [pscustomobject]@{ Name = $_.Trim(); ObjectClass = ''; PrincipalSource = '' }
        }
}
Save-Csv -Data $admins -Name '01_Administrators.csv' | Out-Null
Save-Cmd -Command 'net user' -Name '01_net_user.txt' | Out-Null
Save-Cmd -Command 'net localgroup administrators' -Name '01_net_localgroup_admin.txt' | Out-Null

# 登录会话
Save-Cmd -Command 'query user' -Name '01_logged_on_users.txt' | Out-Null

# ============================================================
# 02 服务
# ============================================================
Write-Log '采集：服务'
$svc = Get-CimInstance Win32_Service | ForEach-Object {
    $path = $_.PathName
    $exe  = $null
    if ($path) {
        $m = [regex]::Match($path, '^"([^"]+)"|^(.+?\.exe)')
        if ($m.Success) {
            if ($m.Groups[1].Success) { $exe = $m.Groups[1].Value }
            elseif ($m.Groups[2].Success) { $exe = $m.Groups[2].Value.Trim() }
        }
    }
    $flags = New-Object System.Collections.Generic.List[string]
    if ($path) {
        # Defender 自身运行在 ProgramData 下，排除以免误报
        $isDefender = ($path -match 'ProgramData\\Microsoft\\Windows Defender\\')
        if (-not $isDefender) {
            if ($path -match 'Users\\Public|[\\/]Temp[\\/]|ProgramData|[\\/]AppData[\\/]') { $flags.Add('SUSPICIOUS_DIR') }
            if ($exe -and $path -notmatch '^\s*"' -and $exe -match '\s') { $flags.Add('UNQUOTED_PATH') }
            if ($exe -and $exe -notmatch '^[A-Za-z]:\\Windows\\' -and $exe -notmatch '^[A-Za-z]:\\Program Files') {
                $flags.Add('NON_SYSTEM_PATH')
                $sig = Get-SigInfo $exe
                if ($sig -and $sig.Status -ne 'Valid') { $flags.Add('UNSIGNED') }
            }
        }
    }
    [pscustomobject]@{
        Name        = $_.Name
        DisplayName = $_.DisplayName
        State       = $_.State
        StartMode   = $_.StartMode
        StartName   = $_.StartName
        ProcessId   = $_.ProcessId
        PathName    = $path
        Suspicious  = ($flags -join ';')
    }
}
Save-Csv -Data $svc -Name '02_Services.csv' | Out-Null
Save-Cmd -Command 'sc query type= service state= all' -Name '02_sc_query.txt' | Out-Null

# ============================================================
# 03 计划任务
# ============================================================
Write-Log '采集：计划任务'
$tasks = @()
try {
    $tasks = Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } | ForEach-Object {
        $t = $_
        $act = ($t.Actions | ForEach-Object {
            if ($_.Execute) { "$($_.Execute) $($_.Arguments)" } else { $_.ToString() }
        }) -join ' | '
        $trg = ($t.Triggers | ForEach-Object { $_.CimClass.CimClassName }) -join ' | '
        [pscustomobject]@{
            TaskName = $t.TaskName
            TaskPath = $t.TaskPath
            State    = $t.State
            Author   = $t.Author
            UserId   = $t.Principal.UserId
            RunLevel = $t.Principal.RunLevel
            Action   = $act
            Trigger  = $trg
        }
    }
} catch {
    Write-Log 'Get-ScheduledTask 不可用，改用 schtasks' 'WARN'
}
Save-Csv -Data $tasks -Name '03_ScheduledTasks.csv' | Out-Null
Save-Cmd -Command 'schtasks /query /fo LIST /v' -Name '03_schtasks_raw.txt' | Out-Null

# ============================================================
# 04 注册表持久化
# ============================================================
Write-Log '采集：注册表持久化'
$regRows = New-Object System.Collections.Generic.List[object]
$runKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
)
foreach ($k in $runKeys) {
    if (Test-Path $k) {
        $props = Get-ItemProperty $k
        $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
            $regRows.Add([pscustomobject]@{ Hive = $k; Name = $_.Name; Value = [string]$_.Value })
        }
    }
}
# Winlogon
$wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
if (Test-Path $wl) {
    $w = Get-ItemProperty $wl
    foreach ($n in 'Shell','Userinit','Taskman','AppSetup') {
        if ($w.$n) { $regRows.Add([pscustomobject]@{ Hive = $wl; Name = $n; Value = [string]$w.$n }) }
    }
}
# AppInit_DLLs
foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows','HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows') {
    if (Test-Path $k) {
        $v = (Get-ItemProperty $k).AppInit_DLLs
        if ($v) { $regRows.Add([pscustomobject]@{ Hive = $k; Name = 'AppInit_DLLs'; Value = [string]$v }) }
    }
}
# IFEO Debugger
$ifeoRoots = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options','HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
foreach ($root in $ifeoRoots) {
    if (Test-Path $root) {
        Get-ChildItem $root | ForEach-Object {
            $d = (Get-ItemProperty $_.PSPath).Debugger
            if ($d) { $regRows.Add([pscustomobject]@{ Hive = $_.PSPath; Name = 'Debugger'; Value = [string]$d }) }
        }
    }
}
# 启动目录
$startupDirs = @(
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
)
foreach ($d in $startupDirs) {
    if (Test-Path $d) {
        Get-ChildItem $d -Force | ForEach-Object {
            $regRows.Add([pscustomobject]@{ Hive = $d; Name = $_.Name; Value = $_.FullName })
        }
    }
}
Save-Csv -Data $regRows -Name '04_RegistryPersistence.csv' | Out-Null

# ============================================================
# 05 WMI 事件订阅
# ============================================================
Write-Log '采集：WMI 持久化'
$wmiLines = New-Object System.Collections.Generic.List[string]
foreach ($cls in '__EventFilter','__EventConsumer','__FilterToConsumerBinding') {
    $wmiLines.Add("===== $cls =====")
    try {
        $items = Get-CimInstance -Namespace 'root\subscription' -ClassName $cls -ErrorAction Stop
        if ($items) { $items | Format-List * | Out-String -Width 300 | ForEach-Object { $wmiLines.Add($_) } }
        else { $wmiLines.Add('(none)') }
    } catch {
        $wmiLines.Add("ERROR: $($_.Exception.Message)")
    }
}
Save-Text -Lines $wmiLines -Name '05_WMI_Persistence.txt' | Out-Null

# ============================================================
# 06 网络连接 / 端口
# ============================================================
Write-Log '采集：网络连接'
$conns = @()
try {
    $conns = Get-NetTCPConnection | ForEach-Object {
        $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        [pscustomobject]@{
            State         = $_.State
            LocalAddress  = $_.LocalAddress
            LocalPort     = $_.LocalPort
            RemoteAddress = $_.RemoteAddress
            RemotePort    = $_.RemotePort
            PID           = $_.OwningProcess
            Process       = $p.ProcessName
            ProcessPath   = $p.Path
            Created       = $_.CreationTime
        }
    }
} catch {
    Write-Log 'Get-NetTCPConnection 不可用，改用 netstat' 'WARN'
}
Save-Csv -Data $conns -Name '06_NetworkConnections.csv' | Out-Null
Save-Cmd -Command 'netstat -ano' -Name '06_netstat_ano.txt' | Out-Null
Save-Cmd -Command 'netstat -rn' -Name '06_routes.txt' | Out-Null
Save-Cmd -Command 'arp -a' -Name '06_arp.txt' | Out-Null
Save-Cmd -Command 'ipconfig /displaydns' -Name '06_dns_cache.txt' | Out-Null

# ============================================================
# 07 共享 / 会话 / 映射盘
# ============================================================
Write-Log '采集：共享与会话'
$shares = @()
try {
    $shares = Get-SmbShare | Select-Object Name, Path, Description, CurrentUsers, EncryptData
} catch {}
Save-Csv -Data $shares -Name '07_SmbShares.csv' | Out-Null
Save-Cmd -Command 'net share' -Name '07_net_share.txt' | Out-Null
Save-Cmd -Command 'net use' -Name '07_net_use.txt' | Out-Null
Save-Cmd -Command 'net session' -Name '07_net_session.txt' | Out-Null

# ============================================================
# 08 近期新增可疑文件
# ============================================================
Write-Log '采集：近期新增文件'
$scanDirs = @(
    'C:\Users\Public',
    'C:\ProgramData',
    'C:\Windows\Temp',
    "$env:SystemRoot\Tasks",
    "$env:APPDATA",
    "$env:LOCALAPPDATA\Temp"
)
# 所有用户 Temp
Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    $t = Join-Path $_.FullName 'AppData\Local\Temp'
    if (Test-Path $t) { $scanDirs += $t }
}
$scanDirs = $scanDirs | Select-Object -Unique

$exts = '.exe','.dll','.ps1','.psm1','.bat','.cmd','.vbs','.vbe','.js','.jse','.hta','.scr','.com','.pif','.lnk','.jsp','.jspx','.war','.aspx','.ashx','.asmx','.php','.b64'
$recent = New-Object System.Collections.Generic.List[object]
foreach ($dir in $scanDirs) {
    if (-not (Test-Path $dir)) { continue }
    Get-FileByDepth -Path $dir -Depth 4 |
        Where-Object { $_.LastWriteTime -gt $Cutoff -and $exts -contains $_.Extension.ToLower() } |
        ForEach-Object {
            if ($recent.Count -ge 4000) { return }
            $sig = Get-SigInfo $_.FullName
            $recent.Add([pscustomobject]@{
                LastWriteTime = $_.LastWriteTime
                SizeKB        = [math]::Round($_.Length/1KB,1)
                Extension     = $_.Extension
                FullName      = $_.FullName
                SHA256        = (Get-HashSafe $_.FullName)
                SigStatus     = $sig.Status
                Signer        = $sig.Signer
            })
        }
}
Save-Csv -Data $recent -Name '08_RecentFiles.csv' | Out-Null

# Base64 文本载荷识别
Write-Log '采集：Base64 文本载荷'
$b64 = New-Object System.Collections.Generic.List[object]
foreach ($dir in @('C:\Users\Public','C:\ProgramData',"$env:LOCALAPPDATA\Temp")) {
    if (-not (Test-Path $dir)) { continue }
    Get-FileByDepth -Path $dir -Depth 3 |
        Where-Object { $_.Length -gt 1KB -and $_.Length -lt 10MB -and $_.Extension -in '.txt','.b64','.dat','.log','.bin' } |
        ForEach-Object {
            if ($b64.Count -ge 500) { return }
            try {
                $head = Get-Content $_.FullName -TotalCount 200 -ErrorAction Stop
                $joined = ($head -join '').Trim()
                if ($joined.Length -gt 200 -and $joined -match '^[A-Za-z0-9+/=\s]+$' -and $joined -notmatch '\s{3,}') {
                    $b64.Add([pscustomobject]@{
                        LastWriteTime = $_.LastWriteTime
                        SizeKB        = [math]::Round($_.Length/1KB,1)
                        FullName      = $_.FullName
                        FirstChars    = $joined.Substring(0, [Math]::Min(80, $joined.Length))
                        SHA256        = (Get-HashSafe $_.FullName)
                    })
                }
            } catch {}
        }
}
Save-Csv -Data $b64 -Name '08_Base64_Blobs.csv' | Out-Null

# ============================================================
# 09 Web 目录与 Webshell 扫描
# ============================================================
if (-not $SkipWebScan) {
    Write-Log '采集：Web 目录/Webshell'
    $webRoots = @(
        'C:\inetpub',
        'C:\wwwroot',
        'C:\WWW',
        'C:\WebSites',
        'C:\xampp',
        'C:\Program Files\Apache Software Foundation',
        'C:\Program Files (x86)\Apache Software Foundation'
    )
    # 自动发现 Tomcat
    Get-ChildItem 'C:\' -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match 'Tomcat|tomcat|jboss|weblogic|jetty' } |
        ForEach-Object { $webRoots += $_.FullName }

    $webExts = '.jsp','.jspx','.jspf','.war','.aspx','.ashx','.asmx','.asa','.php','.php3','.phtml'
    $webFiles = New-Object System.Collections.Generic.List[object]
    foreach ($root in ($webRoots | Select-Object -Unique)) {
        if (-not (Test-Path $root)) { continue }
        Get-ChildItem $root -Recurse -File -Force -ErrorAction SilentlyContinue |
            Where-Object { $webExts -contains $_.Extension.ToLower() } |
            ForEach-Object {
                if ($webFiles.Count -ge 6000) { return }
                $isRecent = ''
                if ($_.LastWriteTime -gt $Cutoff) { $isRecent = 'YES' }
                $webFiles.Add([pscustomobject]@{
                    LastWriteTime = $_.LastWriteTime
                    SizeKB        = [math]::Round($_.Length/1KB,1)
                    FullName      = $_.FullName
                    Recent        = $isRecent
                    SHA256        = (Get-HashSafe $_.FullName)
                })
            }
    }
    Save-Csv -Data $webFiles -Name '09_WebFiles.csv' | Out-Null

    Save-Cmd -Command 'net start | findstr /I "w3svc tomcat"' -Name '09_web_services.txt' | Out-Null
}

# ============================================================
# 10 进程
# ============================================================
Write-Log '采集：进程'
$procs = Get-CimInstance Win32_Process | ForEach-Object {
    $p = $_
    $isSysPath = ($p.ExecutablePath -and $p.ExecutablePath -match '^[A-Za-z]:\\Windows\\')
    $owner = ''
    $sig = $null
    if (-not $isSysPath) {
        try {
            $o = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction Stop
            if ($o -and $o.User) { $owner = "$($o.Domain)\$($o.User)" }
        } catch {}
        if ($p.ExecutablePath) { $sig = Get-SigInfo $p.ExecutablePath }
    }
    $flag = ''
    if ($p.ExecutablePath) {
        if ($p.ExecutablePath -match 'Users\\Public|\\Temp\\|ProgramData\\|\\AppData\\') { $flag = 'SUSPICIOUS_DIR' }
        elseif ($sig -and $sig.Status -ne 'Valid' -and -not $isSysPath) { $flag = 'UNSIGNED_NON_SYSTEM' }
    }
    $sigStatus = 'SystemPath'
    if ($sig) { $sigStatus = $sig.Status }
    [pscustomobject]@{
        PID          = $p.ProcessId
        PPID         = $p.ParentProcessId
        Name         = $p.Name
        Owner        = $owner
        CreationDate = $p.CreationDate
        ExecutablePath = $p.ExecutablePath
        CommandLine  = $p.CommandLine
        SigStatus    = $sigStatus
        Flag         = $flag
    }
}
Save-Csv -Data $procs -Name '10_Processes.csv' | Out-Null

# ============================================================
# 11 Kerberos
# ============================================================
Write-Log '采集：Kerberos 票据'
Save-Cmd -Command 'klist sessions' -Name '11_klist_sessions.txt' | Out-Null
Save-Cmd -Command 'klist' -Name '11_klist_tickets.txt' | Out-Null
Save-Cmd -Command 'klist -li 0x3e7' -Name '11_klist_system.txt' | Out-Null

# ============================================================
# 12 关键事件日志
# ============================================================
Write-Log "采集：事件日志（最近 $Days 天）"
$secIds  = 4624,4625,4648,4672,4673,4720,4722,4726,4728,4732,4756,4768,4769,4771,4776,4697,1102,5140,5145
$sysIds  = 7045,7040,104
$psIds   = 4103,4104

$evtDetail = New-Object System.Collections.Generic.List[object]
$evtCount  = New-Object System.Collections.Generic.List[object]
$evtWarn   = @{}

function Get-EventFields {
    param($Event)
    $h = @{}
    try {
        $xml = [xml]$Event.ToXml()
        foreach ($d in $xml.Event.EventData.Data) {
            if ($null -ne $d.Name) { $h[[string]$d.Name] = [string]$d.'#text' }
        }
    } catch {}
    return $h
}

function Add-Events {
    param([string]$LogName, [int[]]$Ids, [int]$Limit)
    foreach ($id in $Ids) {
        $ev = @()
        try {
            $ev = Get-WinEvent -FilterHashtable @{ LogName = $LogName; Id = $id; StartTime = $Cutoff } -MaxEvents $Limit -ErrorAction Stop
        } catch {
            # 该 ID 在时间窗内没有事件属于正常情况，不提示
            if ($_.FullyQualifiedErrorId -match 'NoMatchingEventsFound') { continue }
            if (-not $evtWarn.ContainsKey($LogName)) {
                $evtWarn[$LogName] = $true
                Write-Log "读取事件日志 $LogName 失败（通常是无该日志权限）：$($_.Exception.Message.Split([Environment]::NewLine)[0])" 'WARN'
            }
            continue
        }
        if (-not $ev) { continue }
        $evtCount.Add([pscustomobject]@{ LogName = $LogName; EventId = $id; Count = @($ev).Count })
        foreach ($e in $ev) {
            $msg = ($e.Message -replace "`r`n", ' ' -replace "`n", ' ')
            if ($msg.Length -gt 600) { $msg = $msg.Substring(0, 600) }
            $f = Get-EventFields $e

            $user = ''
            foreach ($k in 'TargetUserName','SubjectUserName','MemberName','NewTargetUserName','AccountName') {
                if ($f[$k] -and $f[$k] -notin @('-','ANONYMOUS LOGON')) { $user = $f[$k]; break }
            }
            $srcIp = ''
            foreach ($k in 'IpAddress','SourceNetworkAddress','WorkstationName') {
                if ($f[$k] -and $f[$k] -ne '-' -and $f[$k] -ne '::1' -and $f[$k] -ne '127.0.0.1') { $srcIp = $f[$k]; break }
            }
            $obj = ''
            foreach ($k in 'ServiceName','ObjectName','TargetObject','SamAccountName') {
                if ($f[$k]) { $obj = $f[$k]; break }
            }
            $detail = ''
            foreach ($k in 'ServiceFileName','ImagePath','CommandLine','ScriptBlockText') {
                if ($f[$k]) { $detail = $f[$k]; break }
            }
            if ($detail.Length -gt 300) { $detail = $detail.Substring(0, 300) }

            $evtDetail.Add([pscustomobject]@{
                TimeCreated = $e.TimeCreated
                LogName     = $LogName
                EventId     = $id
                Level       = $e.LevelDisplayName
                Account     = $user
                SourceIp    = $srcIp
                Object      = $obj
                Detail      = $detail
                Summary     = $msg
            })
        }
    }
}

Add-Events -LogName 'Security' -Ids $secIds -Limit $MaxEvents
Add-Events -LogName 'System'   -Ids $sysIds -Limit $MaxEvents
Add-Events -LogName 'Microsoft-Windows-PowerShell/Operational' -Ids $psIds -Limit ([Math]::Min($MaxEvents, 1000))

Save-Csv -Data $evtDetail -Name '12_EventLog_Details.csv' | Out-Null
Save-Csv -Data $evtCount  -Name '12_EventLog_Counts.csv' | Out-Null

# 失败登录统计
$failed = $evtDetail | Where-Object { $_.EventId -eq 4625 }
$failStat = $failed | Group-Object Account | Sort-Object Count -Descending |
    Select-Object -First 30 @{n='Account';e={$_.Name}}, Count
Save-Csv -Data $failStat -Name '12_FailedLogon_Top.csv' | Out-Null

# 登录成功来源统计
$okLogon = $evtDetail | Where-Object { $_.EventId -eq 4624 }
$okStat = $okLogon | Group-Object SourceIp | Sort-Object Count -Descending |
    Select-Object -First 30 @{n='SourceIp';e={$_.Name}}, Count
Save-Csv -Data $okStat -Name '12_SuccessLogon_Source_Top.csv' | Out-Null

# ============================================================
# 13 PowerShell 历史
# ============================================================
Write-Log '采集：PowerShell 历史'
$psHist = New-Object System.Collections.Generic.List[string]
Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    $h = Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
    if (Test-Path $h) {
        $psHist.Add("===== $($_.Name) =====")
        $psHist.Add((Get-Content $h -ErrorAction SilentlyContinue | Out-String))
    }
}
if ($psHist.Count -eq 0) { $psHist.Add('(none)') }
Save-Text -Lines $psHist -Name '13_PSReadLine_History.txt' | Out-Null

# ============================================================
# 14 Defender / 防火墙
# ============================================================
Write-Log '采集：Defender 与防火墙'
$defLines = New-Object System.Collections.Generic.List[string]
try {
    $defLines.Add('===== Get-MpComputerStatus =====')
    Get-MpComputerStatus | Format-List * | Out-String -Width 300 | ForEach-Object { $defLines.Add($_) }
} catch {
    $defLines.Add('Defender 不可用或服务器未安装')
}
try {
    $defLines.Add('===== Get-MpPreference (Exclusions) =====')
    $mp = Get-MpPreference
    $defLines.Add("ExclusionPath      : $($mp.ExclusionPath -join '; ')")
    $defLines.Add("ExclusionProcess   : $($mp.ExclusionProcess -join '; ')")
    $defLines.Add("ExclusionExtension : $($mp.ExclusionExtension -join '; ')")
} catch {}
Save-Text -Lines $defLines -Name '14_Defender.txt' | Out-Null
Save-Cmd -Command 'netsh advfirewall show allprofiles' -Name '14_firewall_profiles.txt' | Out-Null
Save-Cmd -Command 'netsh advfirewall firewall show rule name=all dir=in' -Name '14_firewall_rules_in.txt' | Out-Null

# ============================================================
# 15 安全配置基线
# ============================================================
Write-Log '采集：安全配置'
$secLines = New-Object System.Collections.Generic.List[string]

try {
    $smb = Get-SmbServerConfiguration
    $secLines.Add("===== SMB Server =====")
    $secLines.Add("EnableSMB1Protocol   : $($smb.EnableSMB1Protocol)")
    $secLines.Add("RequireSecuritySignature : $($smb.RequireSecuritySignature)")
    $secLines.Add("EnableSecuritySignature  : $($smb.EnableSecuritySignature)")
    $secLines.Add("EnableSMB2Protocol   : $($smb.EnableSMB2Protocol)")
} catch { $secLines.Add('Get-SmbServerConfiguration 不可用') }

$rdp = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections
$secLines.Add('')
$secLines.Add("RDP fDenyTSConnections : $($rdp.fDenyTSConnections)  (0=允许远程桌面)")

$wpad = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name AutoConfigURL
$secLines.Add("WPAD AutoConfigURL     : $($wpad.AutoConfigURL)")

$llmnr = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast
$secLines.Add("LLMNR EnableMulticast  : $($llmnr.EnableMulticast)  (0=已关闭)")

$secLines.Add('')
$secLines.Add('===== 网卡 NetBIOS 设置（2=禁用 NBT）=====')
Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | ForEach-Object {
    $secLines.Add("$($_.Description) : NetbiosOptions=$($_.TcpipNetbiosOptions) IP=$($_.IPAddress -join ',')")
}

$secLines.Add('')
$secLines.Add('===== WinRM Listeners =====')
try {
    Get-ChildItem WSMan:\localhost\Listener -ErrorAction Stop | ForEach-Object {
        $secLines.Add("$($_.PSChildName) : $((Get-ChildItem $_.PSPath).Name -join ',')")
    }
} catch { $secLines.Add('WinRM 未配置或不可读') }

$secLines.Add('')
$secLines.Add('===== hosts 文件 =====')
$hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
if (Test-Path $hostsPath) {
    Get-Content $hostsPath | Where-Object { $_ -and $_ -notmatch '^\s*#' } | ForEach-Object { $secLines.Add($_) }
}

Save-Text -Lines $secLines -Name '15_SecurityBaseline.txt' | Out-Null

# ============================================================
# 16 本地 SQL Server 配置
# ============================================================
Write-Log '采集：SQL Server 配置'
$sqlLines = New-Object System.Collections.Generic.List[string]
$sqlSvc = Get-CimInstance Win32_Service -Filter "Name LIKE 'MSSQL%'"
if (-not $sqlSvc) {
    $sqlLines.Add('本机未发现 SQL Server 服务')
} else {
    $sqlSvc | Select-Object Name, State, StartName, PathName |
        Format-Table -AutoSize | Out-String -Width 300 | ForEach-Object { $sqlLines.Add($_) }

    $sqlcmd = Get-Command sqlcmd.exe -ErrorAction SilentlyContinue
    if (-not $sqlcmd) {
        $sqlLines.Add('未找到 sqlcmd.exe，跳过 SQL 内部查询（可安装 SQL 客户端后重跑）')
    } else {
        $q = @"
SET NOCOUNT ON;
SELECT 'VERSION|' + CAST(SERVERPROPERTY('ProductVersion') AS nvarchar(128)) COLLATE DATABASE_DEFAULT + '|' + CAST(SERVERPROPERTY('Edition') AS nvarchar(128)) COLLATE DATABASE_DEFAULT;
SELECT 'XPCMD|' + CAST(value_in_use AS nvarchar(10)) FROM sys.configurations WHERE name='xp_cmdshell';
SELECT 'SYSADMIN|' + CAST(p.name AS nvarchar(256)) COLLATE DATABASE_DEFAULT FROM sys.server_role_members rm
  JOIN sys.server_principals p ON rm.member_principal_id=p.principal_id
  JOIN sys.server_principals r ON rm.role_principal_id=r.principal_id WHERE r.name='sysadmin';
SELECT 'LOGIN|' + CAST(p.name AS nvarchar(256)) COLLATE DATABASE_DEFAULT + '|' + CAST(p.type_desc AS nvarchar(60)) COLLATE DATABASE_DEFAULT + '|' + CAST(ISNULL(p.default_database_name,'') AS nvarchar(128)) COLLATE DATABASE_DEFAULT FROM sys.server_principals p WHERE p.type IN ('S','U','G');
"@
        $res = sqlcmd -S '.' -E -h -1 -W -Q $q 2>&1
        $sqlLines.Add('===== sqlcmd (本地默认实例, 集成认证) =====')
        $res | ForEach-Object { $sqlLines.Add($_) }

        $q2 = @"
SET NOCOUNT ON;
SELECT 'JOB|' + CAST(j.name AS nvarchar(256)) COLLATE DATABASE_DEFAULT + '|' + CAST(ISNULL(SUSER_SNAME(j.owner_sid),'') AS nvarchar(256)) COLLATE DATABASE_DEFAULT FROM msdb.dbo.sysjobs j;
SELECT 'STEP|' + CAST(j.name AS nvarchar(256)) COLLATE DATABASE_DEFAULT + '|' + CAST(s.step_id AS nvarchar(5)) + '|' + CAST(ISNULL(s.command,'') AS nvarchar(max)) COLLATE DATABASE_DEFAULT FROM msdb.dbo.sysjobsteps s JOIN msdb.dbo.sysjobs j ON s.job_id=j.job_id;
SELECT 'LINKED|' + CAST(name AS nvarchar(256)) COLLATE DATABASE_DEFAULT + '|' + CAST(ISNULL(data_source,'') AS nvarchar(256)) COLLATE DATABASE_DEFAULT FROM sys.servers WHERE is_linked=1;
"@
        $res2 = sqlcmd -S '.' -E -h -1 -W -y 0 -Q $q2 2>&1
        $sqlLines.Add('===== 作业 / 步骤 / 链接服务器 =====')
        $res2 | ForEach-Object { $sqlLines.Add($_) }
    }
}
Save-Text -Lines $sqlLines -Name '16_SQLServer.txt' | Out-Null

# ============================================================
# 16b SQL Server 日志（错误日志/审计/跟踪，用于判断是否注入进入）
# ============================================================
Write-Log '采集：SQL Server 日志'
$sqlLogOut = Join-Path $OutDir '16b_SQL_Logs'
New-Item -ItemType Directory -Force -Path $sqlLogOut | Out-Null

$sqlLogDirs = New-Object System.Collections.Generic.List[string]
foreach ($base in @('C:\Program Files\Microsoft SQL Server','C:\Program Files (x86)\Microsoft SQL Server')) {
    if (-not (Test-Path $base)) { continue }
    Get-ChildItem $base -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $logDir = Join-Path $_.FullName 'MSSQL\Log'
        if (Test-Path $logDir) { $sqlLogDirs.Add($logDir) }
    }
}

# SQL Server 2012+ 的 ERRORLOG 为 UTF-16，按 BOM 与零字节比例判定编码，避免中文乱码
function Read-LogText {
    param([string]$Path, [int]$MaxKB = 16384)
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -eq 0) { return '' }
    $take  = [Math]::Min($bytes.Length, $MaxKB * 1024)
    $slice = New-Object 'byte[]' $take
    [Array]::Copy($bytes, $slice, $take)
    if ($take -ge 2 -and $slice[0] -eq 0xFF -and $slice[1] -eq 0xFE) {
        return [System.Text.Encoding]::Unicode.GetString($slice)
    }
    $zeros = 0
    for ($i = 0; $i -lt [Math]::Min($take, 4000); $i++) { if ($slice[$i] -eq 0) { $zeros++ } }
    if ($zeros -gt 200) { return [System.Text.Encoding]::Unicode.GetString($slice) }
    return [System.Text.Encoding]::Default.GetString($slice)
}

# 原样复制日志文件（ERRORLOG / ERRORLOG.1-6 / SQLAGENT.OUT / 默认跟踪 / XE / 审计）
$logFiles = New-Object System.Collections.Generic.List[object]
foreach ($d in ($sqlLogDirs | Select-Object -Unique)) {
    $instName = Split-Path (Split-Path $d -Parent) -Leaf
    Get-ChildItem $d -File -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^(ERRORLOG|SQLAGENT|LOG)' -or $_.Extension -in '.trc','.xel','.sqlaudit' } |
        Where-Object { $_.Length -lt 200MB } |
        ForEach-Object {
            $dest = Join-Path $sqlLogOut ("{0}__{1}" -f $instName, $_.Name)
            Copy-Item $_.FullName $dest -Force -ErrorAction SilentlyContinue
            $logFiles.Add([pscustomobject]@{
                Instance      = $instName
                File          = $_.Name
                SizeKB        = [math]::Round($_.Length/1KB,1)
                LastWriteTime = $_.LastWriteTime
                Copied        = (Test-Path $dest)
            })
        }
}
Save-Csv -Data $logFiles -Name '16b_SQL_LogFiles.csv' | Out-Null
if ($logFiles.Count -eq 0) { Write-Log '未发现 SQL Server 日志目录（本机可能未安装或路径非默认）' 'WARN' }

# 在 ERRORLOG 中匹配注入与提权特征（语法错误集中出现即典型的注入试探）
$patterns = [ordered]@{
    '登录失败'           = 'Login failed for user'
    '语法错误(疑似注入)'  = 'Error: 102,'
    '关键字语法错误'      = 'Error: 156,'
    '无效列名'           = 'Error: 207,'
    '无效对象名'          = 'Error: 208,'
    '存储过程不存在'      = 'Error: 2812,'
    'xp_cmdshell'        = 'xp_cmdshell'
    '配置变更'           = 'Configuration option|reconfigure'
    '备份还原'           = 'BACKUP|RESTORE'
}
$injHits = New-Object System.Collections.Generic.List[string]
foreach ($lf in $logFiles) {
    if ($lf.File -notmatch '^ERRORLOG') { continue }
    $src = Join-Path $sqlLogOut ("{0}__{1}" -f $lf.Instance, $lf.File)
    if (-not (Test-Path $src)) { continue }
    $lines = (Read-LogText -Path $src) -split "`r?`n"
    $idx = 0
    foreach ($ln in $lines) {
        $idx++
        foreach ($k in $patterns.Keys) {
            if ($ln -match $patterns[$k]) {
                $injHits.Add("[{0}] {1}:{2} [{3}] {4}" -f $k, $lf.Instance, $lf.File, $idx, $ln.Trim())
                break
            }
        }
    }
}
if ($injHits.Count -eq 0) { $injHits.Add('(ERRORLOG 未命中注入/提权关键词)') }
Save-Text -Lines $injHits -Name '16b_SQL_ErrorLog_Hits.txt' | Out-Null

# SQL 相关 Windows 应用日志（服务启动、审计失败、实例异常）
try {
    $sqlEvt = Get-WinEvent -FilterHashtable @{ LogName = 'Application'; StartTime = $Cutoff } -MaxEvents 3000 -ErrorAction Stop |
        Where-Object { $_.ProviderName -match 'MSSQL|SQLSERVERAGENT|SQLSERVERAUDIT|SQLBrowser' } |
        Select-Object TimeCreated, Id, LevelDisplayName, ProviderName,
            @{n='Message';e={ ($_.Message -replace "`r`n", ' ' -replace "`n", ' ') }}
    Save-Csv -Data $sqlEvt -Name '16b_SQL_AppEventLog.csv' | Out-Null
} catch {
    Write-Log '读取 Application 日志失败（SQL 相关事件将缺失）' 'WARN'
}

# 审计 / 扩展事件会话 / 默认跟踪 / 库属主（属主为域账号时 db_owner 可提权）
if (Get-Command sqlcmd.exe -ErrorAction SilentlyContinue) {
    $q3 = @"
SET NOCOUNT ON;
SELECT 'AUDIT|' + CAST(a.name AS nvarchar(256)) COLLATE DATABASE_DEFAULT + '|' + CAST(a.is_state_enabled AS nvarchar(2)) FROM sys.server_audits a;
SELECT 'XE|' + CAST(s.name AS nvarchar(256)) COLLATE DATABASE_DEFAULT FROM sys.dm_xe_sessions s;
SELECT 'TRACE|' + CAST(f.path AS nvarchar(512)) COLLATE DATABASE_DEFAULT + '|' + CAST(f.status AS nvarchar(2)) FROM sys.traces f;
SELECT 'DBOWNER|' + CAST(d.name AS nvarchar(256)) COLLATE DATABASE_DEFAULT + '|' + CAST(SUSER_SNAME(d.owner_sid) AS nvarchar(256)) COLLATE DATABASE_DEFAULT FROM sys.databases d;
"@
    $r3 = sqlcmd -S '.' -E -h -1 -W -Q $q3 2>&1
    Save-Text -Lines (@('===== 审计 / 扩展事件 / 跟踪 / 数据库属主 =====') + @($r3)) -Name '16b_SQL_Audit_XE.txt' | Out-Null
}
else {
    Write-Log '未找到 sqlcmd.exe，审计/跟踪清单需手工导出' 'WARN'
}

# ============================================================
# 17 IOC 定向扫描（本次事件已知特征）
# ============================================================
Write-Log '采集：IOC 定向扫描'
$iocNames = @(
    'w1.exe','gp.exe','gp.exe.b64','kr.cs','kr.b64',
    'kt_tgt.b64','kt_kadmin.b64','kt_hostpds96.b64',
    'p1_probe.ps1','tt_diag2.ps1','tt_pt.ps1','tt_login.ps1','tt57643_diag.ps1',
    's07_leak.ps1','zz_put2.ps1','zz_fetch.ps1','zz_c1ean.jsp','zz_9f163133.jsp',
    'harvest.txt','harvest2.txt','s02_acl.ps1','s11_coerce.ps1','s_wpad.ps1','s_nbns.ps1'
)
$iocDirs = @('C:\Users\Public','C:\ProgramData','C:\Windows\Temp','C:\Users','C:\inetpub','C:\Temp')
if (Test-Path 'C:\Program Files\Apache Software Foundation') { $iocDirs += 'C:\Program Files\Apache Software Foundation' }

$iocHits = New-Object System.Collections.Generic.List[object]
foreach ($dir in ($iocDirs | Select-Object -Unique)) {
    if (-not (Test-Path $dir)) { continue }
    $isPublic = ($dir -eq 'C:\Users\Public')
    Get-FileByDepth -Path $dir -Depth 5 |
        Where-Object {
            $iocNames -contains $_.Name -or
            $_.Name -like 'zz_*.jsp' -or
            $_.Name -like 'kt_*.b64' -or
            ($isPublic -and $_.Name -match '^(i5\d{4}|r5\d{4})_')
        } | ForEach-Object {
            $iocHits.Add([pscustomobject]@{
                LastWriteTime = $_.LastWriteTime
                SizeKB        = [math]::Round($_.Length/1KB,1)
                FullName      = $_.FullName
                SHA256        = (Get-HashSafe $_.FullName)
            })
        }
}
# 已知攻击者目录
$iocDirsKnown = @('C:\Users\Public\g3sb','C:\Users\Public\i56755','C:\Users\Public\ps1a','C:\Users\Public\ps2','C:\Users\Public\zzgit')
foreach ($d in $iocDirsKnown) {
    if (Test-Path $d) {
        $iocHits.Add([pscustomobject]@{
            LastWriteTime = (Get-Item $d).LastWriteTime
            SizeKB        = ''
            FullName      = $d
            SHA256        = 'DIRECTORY_HIT'
        })
    }
}
Save-Csv -Data $iocHits -Name '17_IOC_Hits.csv' | Out-Null

# ============================================================
# 99 汇总
# ============================================================
Write-Log '生成汇总'

$Summary.Add('## 关键统计')
$Summary.Add('')
$Summary.Add('| 项目 | 数量 |')
$Summary.Add('|---|---|')
$Summary.Add("| 本地账号 | $(@($userRows).Count) |")
$Summary.Add("| 本地管理员 | $(@($admins).Count) |")
$Summary.Add("| 服务 | $(@($svc).Count) |")
$Summary.Add("| 非 Microsoft 计划任务 | $(@($tasks).Count) |")
$Summary.Add("| 注册表持久化项 | $($regRows.Count) |")
$Summary.Add("| 近期新增文件（$Days 天） | $($recent.Count) |")
$Summary.Add("| 疑似 Base64 载荷文件 | $($b64.Count) |")
$Summary.Add("| Web 可执行文件 | $(if (Test-Path (Join-Path $OutDir '09_WebFiles.csv')) { (Import-Csv (Join-Path $OutDir '09_WebFiles.csv') | Measure-Object).Count } else { 0 }) |")
$Summary.Add("| 进程数 | $(@($procs).Count) |")
$Summary.Add("| 事件日志明细条数 | $($evtDetail.Count) |")
$Summary.Add("| IOC 命中 | $($iocHits.Count) |")
$Summary.Add('')

$Summary.Add('## 需要重点关注的发现')
$Summary.Add('')

$susSvcs = $svc | Where-Object { $_.Suspicious }
$Summary.Add("### 可疑服务（非系统路径/未加引号/可疑目录）：$(@($susSvcs).Count)")
$susSvcs | Select-Object -First 15 Name, State, StartName, PathName, Suspicious | ForEach-Object {
    $Summary.Add("- ``$($_.Name)`` [$($_.StartMode)] $($_.StartName) → ``$($_.PathName)`` （$($_.Suspicious)）")
}
$Summary.Add('')

$newUsers = $userRows | Where-Object { $_.CreatedRecently -eq 'YES' }
$Summary.Add("### 近期新建本地账号：$(@($newUsers).Count)")
$newUsers | ForEach-Object { $Summary.Add("- $($_.Name)（SID $($_.SID)）创建于 $($_.ProfileCreated)") }
$Summary.Add('')

$newSvcEvents = $evtDetail | Where-Object { $_.EventId -eq 7045 }
$Summary.Add("### 近期安装的服务（7045）：$(@($newSvcEvents).Count) 条")
$newSvcEvents | Select-Object -First 10 | ForEach-Object {
    $Summary.Add("- $($_.TimeCreated) $($_.Summary.Substring(0,[Math]::Min(160,$_.Summary.Length)))")
}
$Summary.Add('')

$cleared = $evtDetail | Where-Object { $_.EventId -eq 1102 }
$Summary.Add("### 日志被清空（1102）：$(@($cleared).Count) 条")
$cleared | ForEach-Object { $Summary.Add("- $($_.TimeCreated) $($_.Account)") }
$Summary.Add('')

$Summary.Add("### 失败登录 TOP")
$failStat | Select-Object -First 10 | ForEach-Object { $Summary.Add("- $($_.Account)：$($_.Count) 次") }
$Summary.Add('')

$Summary.Add("### 成功登录来源 TOP")
$okStat | Select-Object -First 10 | ForEach-Object { $Summary.Add("- $($_.SourceIp)：$($_.Count) 次") }
$Summary.Add('')

$Summary.Add("### IOC 命中：$($iocHits.Count)")
$iocHits | Select-Object -First 20 | ForEach-Object {
    $Summary.Add("- $($_.FullName)（$($_.LastWriteTime)）")
}
$Summary.Add('')

$Summary.Add('## 输出文件说明')
$Summary.Add('')
$Summary.Add('| 文件 | 内容 |')
$Summary.Add('|---|---|')
$Summary.Add('| 00_SystemInfo.csv / 00_systeminfo_raw.txt | 主机、系统、补丁、磁盘 |')
$Summary.Add('| 01_LocalUsers.csv / 01_Administrators.csv | 本地账号（含新建标记）与管理员组 |')
$Summary.Add('| 02_Services.csv | 服务及可疑路径标记 |')
$Summary.Add('| 03_ScheduledTasks.csv | 非 Microsoft 计划任务 |')
$Summary.Add('| 04_RegistryPersistence.csv | Run/Winlogon/IFEO/AppInit/启动目录 |')
$Summary.Add('| 05_WMI_Persistence.txt | WMI 事件订阅 |')
$Summary.Add('| 06_NetworkConnections.csv / 06_netstat_ano.txt | 连接与端口、ARP、DNS 缓存 |')
$Summary.Add('| 07_SmbShares.csv / 07_net_use.txt | 共享、会话、映射盘 |')
$Summary.Add('| 08_RecentFiles.csv / 08_Base64_Blobs.csv | 近期新增文件与疑似 Base64 载荷 |')
$Summary.Add('| 09_WebFiles.csv | Web 目录可执行文件（Recent=YES 为近期改动） |')
$Summary.Add('| 10_Processes.csv | 进程路径、命令行、属主、签名 |')
$Summary.Add('| 11_klist_*.txt | Kerberos 会话与票据 |')
$Summary.Add('| 12_EventLog_Details.csv / 12_EventLog_Counts.csv | 关键事件明细与统计 |')
$Summary.Add('| 13_PSReadLine_History.txt | PowerShell 历史命令 |')
$Summary.Add('| 14_Defender.txt / 14_firewall_*.txt | 防护状态与防火墙规则 |')
$Summary.Add('| 15_SecurityBaseline.txt | SMB/WinRM/RDP/LLMNR/NBT-NS/WPAD/hosts |')
$Summary.Add('| 16_SQLServer.txt | xp_cmdshell、sysadmin、作业步骤、链接服务器 |')
$Summary.Add('| 17_IOC_Hits.csv | 本次事件已知文件名与目录命中 |')
$Summary.Add('| 99_Summary.md | 本汇总 |')
$Summary.Add('| 99_manifest_sha256.csv | 采集包完整性哈希 |')

Save-Text -Lines $Summary -Name '99_Summary.md' | Out-Null

# 采集包哈希
$manifest = Get-ChildItem $OutDir -Recurse -File | Where-Object { $_.Name -ne '99_manifest_sha256.csv' } |
    ForEach-Object {
        [pscustomobject]@{
            File   = $_.FullName.Substring($OutDir.Length + 1)
            SizeKB = [math]::Round($_.Length/1KB, 1)
            SHA256 = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
        }
    }
Save-Csv -Data $manifest -Name '99_manifest_sha256.csv' | Out-Null

# 打包，便于整个目录带回分析（Compress-Archive 需要 PS 5.0+，这里改用 .NET ZipFile）
$zipPath = "$OutDir.zip"
try {
    if (-not ('System.IO.Compression.ZipFile' -as [type])) {
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
    }
    if (Test-Path $zipPath) { Remove-Item $zipPath -Force -ErrorAction SilentlyContinue }
    [System.IO.Compression.ZipFile]::CreateFromDirectory($OutDir, $zipPath)
    Write-Log "已打包：$zipPath（$([math]::Round((Get-Item $zipPath).Length/1MB,1)) MB）"
} catch {
    Write-Log "打包失败（采集结果不受影响）：$($_.Exception.Message)" 'WARN'
}

# 记录运行时长
$elapsed = [math]::Round(((Get-Date) - $StartAt).TotalSeconds, 1)
Write-Log "采集完成，耗时 ${elapsed}s，共生成 $(@($manifest).Count) 个文件"
Write-Host ''
Write-Host '========================================' -ForegroundColor Cyan
Write-Host ' 排查采集完成' -ForegroundColor Cyan
Write-Host " 输出目录: $OutDir" -ForegroundColor Yellow
Write-Host " 汇总报告: $(Join-Path $OutDir '99_Summary.md')" -ForegroundColor Yellow
Write-Host '========================================' -ForegroundColor Cyan
Write-Host ''
Write-Host '提示：请将整个目录打包带回分析，不要在本机删除或修改任何原始文件。'
