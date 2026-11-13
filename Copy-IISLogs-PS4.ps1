#Requires -Version 4.0
<#
.SYNOPSIS
    按日期收集指定目录下的文件（保持原目录结构，兼容 PowerShell 4.0 / 5.x）

.DESCRIPTION
    递归扫描源目录下的所有文件（不限制扩展名），把“文件日期落在
    [StartDate, EndDate] 区间内”的文件复制到目标目录，目标目录中的
    相对路径与源目录完全一致：

        源  ： C:\inetpub\logs\LogFiles\W3SVC1\u_ex261101.log
        目标： D:\IISLogBackup\W3SVC1\u_ex261101.log

    文件日期 = 文件的“最后修改时间”（LastWriteTime），按“天”比较：
      StartDate 当天 00:00 起算，EndDate 当天 23:59:59 截止，两端都包含。
      （IIS 每天一份 u_exYYMMDD.log，最后修改时间就是该日志收尾的时间，
        所以取 2026-11-01 开始，实际包含的是 11-01 当天写入的日志文件。）

    说明：
      - 只复制，不移动、不删除源文件；
      - 目标目录不存在时会自动创建；
      - 目标位置已有同名文件时直接覆盖；
      - 目标目录位于源目录内部时会自动跳过，避免把备份再抄一遍；
      - 无权限访问的子目录会跳过，最后给出提示，不中断整体复制。

.PARAMETER SourcePath
    源目录，通常是 C:\inetpub\logs\LogFiles（该目录下按站点分 W3SVC1、W3SVC2... 子目录）。

.PARAMETER DestinationPath
    目标目录，例如 D:\IISLogBackup，也可以是 UNC 路径 \\nas\share\IISLogs。

.PARAMETER StartDate
    起始日期（含当天），支持 2026-11-01、2026.11.01、2026/11/01 等写法。

.PARAMETER EndDate
    结束日期（含当天），可省略；省略表示一直取到当前最新的文件。

.EXAMPLE
    .\Copy-IISLogs-PS4.ps1 -SourcePath C:\inetpub\logs\LogFiles -DestinationPath D:\IISLogBackup -StartDate 2026.11.01

.EXAMPLE
    # 只取 2026-11-01 至 2026-11-10，先用 -WhatIf 预览要复制的文件，不实际拷贝
    .\Copy-IISLogs-PS4.ps1 -SourcePath C:\inetpub\logs\LogFiles -DestinationPath D:\IISLogBackup -StartDate 2026-11-01 -EndDate 2026-11-10 -WhatIf

.NOTES
    兼容 Windows PowerShell 4.0 及以上（Windows Server 2012 R2 默认自带 4.0）。
    读取 C:\inetpub\logs 一般需要管理员权限，建议以管理员身份运行。
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$SourcePath,

    [Parameter(Mandatory = $true, Position = 1)]
    [string]$DestinationPath,

    [Parameter(Mandatory = $true, Position = 2)]
    [string]$StartDate,

    [string]$EndDate
)

$ErrorActionPreference = 'Stop'

function ConvertTo-ScriptDate {
    param(
        [string]$Text,
        [string]$Name
    )
    if ([string]::IsNullOrWhiteSpace($Text)) {
        throw "$Name 不能为空。"
    }
    # 允许 2026.11.01 / 2026/11/01 / 2026-11-01（可带时间部分）
    $normalized = $Text.Trim() -replace '[./]', '-'
    $value = [datetime]::MinValue
    if (-not [datetime]::TryParse($normalized, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$value)) {
        throw "$Name 不是可识别的日期：'$Text'，示例：2026-11-01 或 2026.11.01"
    }
    return $value.Date
}

# ---------- 参数处理 ----------

if (-not (Test-Path -LiteralPath $SourcePath -PathType Container)) {
    throw "源目录不存在：$SourcePath"
}
$src = (Resolve-Path -LiteralPath $SourcePath).ProviderPath

$start = ConvertTo-ScriptDate -Text $StartDate -Name 'StartDate'
if ($EndDate) {
    # 结束日期按“当天结束”处理，即 < 次日 00:00
    $end = (ConvertTo-ScriptDate -Text $EndDate -Name 'EndDate').AddDays(1)
    if ($end -le $start) {
        throw "EndDate（$EndDate）早于 StartDate（$StartDate）。"
    }
    $endText = (ConvertTo-ScriptDate -Text $EndDate -Name 'EndDate').ToString('yyyy-MM-dd')
}
else {
    $end = [datetime]::MaxValue
    $endText = '不限'
}

$dst = $DestinationPath
if (-not [System.IO.Path]::IsPathRooted($dst)) {
    $dst = Join-Path (Get-Location).ProviderPath $dst
}
$dst = $dst.TrimEnd('\')
if ($dst -ieq $src.TrimEnd('\')) {
    throw "目标目录不能与源目录相同：$dst"
}
$dstPrefix = $dst + '\'

Write-Host "源目录  ：$src"
Write-Host "目标目录：$dst"
Write-Host ("日期范围：{0:yyyy-MM-dd} ~ {1}" -f $start, $endText)
Write-Host ''

# ---------- 扫描并复制 ----------

$enumErrors = @()
$files = @(Get-ChildItem -LiteralPath $src -Recurse -File -ErrorAction SilentlyContinue -ErrorVariable +enumErrors)

$matched = 0
$copied  = 0

foreach ($file in $files) {
    $full = $file.FullName

    # 目标目录在源目录内部时，跳过目标目录自身，避免把已经复制过去的文件再抄一遍
    if ($full.StartsWith($dstPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        continue
    }

    $modified = $file.LastWriteTime
    if ($modified -lt $start -or $modified -ge $end) {
        continue
    }

    $matched++
    $relative = $full.Substring($src.Length).TrimStart('\')
    $target = Join-Path $dst $relative

    if (-not $PSCmdlet.ShouldProcess($target, '复制文件')) {
        continue
    }

    $parent = [System.IO.Path]::GetDirectoryName($target)
    if (-not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    Copy-Item -LiteralPath $full -Destination $target -Force
    $copied++
}

Write-Host ''
Write-Host ("扫描文件  ：{0} 个" -f $files.Count)
Write-Host ("日期命中  ：{0} 个" -f $matched)
Write-Host ("已复制    ：{0} 个" -f $copied)
if ($enumErrors.Count -gt 0) {
    Write-Warning ("有 {0} 处目录或文件读取失败（多为无权限），已跳过。" -f $enumErrors.Count)
}
