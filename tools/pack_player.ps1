$ErrorActionPreference = 'Stop'

# 1. 備份原始 bat
Copy-Item 'Fightcade-win32-latest\FightcadeRewindPlayer.bat' -Destination '.backup\FightcadeRewindPlayer_20261020_114543.bat' -Force

# 2. 定義 GZip 壓縮函式
function Get-GzipB64($filePath) {
    $bytes = [System.IO.File]::ReadAllBytes($filePath)
    $ms = New-Object System.IO.MemoryStream
    $gz = New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Compress)
    $gz.Write($bytes, 0, $bytes.Length)
    $gz.Close()
    return [Convert]::ToBase64String($ms.ToArray())
}

$dllPath = 'tools\proxy_ggpo\ggponet.dll'
$luaPath = 'Fightcade-win32-latest\emulator\fbneo\scripts\rewind_core.lua'

$dllB64 = Get-GzipB64 $dllPath
$luaB64 = Get-GzipB64 $luaPath

Write-Host "DLL B64 Length: $($dllB64.Length)"
Write-Host "Lua B64 Length: $($luaB64.Length)"

# 3. 讀取並替換 bat 內容
$batFile = 'Fightcade-win32-latest\FightcadeRewindPlayer.bat'
$batContent = [System.IO.File]::ReadAllText($batFile, [System.Text.Encoding]::UTF8)

$batContent = [System.Text.RegularExpressions.Regex]::Replace($batContent, 'private const string EMBEDDED_DLL_B64 = @\"[\s\S]*?\";', "private const string EMBEDDED_DLL_B64 = @`"$dllB64`";")
$batContent = [System.Text.RegularExpressions.Regex]::Replace($batContent, 'private const string EMBEDDED_LUA_B64 = @\"[\s\S]*?\";', "private const string EMBEDDED_LUA_B64 = @`"$luaB64`";")

[System.IO.File]::WriteAllText($batFile, $batContent, [System.Text.Encoding]::UTF8)
Write-Host "FightcadeRewindPlayer.bat updated successfully."

# 4. 編譯 EXE
$csc = 'C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe'
if (-not (Test-Path $csc)) {
    $csc = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe'
}

$lines = [System.IO.File]::ReadAllLines($batFile, [System.Text.Encoding]::UTF8)
$csLines = $lines[40..($lines.Length - 1)]
$csFile = 'Fightcade-win32-latest\temp_source.cs'
[System.IO.File]::WriteAllLines($csFile, $csLines, [System.Text.Encoding]::UTF8)

$exeFile = 'Fightcade-win32-latest\FightcadeRewindPlayer.exe'
$ico = 'Fightcade-win32-latest\FightcadeRewindPlayer.ico'
$icoArg = if (Test-Path $ico) { "/win32icon:$ico" } else { '' }

& $csc /nologo /target:winexe /optimize+ /platform:anycpu $icoArg /reference:System.dll,System.Windows.Forms.dll,System.Drawing.dll /out:$exeFile $csFile

if (Test-Path $csFile) { Remove-Item $csFile -Force }

Write-Host "FightcadeRewindPlayer.exe compiled successfully."
