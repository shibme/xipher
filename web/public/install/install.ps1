#!/usr/bin/env pwsh

$ErrorActionPreference = 'Stop'

if ($v) {
  $Version = "v${v}"
}
if ($Args.Length -eq 1) {
  $Version = $Args.Get(0)
}

$XipherInstall = $env:Xipher_INSTALL
$BinDir = if ($XipherInstall) {
  "${XipherInstall}\bin"
} else {
  "${Home}\.xipher\bin"
}

$XipherZip = "$BinDir\xipher.zip"
$XipherExe = "$BinDir\xipher.exe"
$Target = 'windows_amd64'

$DownloadUrl = if (!$Version) {
  "https://github.com/shibme/xipher/releases/latest/download/xipher_${Target}.zip"
} else {
  "https://github.com/shibme/xipher/releases/download/${Version}/xipher_${Target}.zip"
}

if (!(Test-Path $BinDir)) {
  New-Item $BinDir -ItemType Directory | Out-Null
}

curl.exe -Lo $XipherZip $DownloadUrl

tar.exe xf $XipherZip -C $BinDir

Remove-Item $XipherZip

$User = [System.EnvironmentVariableTarget]::User
$Path = [System.Environment]::GetEnvironmentVariable('Path', $User)
if (!(";${Path};".ToLower() -like "*;${BinDir};*".ToLower())) {
  [System.Environment]::SetEnvironmentVariable('Path', "${Path};${BinDir}", $User)
  $Env:Path += ";${BinDir}"
}

Write-Output "Xipher was installed successfully to ${XipherExe}"
Write-Output "Run 'xipher --help' to get started"
