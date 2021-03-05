if (!(Test-Path -PathType Container "$($env:exchangeinstallpath)/Frontend")) {
    echo "Could not detect Exchange installation directory"
    exit
}

$affected = $FALSE

##
## 1. iterate over files in inetpub/wwwroot and consider everything suspicious
##

$inetpubs = @()

# inetpub is usually located at "$($env:systemdrive)/inetpub"
$path = "$($env:systemdrive)/inetpub/wwwroot/aspnet_client".ToLower()
if ( Test-Path -PathType Container $path ) {
    $inetpubs += $path
}

# but IIS might be pointing to a different place
try {
    $inetpubs = $inetpubs + (Get-WebFilePath 'IIS:\Sites\Default Web Site\aspnet_clients').FullName.ToLower() | select -Unique
} catch {
    # e.g. Default Web Site might have been removed from IIS
}

$files = Get-ChildItem $inetpubs -Recurse -File
if ($files) {
    echo "Found suspicious files (not used by Exchange, typical webshell location):"
    $files | Select-Object FullName, LastWriteTime
    $affected = $TRUE
}

##
## 2. iterate over files in frontend and look for webshell IoC's
##

$keywords = @(
    # interpreters used in webshells and not used by Exchange
    'wscript',
    'vbscript',
    'visualbasic',
    'jscript',
    # evals & co
    'eval\s?\(',
    'process\s?\(',
    'eval_r',
    'executestatement',
    'processstartinfo',
    'os.run',
    'oscript.run',
    'oshell.run',
    # encoding, smuggling
    'convert.frombase64string',
    'request.headers',
    'createobject',
    # file managers / droppers
    'filesystemobject',
    'httppostedfile',
    'system.io.file',
    'writealltext',
    # command execution
    'cmd.exe',
    'cmd /c',
    'powershell.exe',
    # post exploitation
    'net user',
    'net group',
    'lsass.exe',
    'procdump',
    'whoami',
    'ping.exe',
    # csharp webshells
    'new socket',
    'binarywrite'
    # SharPyShell
    'assembly.load',
    'compileassemblyfromsource',
    'aesenc',
    # generic tags
    'webshell')

$directory = "$($env:exchangeinstallpath)/Frontend"
$matches = dir -Recurse $directory | Select-String -Pattern $keywords
if ($matches) {
    echo "Found suspicious files in Exchange frontend dir and they match functions used by known webshells:"
    Get-ChildItem $matches.Path | Select-Object FullName, LastWriteTime
    $affected = $TRUE
}

if ($affected) {
    echo "Server requires further examination to confirm the breach and determine it's extent"
    echo "Consider sending malware (webshells and other) samples to cert@cert.lv for further analysis"
} else {
    echo "No webshells found, but they might have been removed or attackers might have used other persistence techniques'"
}
