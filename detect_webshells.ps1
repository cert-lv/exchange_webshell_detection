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

# some IIS have useless web.config files in inetpub for legacy reasons
$files = Get-ChildItem $inetpubs -Recurse -File | Where-Object { $_.Name -ne "web.config" }
if ($files) {
    echo "Found suspicious files (not used by Exchange, typical webshell location):"
    echo ""
    Get-ChildItem $files.FullName | Select-Object FullName, LastWriteTime | Format-Table -Wrap -Autosize
    echo ""
    $affected = $TRUE
}

# web.config can hold backdoor itself though, so filter out legacy ones

# hashes of false positive web.config files
$false_positives = $(
# <?xml version="1.0" encoding="UTF-8"?>
# <configuration>
# <system.webServer>
# <httpRedirect enabled="false" />
# </system.webServer>
# </configuration>
    "5470EAFEB40805AC58B13DE3EB64BEA6200C5446E37A21E7674913F2ADF5C089",
#
# <?xml version="1.0" encoding="UTF-8"?>
# <configuration>
# <system.webServer>
# <httpRedirect enabled="true" />
# </system.webServer>
# </configuration>
    "843A6D81A3BE784755EF1340F224465CD9AA51E7A71D4153048307F8E1AA7C15",
#
# <configuration>
# <system.webServer>
# <httpRedirect enabled="false" destination="" childOnly="false" />
# </system.webServer>
# </configuration>
    "6625962A82913289FEFDC17E12BB44360898C12D0DBD3E47B0A9345ED99C887D",
#
# <configuration>
# <system.webServer>
# <httpRedirect enabled="true" destination="" childOnly="false" />
# </system.webServer>
# </configuration>
    "0B996ADC7D510FCCEB253DC8B56AAA487840DD84EECD022F8F3A36EB0A6FD9F6"
)

# go through web.config's, filter out the ones with hashes different from the ones listed above
$hashes = Get-ChildItem $inetpubs -Recurse -File |
  Where-Object { $_.Name -eq "web.config" } |
  ForEach-Object { Get-FileHash -Algorithm sha256 $_.FullName } |
  Where-Object { $_.Hash -notin $false_positives }

if ($hashes) {
    echo "Found following web.config files. These files are often created automatically by IIS to reflect local configuration / environment."
    echo "So far there have been no reports of any web.config files being used in attacks related to proxylogin vulnerabilities."
    echo "Nevertheless we suggest expecting these web.config files manually as they can be used to host backdoors:"
    echo "    https://soroush.secproject.com/blog/2019/08/uploading-web-config-for-fun-and-profit-2/"
    echo ""
    Get-ChildItem $hashes.Path | Select-Object FullName, LastWriteTime | Format-Table -Wrap -Autosize
    echo ""
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
    echo ""
    Get-ChildItem $matches.Path | Select-Object FullName, LastWriteTime | Format-Table -Wrap -Autosize
    echo ""
    $affected = $TRUE
}

if ($affected) {
    echo "Server requires further examination to confirm the breach and determine it's extent"
    echo "Consider sending malware (webshells and other) samples to cert@cert.lv for further analysis"
} else {
    echo "No webshells found, but they might have been removed or attackers might have used other persistence techniques"
}
