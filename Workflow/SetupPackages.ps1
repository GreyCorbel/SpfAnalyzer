using namespace System.IO

param
(
 [string]$ModuleName,
 [string]$RootPath,
 [string]$nugetPath
)

$packagesDir = [Path]::Combine($RootPath,'packages')
$modulePath = [Path]::Combine($RootPath,'Module',$ModuleName)
$sharedPath = [Path]::Combine($modulePath,'lib')

&"$nugetPath" restore ([Path]::Combine($RootPath,'Workflow','packages.config')) -packagesDirectory $packagesDir | Out-Null
"Updating packages in the module"
$packages = ([xml](get-content -path ([Path]::Combine($RootPath,'Workflow','packages.config')) -raw)).packages.package
$packages
if(-not (Test-Path -Path $sharedPath)) { New-Item -ItemType Directory -Path $sharedPath | Out-Null}
if(-not (Test-Path -Path ([Path]::Combine($sharedPath, 'net8.0')))) { New-Item -ItemType Directory -Path ([Path]::Combine($sharedPath, 'net8.0')) | Out-Null}

$pkg = $packages | where-object{$_.id -eq "DnsClient"}
"Processing: $($pkg.id)"
$packageFolder = [Path]::Combine($packagesDir, "$($pkg.id)`.$($pkg.version)")
Copy-Item -Path ([Path]::Combine($packageFolder,'lib','net8.0',"$($pkg.id)`.dll")) -Destination ([Path]::Combine($sharedPath,'net8.0')) -Force
