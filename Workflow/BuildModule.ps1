using namespace System.IO
param
(
    [string]$rootPath = '.',
    [string]$moduleName
)

if([string]::IsNullOrWhiteSpace($moduleName))
{
    Write-Error 'Module name must be provided'
    return
}

$moduleFile = [Path]::Combine($rootPath,'Module',$moduleName,"$moduleName`.psm1")
#clear the file
Clear-Content -Path $moduleFile

#optional commands to place at the beginning of the module, e.g. using statements
if(Test-Path ([Path]::Combine($rootPath,'Commands','ModuleStart.ps1')))
{
    Get-Content ([Path]::Combine($rootPath,'Commands','ModuleStart.ps1')) | Out-File -FilePath $moduleFile -Append
}

$path = [Path]::Combine($rootPath,'Enums')
if(Test-Path $path)
{
    '#region Enums' | Out-File -FilePath $moduleFile -Append
    foreach($file in Get-ChildItem -Path $path)
    {
        Get-Content $file.FullName | Out-File -FilePath $moduleFile -Append
    }
    '#endregion Enums' | Out-File -FilePath $moduleFile -Append
}

$path = [Path]::Combine($rootPath,'Classes')
if(Test-Path $path)
{
    '#region Classes' | Out-File -FilePath $moduleFile -Append
    foreach($file in Get-ChildItem -Path $path)
    {
        Get-Content $file.FullName | Out-File -FilePath $moduleFile -Append
    }
    '#endregion Classes' | Out-File -FilePath $moduleFile -Append
}

$path = [Path]::Combine($rootPath,'Commands','Public')
if(Test-Path $path)
{
    '#region Public commands' | Out-File -FilePath $moduleFile -Append
    foreach($file in Get-ChildItem -Path $path)
    {
        Get-Content $file.FullName | Out-File -FilePath $moduleFile -Append
    }
    '#endregion Public commands' | Out-File -FilePath $moduleFile -Append
}

$path = [Path]::Combine($rootPath,'Commands','Internal')
if(Test-Path $path)
{
    '#region Internal commands' | Out-File -FilePath $moduleFile -Append
    foreach($file in Get-ChildItem -Path $path)
    {
        Get-Content $file.FullName | Out-File -FilePath $moduleFile -Append
    }
    '#endregion Internal commands' | Out-File -FilePath $moduleFile -Append
}

#optional commands to place at the end of the module, e.g. module initialization
$path = [Path]::Combine($rootPath,'Commands','ModuleInitialization.ps1')
if(Test-Path $path)
{
    '#region Module initialization' | Out-File -FilePath $moduleFile -Append
    Get-Content $path | Out-File -FilePath $moduleFile -Append
    '#endregion Module initialization' | Out-File -FilePath $moduleFile -Append
}