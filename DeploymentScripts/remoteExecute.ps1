<#
.SYNOPSIS
    Script to execute a deployment on a Dynamics365 Finance & Operations Enterprise Edition VM
    See https://github.com/laneswenka/d365-foee-alm
#>
param(
[string] $Directory = $null,
[string] $ScriptsDirectory = $null,
[Parameter(Mandatory=$true)]
[string] $BuildNumber = $null
)

trap
{
    write-host "Errors found"
    write-host $_
    exit 1
}

<#
.SYNOPSIS
    Runs AxUpdateInstaller.exe
#>
function Execute-Installer([string]$executeArgs, [string]$packageDirectory)
{

    $deploymentPath = [string]::Format("{0}", $Directory)
    $installerFile = [string]::Format("{0}\{1}", $packageDirectory, "AxUpdateInstaller.exe")

    $installerInfo = New-Object System.Diagnostics.ProcessStartInfo
    $installerInfo.FileName = $installerFile
    $installerInfo.RedirectStandardOutput = $true
    $installerInfo.UseShellExecute = $false
    $installerInfo.Arguments = $executeArgs

    $installer = New-Object System.Diagnostics.Process
    $installer.StartInfo = $installerInfo
    $installer.Start() | Out-Null

    $stdout = $installer.StandardOutput.ReadToEnd()

    write-host $stdout
}

Add-Type -AssemblyName System.IO.Compression.FileSystem

$deploymentPath = [string]::Format("{0}", $Directory)
$counter = 0

cd $deploymentPath

$zipFiles = Get-ChildItem -Path $deploymentPath -Filter "*.zip"

foreach($zipFile in $zipFiles)
{
    Write-Host "Unblocking File $($zipFile.name)..."
    Unblock-File -Path $zipFile.FullName
    Write-Host "Successful"

    Write-Host "Extracting..."
	
	$packageDirectory = [string]::Format("{0}\{1}_{2}", $deploymentPath, "package", $counter)
	[System.IO.Compression.ZipFile]::ExtractToDirectory($zipFile.FullName, $packageDirectory)
	Write-Host "Extracting $($zipFile.name) Finished"

	#Generate Runbook
	$runbookFile = [string]::Format("{0}_{1}.xml", $BuildNumber, $counter)
	$runbookId = [string]::Format("{0}_{1}", $BuildNumber, $counter)
	$defaultTopology = [string]::Format("{0}\{1}", $ScriptsDirectory, "DefaultTopologyData.xml")
	$defaultServiceModel = [string]::Format("{0}\{1}", $ScriptsDirectory, "DefaultServiceModelData.xml")

	write-host 'Generating Runbook...'

	$args = [string]::Format("generate -runbookId={0} -runbookFile={1} -topologyFile={2} -serviceModelFile={3}", $runbookId, $runbookFile, $defaultTopology, $defaultServiceModel)
	Execute-Installer -executeArgs $args -packageDirectory $packageDirectory

	write-host "Runbook $($runbookFile) Generated"

	#Import Runbook
	write-host "Importing Runbook..."

	$args2 = [string]::Format("import -runbookFile={0}", $runbookFile)
	Execute-Installer -executeArgs $args2 -packageDirectory $packageDirectory

	write-host "Runbook Imported"

	#Execute
	write-host "Executing..."

	$args3 = [string]::Format("execute -runbookId={0}", $runbookId)
	Execute-Installer -executeArgs $args3 -packageDirectory $packageDirectory

	write-host "Deployment Complete"

	$counter = $counter + 1
}

exit 0

