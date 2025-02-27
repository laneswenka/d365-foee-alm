#requires -Modules Az.Accounts
[CmdletBinding()]
param (
    #Security, govarnance and compliance
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPGuestMakerSetting,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPAppSharingSetting,
    #Admin environment and settings
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPEnvCreationSetting,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPTrialEnvCreationSetting,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPEnvCapacitySetting,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPTenantIsolationSetting,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPTenantDLP,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPTenantIsolationDomains,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPAdminEnvNaming,
    [ValidateSet('unitedstates', 'europe', 'asia', 'australia', 'india', 'japan', 'canada', 'unitedkingdom', 'unitedstatesfirstrelease', 'southamerica', 'france', 'switzerland', 'germany', 'unitedarabemirates', 'norway')][Parameter(Mandatory = $false)][string]$PPAdminRegion,
    [Parameter(Mandatory = $false)][string]$PPAdminBilling,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPAdminCoeSetting,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPAdminDlp,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPAdminEnvEnablement,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPAdminManagedEnv,
    #Landing Zones
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPDefaultRenameText,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPDefaultDLP,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPDefaultManagedEnv,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPDefaultManagedSharing,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPCitizen,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPCitizenCount,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPCitizenNaming,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPCitizenRegion,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPCitizenDlp,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPCitizenBilling,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPCitizenManagedEnv,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPCitizenAlm,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPCitizenDescription,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPCitizenCurrency,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPCitizenLanguage,
    [Parameter(Mandatory = $false)]$finOpsEnv,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPPro,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPProCount,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPProNaming,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPProRegion,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPProDlp,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPProBilling,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPProManagedEnv,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPProAlm,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPProDescription,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPProCurrency,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPProLanguage,
    [Parameter(Mandatory = $false)]$PPProConfiguration,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPSelectIndustry,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPIndustryNaming,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPIndustryRegion,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPIndustryBilling,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPIndustryAlm,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPIndustryManagedEnv
)

$DeploymentScriptOutputs = @{}

function Register-PowerOpsAdminApplication {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $ClientId
    )
    Invoke-PowerOpsRequest -Path "/providers/Microsoft.BusinessAppPlatform/adminApplications/$ClientId" -Method Put
}
function Invoke-PowerOpsRequest {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('Get', 'Post', 'Patch', 'Delete', 'Put')]
        [String]
        $Method,

        [Parameter(Mandatory = $false)]
        [Object]
        $RequestBody,

        [Parameter(Mandatory = $true)]
        $Path,

        [Parameter(Mandatory = $false)]
        [switch]$Force
    )

    begin {
        # Set base URI
        $BaseUri = "https://api.bap.microsoft.com"
        if (-not $PSBoundParameters['Force']) {
            $ApiVersion = if ($Path -notmatch '\?') { '?api-version=2021-07-01' } else { '&api-version=2021-07-01' }
        }
        else {
            $ApiVersion = $null
        }
        # Acquire token and set default headers
        try {
            $token = Get-AzAccessToken
        }
        catch {
            throw "Unable to acquire token"
        }
        $Headers = @{
            "Content-Type"  = "application/json; charset=utf-8"
            "Authorization" = "Bearer $($Token.Token)"
        }
    }
    process {
        $RestParameters = @{
            "Uri"         = "$($BaseUri)$($Path)$($ApiVersion)"
            "Method"      = $Method
            "Headers"     = $Headers
            "ContentType" = 'application/json; charset=utf-8'
        }
        if ($RequestBody) {
            $RestParameters["Body"] = $RequestBody
        }
        try {
            $Request = Invoke-RestMethod @RestParameters
            if ($Method -eq 'Get') {
                if ($Request.value) {
                    return $Request.value
                }
                if ($Request.Properties) {
                    return $Request.Properties
                }
            }
            else {
                $Request
            }
        }
        catch {
            throw $_
        }
    }
    end {

    }
}
function New-PowerOpsEnvironment {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [ValidateSet('unitedstates', 'europe', 'asia', 'australia', 'india',
            'japan', 'canada', 'unitedkingdom', 'unitedstatesfirstrelease',
            'southamerica', 'france', 'switzerland', 'germany', 'unitedarabemirates', 'norway')]
        [String]$Location,
        [Parameter(Mandatory = $false)]
        [bool]$Dataverse = $false,
        [Parameter(Mandatory = $false)]
        [string]$Description,
        [Parameter(Mandatory = $false)]
        [string]$LanguageName,
        [Parameter(Mandatory = $false)]
        [string]$CurrencyName,
        [Parameter(Mandatory = $false)]
        [string]$SecurityGroupId,
        [Parameter(Mandatory = $false)]
        [ValidateSet('D365_FinOps_Finance')]
        [String]$Templates,
        [Parameter(Mandatory = $false)]
        [bool]$ManagedEnvironment = $false,
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    begin {
        # Validate if environment with the same name already exists
        if (-not $PSBoundParameters['Force']) {
            $existingEnv = Get-PowerOpsEnvironment | Where-Object { $_.properties.displayName -eq $Name }
            if ($existingEnv) {
                throw "Environment with DisplayName '$Name' already exists in Power Platform. Retry command with the -Force switch if you really want to create the environment with the duplicate name"
            }
        }
    }
    process {
        $postBody = @{
            "properties" = @{
                "linkedEnvironmentMetadata" = @{
                    "baseLanguage" = ''
                    "domainName"   = "$($Name)"
                }
                "displayName"               = "$($Name)"
                "environmentSku"            = "Sandbox"
                "databaseType"              = "None"
                "description"               = "$($Description)"
            }
            "location"   = "$($Location)"
        }
        if ($true -eq $Dataverse) {
            $postBody.properties.databaseType = "CommonDataService"
            #Add security group if provided
            if (-not[string]::IsNullOrEmpty($SecurityGroupId)) {
                $postBody.properties.linkedEnvironmentMetadata.securityGroupId = $SecurityGroupId
            }
            #Add currency if provided
            if (-not[string]::IsNullOrEmpty($CurrencyName)) {
                $postBody.properties.linkedEnvironmentMetadata.currency = @{
                    code = $CurrencyName
                }
            }
            #Add language if provided
            if (-not[string]::IsNullOrEmpty($LanguageName)) {
                $postBody.properties.linkedEnvironmentMetadata.baseLanguage = $LanguageName
            }
            #Add D365 template if provided
            if (-not[string]::IsNullOrEmpty($Templates)) {
                $postBody.properties.linkedEnvironmentMetadata.templates = @($Templates)
            }
        }
        if ($PSCmdlet.ShouldProcess("Create environment $Name in $Location")) {
            try {
                Write-Verbose -Message "Creating environment $Name in $Location"
                Invoke-PowerOpsRequest -Method Post -Path '/providers/Microsoft.BusinessAppPlatform/environments?api-version=2021-07-01&ud=/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments' -RequestBody ($postBody | ConvertTo-Json -Depth 100) -Force

                if ($true -eq $ManagedEnvironment) {
                    Write-Verbose -Message "Waiting for environment to be successfully provisioned before enabling managed environment"
                    do {
                        Start-Sleep -Seconds 10
                        $environmentStatus = Get-PowerOpsEnvironment | Where-Object { $_.properties.displayname -eq $Name }
                    } until ($environmentStatus.properties.provisioningState -eq 'Succeeded')

                    Enable-PowerOpsManagedEnvironment -EnvironmentName $environmentStatus.Name
                }
            }
            catch {
                Write-Error $_
            }
        }

    }
    end {

    }
}
function New-PowerOpsRoleAssignment {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory = $true)]
        [string]$PrincipalId,
        [Parameter(Mandatory = $false)]
        [ValidateSet('EnvironmentAdmin', 'EnvironmentMaker')]
        [String]$RoleDefinition,
        [Parameter(Mandatory = $false)]
        [bool]$Dataverse = $false,
        [Parameter(Mandatory = $false)]
        [String]$EnvironmentName
    )
    begin {
        # Validate if environment with the name exists
        $environment = Get-PowerOpsEnvironment | Where-Object { $_.properties.displayName -eq $EnvironmentName }
        if (-not $environment) {
            throw "Environment with DisplayName '$EnvironmentName' doesn't exist."
        }
    }

    process {
        $requestBody = @{
            name       = (New-Guid).Guid
            properties = @{
                roledefinition = @{
                    id = "$($environment.id)/roleDefinitions/$RoleDefinition"
                }
                principal      = @{
                    id = "$PrincipalId"
                }
            }
        }
        if ($PSCmdlet.ShouldProcess("Create roleAssignment $roleDefinition for $($environment.id)")) {
            try {
                $roleAssignmentPayload = @{
                    Method      = 'Post'
                    Path        = '{0}/roleAssignments' -f $environment.id
                    RequestBody = ($requestBody | ConvertTo-Json -Depth 100)
                }
                Write-Verbose -Message "Create roleAssignment $roleDefinition for $($environment.id)"
                Invoke-PowerOpsRequest @roleAssignmentPayload
            }
            catch {
                Write-Error $_
            }
        }
    }
    end {

    }
}
function Remove-PowerOpsEnvironment {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Name')]
        [ValidateNotNullOrEmpty()]
        [string]$EnvironmentName,
        [Parameter(Mandatory = $true, ParameterSetName = 'Id')]
        [ValidateNotNullOrEmpty()]
        [string]$EnvironmentId,
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    begin {
        # Validate if environment exists
        if ($EnvironmentName) {
            $existingEnv = Invoke-PowerOpsRequest -Method Get -Path '/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments' | Where-Object { $_.properties.displayName -eq $EnvironmentName }
            if (-not $existingEnv) {
                throw "Environment with DisplayName '$Name' doesn't exists in Power Platform. Nothing to remove"
            }
            $environmentId = $existingEnv.name
        }
        Write-Verbose -Message "EnvironmentId is $EnvironmentId"
        $validateUri = '/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments/{0}/validateDelete?api-version=2018-01-01' -f $environmentId
        $validateDelete = Invoke-PowerOpsRequest -Method Post -Path $validateUri -Force
        Write-Verbose "CanInitiateDelete: $($validateDelete.canInitiateDelete)"
    }
    process {
        if ($validateDelete.canInitiateDelete) {
            if ($PSCmdlet.ShouldProcess("Delete environment $EnvironmentId")) {
                try {
                    $restCall = @{
                        path   = '/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments/{0}?api-version=2018-01-01' -f $existingEnv.Name
                        method = 'Delete'
                    }
                    Write-Verbose -Message "Deleting environment $EnvironmentId"
                    Invoke-PowerOpsRequest @restCall -Force
                    Write-Verbose -Message "Successfully deleted environment $EnvironmentId"
                }
                catch {
                    Write-Error $_
                }
            }
        }
        else {
            Write-Error "Cannot initiate delete"
            return $validateDelete.errors
        }
    }
}
function New-PowerOpsDLPPolicy {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,
        [Parameter(Mandatory = $false)]
        [switch]$Force,
        [Parameter(Mandatory = $false)]
        [string]$TemplateFile
    )
    begin {
        # Validate template
        $Template = Get-Content -Raw -Path $TemplateFile | ConvertFrom-Json -Depth 100
        # Validate if environment with the same name already exists
        if (-not $PSBoundParameters['Force']) {
            $existingPolicy = Invoke-PowerOpsRequest -Method Get -Path '/providers/PowerPlatform.Governance/v1/policies?$top=100' | Where-Object { $_.displayName -eq $Name }
            if ($existingPolicy) {
                throw "DLP Policy with DisplayName '$Name' already exists in Power Platform. Retry command with the -Force switch if you really want to create the policy with the duplicate name"
            }
        }
        # Update displayname in template from parameter
        $Template.displayName = $Name
    }
    process {
        # API payload
        try {
            if ($PSCmdlet.ShouldProcess("Create DLP Policy $Name")) {
                Write-Verbose -Message "Creating DLP Policy $Name"
                Invoke-PowerOpsRequest -Method Post -Path '/providers/PowerPlatform.Governance/v1/policies' -RequestBody ($template | ConvertTo-Json -Depth 100)
            }
        }
        catch {
            Write-Error $_
        }

    }
    end {

    }
    #>
}
function Get-PowerOpsTenantSettings {
    $tenantSettings = Invoke-PowerOpsRequest -Method Post -Path '/providers/Microsoft.BusinessAppPlatform/listTenantSettings'
    return $tenantSettings
}

function Get-PowerOpsEnvironment {
    $existingEnv = Invoke-PowerOpsRequest -Method Get -Path '/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments'
    return $existingEnv
}

function Enable-PowerOpsManagedEnvironment {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        $EnvironmentName = '',
        [Parameter(Mandatory = $false)]
        $GroupSharingDisabled = $false,
        [Parameter(Mandatory = $false)]
        $MaxLimitUserSharing = -1
    )
    Write-Verbose -Message "Enabling managed environment for $Name"
    $patchBody = @{
        properties = @{
            governanceConfiguration = @{
                protectionLevel = "Standard"
                settings        = @{
                    extendedSettings = @{
                        excludeEnvironmentFromAnalysis = $false
                        isGroupSharingDisabled         = $GroupSharingDisabled
                        maxLimitUserSharing            = $MaxLimitUserSharing
                    }
                }
            }
        }
    }
    $patchPath = '/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments/{0}' -f $EnvironmentName
    Invoke-PowerOpsRequest -Method Patch -Path $patchPath -RequestBody ($patchBody | ConvertTo-Json -Depth 100)
}
function Invoke-PowerOpsPull {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    #region tenant settings
    $tenantDetails = Get-AzTenant | Select-Object -First 1
    $tenantDomain = (((Invoke-AzRestMethod -Uri https://graph.microsoft.com/v1.0/domains).Content | ConvertFrom-Json).value).id
    $tenantSettings = Invoke-PowerOpsRequest -Method Post -Path '/providers/Microsoft.BusinessAppPlatform/listTenantSettings'
    $tenantSettingsFile = '{0}_{1}.json' -f $tenantDomain, $tenantDetails.Id

    $rootDirectory = "$($tenantDomain) ($($tenantDetails.Id))"
    if ($PSBoundParameters['Force']) {
        Remove-Item -Path $rootDirectory -Force -Recurse
    }
    $null = New-Item -ItemType Directory -Name $rootDirectory/tenant -Force
    $tenantsettings | ConvertTo-Json -Depth 100 | Out-File -Path $rootDirectory/tenant/$tenantSettingsFile -Force
    $isolationPath = "/providers/PowerPlatform.Governance/v1/tenants/{0}/tenantIsolationPolicy" -f (Get-AzTenant).Id
    $isolationSettings = Invoke-PowerOpsRequest -Method Get -Path $isolationPath
    $isolationSettings | ConvertTo-Json -Depth 100 | Out-File -Path "$rootDirectory/tenant/isolation_$tenantDomain.json" -Force
    #endregion tenant settings

    #region get environments
    $environments = Invoke-PowerOpsRequest -Method Get -Path '/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments'
    if ($environments) { $null = New-Item -ItemType Directory -Path $rootDirectory -Name 'environments' -Force }
    foreach ($environment in $environments) {
        $envPath = $rootDirectory + '/environments'
        $filePath = '{0}/{1}_{2}.json' -f $envPath, $environment.properties.displayName, $environment.name
        Write-Output -InputObject "Creating environment $filepath"
        $environment | ConvertTo-Json -Depth 100 | jq 'del (.properties.lastModifiedTime,.properties.retentionPeriod,.properties.states,.properties.retentionDetails,.properties.cluster,.properties.lifecycleOperationsEnforcement,.properties.notificationMetadata)' | Out-File -Path $filePath -Force
    }
    #endregion get environments

    #region get environments
    $policies = Invoke-PowerOpsRequest -Method Get -Path '/providers/PowerPlatform.Governance/v1/policies'
    if ($policies) { $null = New-Item -ItemType Directory -Path $rootDirectory -Name 'policies' -Force }
    foreach ($policy in $policies) {
        $policyPath = $rootDirectory + '/policies'
        $filePath = '{0}/{1}_{2}.json' -f $policyPath, $policy.displayName, $policy.name
        Write-Output -InputObject "Creating policy $filepath"
        $policy | ConvertTo-Json -Depth 100 | jq 'del (.etag,.createdBy,.createdTime,.lastModifiedBy,.lastModifiedTime,.isLegacySchemaVersion)' | Out-File -Path $filePath -Force
    }
    #endregion get environments
}
function New-PowerOpsScope {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory = $true)]
        $FilePath
    )
    $FilePath = Get-ChildItem -Path $FilePath
    $tenantDetails = Get-AzTenant | Select-Object -First 1
    $templateDetails = Get-Content -Path $FilePath.FullName | ConvertFrom-Json -Depth 100

    switch ($FilePath.FullName) {
        { $_.split('/')[-1] -match $tenantDetails.id } {
            [PSCustomObject]@{
                path   = '/providers/Microsoft.BusinessAppPlatform/scopes/admin/updateTenantSettings'
                method = 'Post'
            }
        }
        { $_ -match 'policies' } {
            [PSCustomObject]@{
                path   = '/providers/PowerPlatform.Governance/v1/policies/{0}' -f $templateDetails.Name
                method = 'Patch'
            }
        }
        { $_ -match 'environments' } {
            [PSCustomObject]@{
                path   = '/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments/{0}' -f $templateDetails.Name
                method = 'Patch'
            }
        }
    }
}
function Invoke-PowerOpsPush {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory = $true)]
        $ChangeSet
    )
    $deleteSet = @()
    $addModifySet = foreach ($change in $ChangeSet) {
        $operation, $filename = ($change -split "`t")[0, -1]
        if ($operation -eq 'D') {
            $deleteSet += $filename
            continue
        }
        if ($operation -in 'A', 'M', 'R' -or $operation -match '^R0[0-9][0-9]$') { $filename }
    }

    foreach ($addModify in $addModifySet) {
        Write-Output -InputObject "Adding or modifying $addModify"
        New-PowerOpsDeployment -FilePath $addModify
    }
    foreach ($deletion in $deleteSet) {
        Write-Output -InputObject "Removing $deletion"
    }
}
function New-PowerOpsDeployment {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory = $true)]
        $FilePath
    )
    $deploymentType = New-PowerOpsScope -FilePath $FilePath
    Write-Output -InputObject "Attempting to deploy $filePath to $($deploymentType.Path)"
    Invoke-PowerOpsRequest -Path $deploymentType.Path -Method $deploymentType.Method -RequestBody (Get-Content -Path $FilePath)
}
function Get-PowerOpsTenantCapacityStatus {
    $TenantId = (Get-AzContext).Tenant.Id
    $AccessTokenLicense = Get-AzAccessToken -ResourceUrl 'https://licensing.powerplatform.microsoft.com'
    $Headers = @{
        "Content-Type"  = "application/json; charset=utf-8"
        "Authorization" = "Bearer $($AccessTokenLicense.Token)"
    }
    Invoke-RestMethod -Headers $Headers -Uri https://licensing.powerplatform.microsoft.com/v0.1-alpha/tenants/$TenantId/TenantCapacity -Method GET -ContentType 'application/json; charset=utf-8'
}
function Get-PowerOpsAADPermissions {
    # TODO - add support for service principals
    $roleDefinitions = ((Invoke-AzRestMethod -Uri https://graph.microsoft.com/v1.0/directoryRoleTemplates).Content  | ConvertFrom-Json -Depth 100).value
    $currentUser = (Invoke-AzRestMethod -Uri https://graph.microsoft.com/v1.0/me).Content | ConvertFrom-Json
    $graphQuery = "?`$filter=principalId eq '{0}'" -f $currentUser.id
    $AADRoleAssignments = (Invoke-AzRestMethod -Uri "https://graph.microsoft.com/beta/roleManagement/directory/roleAssignments$($graphQuery)").Content | ConvertFrom-Json -Depth 100
    foreach ($role in $AADRoleAssignments.value) {
        $roleDetails = $roleDefinitions | Where-Object { $_.id -eq $role.roleDefinitionId }
        $roleDetails
    }
}
function Set-PowerOpsTenantIsolation {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory = $true)]
        [bool]$Enabled,
        [Parameter(Mandatory = $false)]
        [ValidateSet('InboundAndOutbound', 'Inbound', 'Outbound')]
        [string]$AllowedDirection,
        [Parameter(Mandatory = $false)]
        [string]$TenantId
    )
    $Path = "/providers/PowerPlatform.Governance/v1/tenants/{0}/tenantIsolationPolicy" -f (Get-AzTenant).Id
    Write-Verbose -Message "API Path: $Path"
    # Validate tenantId
    if ($TenantId -match '.' -and $TenantId -ne "*") {
        $wellKnown = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantId/.well-known/openid-configuration"
        if (-not $wellKnown.issuer) {
            throw "Tenant $TenantId does not exist in public Azure "
        }
        else {
            $TenantId = $wellknown.issuer.Split("/")[-2]
        }
    }
    Write-Verbose -Message "TenantId: $TenantId"

    # Get existing isolation settings
    $existingSettings = Invoke-PowerOpsRequest -Method Get -Path $Path

    # Update settings
    $newSettings = [PSCustomObject]@{ properties = $existingSettings }
    $newSettings.properties.isDisabled = ($Enabled -eq $false)
    Write-Verbose -Message "Tenant Isolation isDisabled will be set to $($newSettings.properties.isDisabled)"
    if ($TenantId -and $AllowedDirection) {
        # Check if rule for tenant already exists and update accordingly
        $existingRule = $newSettings.properties.allowedTenants | Where-Object { $_.TenantId -eq $TenantId }
        if ($existingRule.tenantId -eq $TenantId) {
            # Update existing tenant rule
            Write-Verbose -Message "Tenant rule for $TenantId already exist"
            $existingRule.direction.inbound = $AllowedDirection -in 'Inbound', 'InboundAndOutBound'
            $existingRule.direction.outbound = $AllowedDirection -in 'Outbound', 'InboundAndOutBound'
        }
        else {
            # Create new rule for tenant
            $newSettings.properties.allowedTenants += [PSCustomObject]@{
                tenantId  = $TenantId
                direction = [PSCustomObject]@{
                    inbound  = $AllowedDirection -in 'Inbound', 'InboundAndOutBound'
                    outbound = $AllowedDirection -in 'Outbound', 'InboundAndOutBound'
                }
            }
        }

    }
    Write-Verbose -Message "Tenant rule for $TenantId will be configured in the direction $AllowedDirection"

    if ($PSCmdlet.ShouldProcess("Update tenant isolation settings to Enabled=$Enabled")) {
        Invoke-PowerOpsRequest -Method Put -Path $Path -RequestBody ($newSettings | ConvertTo-Json -Depth 100)
    }
}
function New-EnvironmentCreationObject {
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'ARMInputString')]$ARMInputString,
        [Parameter(Mandatory = $true, ParameterSetName = 'EnvCount')][int]$EnvCount,
        [Parameter(Mandatory = $true, ParameterSetName = 'EnvCount')]$EnvNaming,
        [Parameter(Mandatory = $true, ParameterSetName = 'EnvCount')]$EnvRegion,
        [Parameter(Mandatory = $true, ParameterSetName = 'EnvCount')]$EnvLanguage,
        [Parameter(Mandatory = $true, ParameterSetName = 'EnvCount')]$EnvCurrency,
        [Parameter(Mandatory = $true, ParameterSetName = 'EnvCount')]$EnvDescription,
        [Parameter(Mandatory = $false)][switch]$EnvALM,
        [Parameter(Mandatory = $false, ParameterSetName = 'EnvCount')][switch]$EnvDataverse
    )
    if (-not [string]::IsNullOrEmpty($ARMInputString)) {
        foreach ($env in ($ARMInputString -split 'ppEnvName:')) {
            if ($env -match ".") {
                $environment = $env.TrimEnd(',')
                if ($EnvALM) {
                    foreach ($envTier in $envTiers) {
                        [PSCustomObject]@{
                            envRegion      = ($environment -split (','))[2].Split(':')[1]
                            envLanguage    = ($environment -split (','))[3].Split(':')[1]
                            envCurrency    = ($environment -split (','))[4].Split(':')[1]
                            envDescription = ($environment -split (','))[1].Split(':')[1]
                            envRbac        = ($environment -split (','))[5].Split(':')[1]
                            envName        = '{0}-{1}' -f ($environment -split (','))[0], $envTier
                        }
                    }
                }
                else {
                    [PSCustomObject]@{
                        envName        = ($environment -split (','))[0]
                        envSubType        = ($environment -split (','))[2].Split(':')[1]
                        envRegion      = ($environment -split (','))[3].Split(':')[1]
                        envLanguage    = ($environment -split (','))[4].Split(':')[1]
                        envCurrency    = ($environment -split (','))[5].Split(':')[1]
                        envDescription = ($environment -split (','))[1].Split(':')[1]
                    }
                }
            }
        }
    }
    else {
        1..$EnvCount | ForEach-Object -Process {
            $environmentName = "{0}-{1:d3}" -f $EnvNaming, $_
            if ($true -eq $EnvALM) {
                foreach ($envTier in $envTiers) {
                    [PSCustomObject]@{
                        envName        = "{0}-{1}" -f $environmentName, $envTier
                        envRegion      = $EnvRegion
                        envDataverse   = $EnvDataverse
                        envLanguage    = $envLanguage
                        envCurrency    = $envCurrency
                        envDescription = $envDescription
                        envRbac        = ''
                    }
                }
            }
            else {
                [PSCustomObject]@{
                    envName        = $environmentName
                    envRegion      = $EnvRegion
                    envDataverse   = $EnvDataverse
                    envLanguage    = $envLanguage
                    envCurrency    = $envCurrency
                    envDescription = $envDescription
                    envRbac        = ''
                }
            }
        }
    }
}
if ($finOpsEnv -ne 'null') {
    try {
        $environmentsToCreate = New-EnvironmentCreationObject -ARMInputString ($finOpsEnv -join ',')
    }
    catch {
        throw "Failed to create environment object. Input data is malformed. '`r`n$_'"
    }
}
foreach ($environment in $environmentsToCreate) {
        try {
            $envCreationHt = @{
                Name               = $environment.envName
                Location           = $environment.envRegion
                Dataverse          = $true
                ManagedEnvironment = $false
                Description        = $environment.envDescription
                LanguageName       = $environment.envLanguage
                Currency           = $environment.envCurrency
                SecurityGroupId    = ''
                SubType          =  $environment.envSubType
                Templates           = 'D365_FinOps_Finance'
            }
            $null = New-PowerOpsEnvironment @envCreationHt
            Write-Output "Created FinOps environment $($environment.envName) in $($environment.envRegion)"
            if (-not [string]::IsNullOrEmpty($environment.envRbac) -and $environment.envDataverse -eq $false) {
                Write-Output "Assigning RBAC for principalId $($environment.envRbac) in citizen environment $($environment.envName)"
                $null = New-PowerOpsRoleAssignment -PrincipalId $environment.envRbac -RoleDefinition EnvironmentAdmin -EnvironmentName $environment.envName
            }
        }
        catch {
            Write-Warning "Failed to create FinOps environment $($environment.envName) "
        }
    }
