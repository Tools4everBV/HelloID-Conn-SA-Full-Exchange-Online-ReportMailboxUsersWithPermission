# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12
#HelloID variables
#Note: when running this script inside HelloID; portalUrl and API credentials are provided automatically (generate and save API credentials first in your admin panel!)
$portalUrl = "https://CUSTOMER.helloid.com"
$apiKey = "API_KEY"
$apiSecret = "API_SECRET"
$delegatedFormAccessGroupNames = @("Users","HID_administrators") #Only unique names are supported. Groups must exist!
$delegatedFormCategories = @("Active Directory","User Management") #Only unique names are supported. Categories will be created if not exists
$script:debugLogging = $false #Default value: $false. If $true, the HelloID resource GUIDs will be shown in the logging
$script:duplicateForm = $false #Default value: $false. If $true, the HelloID resource names will be changed to import a duplicate Form
$script:duplicateFormSuffix = "_tmp" #the suffix will be added to all HelloID resource names to generate a duplicate form with different resource names

#The following HelloID Global variables are used by this form. No existing HelloID global variables will be overriden only new ones are created.
#NOTE: You can also update the HelloID Global variable values afterwards in the HelloID Admin Portal: https://<CUSTOMER>.helloid.com/admin/variablelibrary
$globalHelloIDVariables = [System.Collections.Generic.List[object]]@();

#Global variable #1 >> ExchangeOnlineAdminUsername
$tmpName = @'
ExchangeOnlineAdminUsername
'@ 
$tmpValue = @'
svc_helloid@enyoi.nl
'@ 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});

#Global variable #2 >> ExchangeOnlineAdminPassword
$tmpName = @'
ExchangeOnlineAdminPassword
'@ 
$tmpValue = "" 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "True"});


#make sure write-information logging is visual
$InformationPreference = "continue"
# Check for prefilled API Authorization header
if (-not [string]::IsNullOrEmpty($portalApiBasic)) {
    $script:headers = @{"authorization" = $portalApiBasic}
    Write-Information "Using prefilled API credentials"
} else {
    # Create authorization headers with HelloID API key
    $pair = "$apiKey" + ":" + "$apiSecret"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
    $base64 = [System.Convert]::ToBase64String($bytes)
    $key = "Basic $base64"
    $script:headers = @{"authorization" = $Key}
    Write-Information "Using manual API credentials"
}
# Check for prefilled PortalBaseURL
if (-not [string]::IsNullOrEmpty($portalBaseUrl)) {
    $script:PortalBaseUrl = $portalBaseUrl
    Write-Information "Using prefilled PortalURL: $script:PortalBaseUrl"
} else {
    $script:PortalBaseUrl = $portalUrl
    Write-Information "Using manual PortalURL: $script:PortalBaseUrl"
}
# Define specific endpoint URI
$script:PortalBaseUrl = $script:PortalBaseUrl.trim("/") + "/"  
 
function Invoke-HelloIDGlobalVariable {
    param(
        [parameter(Mandatory)][String]$Name,
        [parameter(Mandatory)][String][AllowEmptyString()]$Value,
        [parameter(Mandatory)][String]$Secret
    )
    $Name = $Name + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })
    try {
        $uri = ($script:PortalBaseUrl + "api/v1/automation/variables/named/$Name")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
    
        if ([string]::IsNullOrEmpty($response.automationVariableGuid)) {
            #Create Variable
            $body = @{
                name     = $Name;
                value    = $Value;
                secret   = $Secret;
                ItemType = 0;
            }    
            $body = ConvertTo-Json -InputObject $body
    
            $uri = ($script:PortalBaseUrl + "api/v1/automation/variable")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
            $variableGuid = $response.automationVariableGuid
            Write-Information "Variable '$Name' created$(if ($script:debugLogging -eq $true) { ": " + $variableGuid })"
        } else {
            $variableGuid = $response.automationVariableGuid
            Write-Warning "Variable '$Name' already exists$(if ($script:debugLogging -eq $true) { ": " + $variableGuid })"
        }
    } catch {
        Write-Error "Variable '$Name', message: $_"
    }
}
function Invoke-HelloIDAutomationTask {
    param(
        [parameter(Mandatory)][String]$TaskName,
        [parameter(Mandatory)][String]$UseTemplate,
        [parameter(Mandatory)][String]$AutomationContainer,
        [parameter(Mandatory)][String][AllowEmptyString()]$Variables,
        [parameter(Mandatory)][String]$PowershellScript,
        [parameter()][String][AllowEmptyString()]$ObjectGuid,
        [parameter()][String][AllowEmptyString()]$ForceCreateTask,
        [parameter(Mandatory)][Ref]$returnObject
    )
    
    $TaskName = $TaskName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/automationtasks?search=$TaskName&container=$AutomationContainer")
        $responseRaw = (Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false) 
        $response = $responseRaw | Where-Object -filter {$_.name -eq $TaskName}
    
        if([string]::IsNullOrEmpty($response.automationTaskGuid) -or $ForceCreateTask -eq $true) {
            #Create Task
            $body = @{
                name                = $TaskName;
                useTemplate         = $UseTemplate;
                powerShellScript    = $PowershellScript;
                automationContainer = $AutomationContainer;
                objectGuid          = $ObjectGuid;
                variables           = [Object[]]($Variables | ConvertFrom-Json);
            }
            $body = ConvertTo-Json -InputObject $body
    
            $uri = ($script:PortalBaseUrl +"api/v1/automationtasks/powershell")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
            $taskGuid = $response.automationTaskGuid
            Write-Information "Powershell task '$TaskName' created$(if ($script:debugLogging -eq $true) { ": " + $taskGuid })"
        } else {
            #Get TaskGUID
            $taskGuid = $response.automationTaskGuid
            Write-Warning "Powershell task '$TaskName' already exists$(if ($script:debugLogging -eq $true) { ": " + $taskGuid })"
        }
    } catch {
        Write-Error "Powershell task '$TaskName', message: $_"
    }
    $returnObject.Value = $taskGuid
}
function Invoke-HelloIDDatasource {
    param(
        [parameter(Mandatory)][String]$DatasourceName,
        [parameter(Mandatory)][String]$DatasourceType,
        [parameter(Mandatory)][String][AllowEmptyString()]$DatasourceModel,
        [parameter()][String][AllowEmptyString()]$DatasourceStaticValue,
        [parameter()][String][AllowEmptyString()]$DatasourcePsScript,        
        [parameter()][String][AllowEmptyString()]$DatasourceInput,
        [parameter()][String][AllowEmptyString()]$AutomationTaskGuid,
        [parameter(Mandatory)][Ref]$returnObject
    )
    $DatasourceName = $DatasourceName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })
    $datasourceTypeName = switch($DatasourceType) { 
        "1" { "Native data source"; break} 
        "2" { "Static data source"; break} 
        "3" { "Task data source"; break} 
        "4" { "Powershell data source"; break}
    }
    
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/datasource/named/$DatasourceName")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
      
        if([string]::IsNullOrEmpty($response.dataSourceGUID)) {
            #Create DataSource
            $body = @{
                name               = $DatasourceName;
                type               = $DatasourceType;
                model              = [Object[]]($DatasourceModel | ConvertFrom-Json);
                automationTaskGUID = $AutomationTaskGuid;
                value              = [Object[]]($DatasourceStaticValue | ConvertFrom-Json);
                script             = $DatasourcePsScript;
                input              = [Object[]]($DatasourceInput | ConvertFrom-Json);
            }
            $body = ConvertTo-Json -InputObject $body
      
            $uri = ($script:PortalBaseUrl +"api/v1/datasource")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
              
            $datasourceGuid = $response.dataSourceGUID
            Write-Information "$datasourceTypeName '$DatasourceName' created$(if ($script:debugLogging -eq $true) { ": " + $datasourceGuid })"
        } else {
            #Get DatasourceGUID
            $datasourceGuid = $response.dataSourceGUID
            Write-Warning "$datasourceTypeName '$DatasourceName' already exists$(if ($script:debugLogging -eq $true) { ": " + $datasourceGuid })"
        }
    } catch {
      Write-Error "$datasourceTypeName '$DatasourceName', message: $_"
    }
    $returnObject.Value = $datasourceGuid
}
function Invoke-HelloIDDynamicForm {
    param(
        [parameter(Mandatory)][String]$FormName,
        [parameter(Mandatory)][String]$FormSchema,
        [parameter(Mandatory)][Ref]$returnObject
    )
    
    $FormName = $FormName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })
    try {
        try {
            $uri = ($script:PortalBaseUrl +"api/v1/forms/$FormName")
            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        } catch {
            $response = $null
        }
    
        if(([string]::IsNullOrEmpty($response.dynamicFormGUID)) -or ($response.isUpdated -eq $true)) {
            #Create Dynamic form
            $body = @{
                Name       = $FormName;
                FormSchema = [Object[]]($FormSchema | ConvertFrom-Json)
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl +"api/v1/forms")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
    
            $formGuid = $response.dynamicFormGUID
            Write-Information "Dynamic form '$formName' created$(if ($script:debugLogging -eq $true) { ": " + $formGuid })"
        } else {
            $formGuid = $response.dynamicFormGUID
            Write-Warning "Dynamic form '$FormName' already exists$(if ($script:debugLogging -eq $true) { ": " + $formGuid })"
        }
    } catch {
        Write-Error "Dynamic form '$FormName', message: $_"
    }
    $returnObject.Value = $formGuid
}
function Invoke-HelloIDDelegatedForm {
    param(
        [parameter(Mandatory)][String]$DelegatedFormName,
        [parameter(Mandatory)][String]$DynamicFormGuid,
        [parameter()][String][AllowEmptyString()]$AccessGroups,
        [parameter()][String][AllowEmptyString()]$Categories,
        [parameter(Mandatory)][String]$UseFaIcon,
        [parameter()][String][AllowEmptyString()]$FaIcon,
        [parameter(Mandatory)][Ref]$returnObject
    )
    $delegatedFormCreated = $false
    $DelegatedFormName = $DelegatedFormName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })
    try {
        try {
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms/$DelegatedFormName")
            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        } catch {
            $response = $null
        }
    
        if([string]::IsNullOrEmpty($response.delegatedFormGUID)) {
            #Create DelegatedForm
            $body = @{
                name            = $DelegatedFormName;
                dynamicFormGUID = $DynamicFormGuid;
                isEnabled       = "True";
                accessGroups    = [Object[]]($AccessGroups | ConvertFrom-Json);
                useFaIcon       = $UseFaIcon;
                faIcon          = $FaIcon;
            }    
            $body = ConvertTo-Json -InputObject $body
    
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
    
            $delegatedFormGuid = $response.delegatedFormGUID
            Write-Information "Delegated form '$DelegatedFormName' created$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormGuid })"
            $delegatedFormCreated = $true
            $bodyCategories = $Categories
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms/$delegatedFormGuid/categories")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $bodyCategories
            Write-Information "Delegated form '$DelegatedFormName' updated with categories"
        } else {
            #Get delegatedFormGUID
            $delegatedFormGuid = $response.delegatedFormGUID
            Write-Warning "Delegated form '$DelegatedFormName' already exists$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormGuid })"
        }
    } catch {
        Write-Error "Delegated form '$DelegatedFormName', message: $_"
    }
    $returnObject.value.guid = $delegatedFormGuid
    $returnObject.value.created = $delegatedFormCreated
}<# Begin: HelloID Global Variables #>
foreach ($item in $globalHelloIDVariables) {
	Invoke-HelloIDGlobalVariable -Name $item.name -Value $item.value -Secret $item.secret 
}
<# End: HelloID Global Variables #>


<# Begin: HelloID Data sources #>
<# Begin: DataSource "mailbox-generate-users-with-permission-userprincipalname" #>
$tmpPsScript = @'
$UserPrincipalName = $datasource.UserPrincipalName

# Connect to Office 365
try{
    Write-Verbose -Verbose "Connecting to Office 365.."

    $module = Import-Module ExchangeOnlineManagement

    $securePassword = ConvertTo-SecureString $ExchangeOnlineAdminPassword -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential ($ExchangeOnlineAdminUsername, $securePassword)

    $exchangeSession = Connect-ExchangeOnline -Credential $credential -ShowBanner:$false -ShowProgress:$false -TrackPerformance:$false -ErrorAction Stop 

    Write-Verbose -Verbose "Successfully connected to Office 365"
}catch{
    throw "Could not connect to Exchange Online, error: $_"
}

# Get Exchange mailbox permissions
try {
    Write-Verbose -Verbose "Searching for mailbox: $UserPrincipalName"
        
    $mailbox = Get-EXOMailbox -Identity $UserPrincipalName -ErrorAction Stop

    # List all users with Full Access permissions
    Write-Verbose -Verbose "Gathering Full Access Permissions.."
    [System.Collections.ArrayList]$usersWithFullAccessPermission = @{}
    $fullAccessPermissions = Get-EXOMailboxPermission -Identity $mailbox.Identity -resultSize unlimited | Where-Object { ($_.accessRights -like "*fullaccess*") -and -not ($_.Deny -eq $true) -and -not ($_.User -match "NT AUTHORITY") -and -not ($_.User -like "*\Domain Admins")-and -not ($_.User -like "*\Organisations-Admins") -and -not ($_.User -like "*\Organization Management") -and -not ($_.User -like "*\Administrator") -and -not ($_.User -like "*\Exchange Servers") -and -not ($_.User -like "*\Exchange Trusted Subsystem") -and -not ($_.User -like "*\Enterprise Admins") -and -not ($_.User -like "*\Exchange Domain Servers") } -ErrorAction Stop
    foreach($entry in $fullAccessPermissions){
        $adUser = Get-ADUser -Filter "Name -eq '$($entry.User)'" -Properties DisplayName, SamAccountName, UserPrincipalName, Mail, Description, EmployeeId -ErrorAction Continue
        if($adUser){
            $adUser | Add-Member -MemberType NoteProperty -Name Permission -Value "Full Access" -Force
            $adUser | Add-Member -MemberType NoteProperty -Name InheritedFromGroup -Value $false -Force
            $adUser | Add-Member -MemberType NoteProperty -Name Group -Value $null -Force

            $null = $usersWithFullAccessPermission.Add($adUser)
        }else{
            $adGroup = Get-ADGroup -Identity $entry.User -ErrorAction Continue

            $Users = Get-ADGroupMember -Identity $adGroup -ErrorAction Continue
            foreach($User in $Users){
                    $adUser = Get-ADUser -Identity $User -Properties DisplayName, SamAccountName, UserPrincipalName, Mail, Description, EmployeeId -ErrorAction Continue

                    $adUser | Add-Member -MemberType NoteProperty -Name Permission -Value "Full Access" -Force
                    $adUser | Add-Member -MemberType NoteProperty -Name InheritedFromGroup -Value $true -Force
                    $adUser | Add-Member -MemberType NoteProperty -Name Group -Value $($adGroup.Name) -Force

                    $null = $usersWithFullAccessPermission.Add($adUser)
            }
        }
    }

    Write-Information "Users with Full Access permissions: $($usersWithFullAccessPermission.Name.Count)"
    
    if($usersWithFullAccessPermission.Name.Count -gt 0){
        foreach($user in $usersWithFullAccessPermission){
            $returnObject = [Ordered]@{
                Permission=$user.Permission;
                DisplayName=$user.displayName;
                SamAccountName=$user.SamAccountName;
                UserPrincipalName=$user.UserPrincipalName;
                Mail=$user.mail;
                Description=$user.Description;
                EmployeeId=$user.EmployeeId;
                InheritedFromGroup = $user.InheritedFromGroup;
                Group = $user.Group
            }
            Write-Output $returnObject
        }
    }



    # List all users with Send As permissions
    Write-Verbose -Verbose "Gathering Send As Permissions.."
    [System.Collections.ArrayList]$usersWithSendAsPermission = @{}
    $sendAsPermissions = $mailbox | Get-EXORecipientPermission | Where-Object { $_.AccessRights -like 'Send*' -and -not ($_.Trustee -match "NT AUTHORITY") }
    foreach($entry in $sendAsPermissions){
        $adUser = Get-ADUser -Filter "UserPrincipalName -eq '$($entry.Trustee)'" -Properties DisplayName, SamAccountName, UserPrincipalName, Mail, Description, EmployeeId -ErrorAction Continue
        if($adUser){
            $adUser | Add-Member -MemberType NoteProperty -Name Permission -Value "Send As" -Force
            $adUser | Add-Member -MemberType NoteProperty -Name InheritedFromGroup -Value $false -Force
            $adUser | Add-Member -MemberType NoteProperty -Name Group -Value $null -Force

            $null = $usersWithSendAsPermission.Add($adUser)
        }else{
            $adGroup = Get-ADGroup -Identity $entry.Trustee -ErrorAction Continue

            $Users = Get-ADGroupMember -Identity $adGroup -ErrorAction Continue
            foreach($User in $Users){
                    $adUser = Get-ADUser -Identity $User -Properties DisplayName, SamAccountName, UserPrincipalName, Mail, Description, EmployeeId -ErrorAction Continue

                    $adUser | Add-Member -MemberType NoteProperty -Name Permission -Value "Send As" -Force
                    $adUser | Add-Member -MemberType NoteProperty -Name InheritedFromGroup -Value $true -Force
                    $adUser | Add-Member -MemberType NoteProperty -Name Group -Value $($adGroup.Name) -Force

                    $null = $usersWithSendAsPermission.Add($adUser)
            }
        }
    }

    Write-Information "Users with Send As permissions: $($usersWithSendAsPermission.Name.Count)"
    
    if($usersWithSendAsPermission.Name.Count -gt 0){
        foreach($user in $usersWithSendAsPermission){
            $returnObject = [Ordered]@{
                Permission=$user.Permission;
                DisplayName=$user.displayName;
                SamAccountName=$user.SamAccountName;
                UserPrincipalName=$user.UserPrincipalName;
                Mail=$user.mail;
                Description=$user.Description;
                EmployeeId=$user.EmployeeId;
                InheritedFromGroup = $user.InheritedFromGroup;
                Group = $user.Group
            }
            Write-Output $returnObject
        }
    }

    # List all users with Send on behalf permissions
    Write-Verbose -Verbose "Gathering Send On Behalf Permissions.."
    [System.Collections.ArrayList]$usersWithSendOnBehalfPermission = @{}
    foreach($entry in $mailbox.GrantSendOnBehalfTo){
        $adUser = Get-ADUser -Filter "Name -eq '$($entry)'" -Properties DisplayName, SamAccountName, UserPrincipalName, Mail, Description, EmployeeId -ErrorAction Continue
        if($adUser){
            $adUser | Add-Member -MemberType NoteProperty -Name Permission -Value "Send On Behalf" -Force
            $adUser | Add-Member -MemberType NoteProperty -Name InheritedFromGroup -Value $false -Force
            $adUser | Add-Member -MemberType NoteProperty -Name Group -Value $null -Force

            $null = $usersWithSendAsPermission.Add($adUser)
        }else{
            $adGroup = Get-ADGroup -Identity $entry -ErrorAction Continue

            $Users = Get-ADGroupMember -Identity $adGroup -ErrorAction Continue
            foreach($User in $Users){
                    $adUser = Get-ADUser -Identity $User -Properties DisplayName, SamAccountName, UserPrincipalName, Mail, Description, EmployeeId -ErrorAction Continue

                    $adUser | Add-Member -MemberType NoteProperty -Name Permission -Value "Send On Behalf" -Force
                    $adUser | Add-Member -MemberType NoteProperty -Name InheritedFromGroup -Value $true -Force
                    $adUser | Add-Member -MemberType NoteProperty -Name Group -Value $($adGroup.Name) -Force

                    $null = $usersWithSendAsPermission.Add($adUser)
            }
        }
    }

    Write-Information "Users with Send As permissions: $($usersWithSendOnBehalfPermission.Name.Count)"
    
    if($usersWithSendOnBehalfPermission.Name.Count -gt 0){
        foreach($user in $usersWithSendAsPermission){
            $returnObject = [Ordered]@{
                Permission=$user.Permission;
                DisplayName=$user.displayName;
                SamAccountName=$user.SamAccountName;
                UserPrincipalName=$user.UserPrincipalName;
                Mail=$user.mail;
                Description=$user.Description;
                EmployeeId=$user.EmployeeId;
                InheritedFromGroup = $user.InheritedFromGroup;
                Group = $user.Group
            }
            Write-Output $returnObject
        }
    }

} catch {
    Write-Error "Error searching for mailbox permissions for mailbox: $User. Error: $_"
} finally {
    Write-Verbose -Verbose "Disconnecting from Office 365.."
    $exchangeSessionEnd = Disconnect-ExchangeOnline -Confirm:$false -Verbose:$false -ErrorAction Stop
    Write-Verbose -Verbose "Successfully disconnected from Office 365"
}
'@ 
$tmpModel = @'
[{"key":"Permission","type":0},{"key":"Group","type":0},{"key":"UserPrincipalName","type":0},{"key":"InheritedFromGroup","type":0},{"key":"EmployeeId","type":0},{"key":"SamAccountName","type":0},{"key":"DisplayName","type":0},{"key":"Mail","type":0},{"key":"Description","type":0}]
'@ 
$tmpInput = @'
[{"description":null,"translateDescription":false,"inputFieldType":1,"key":"UserPrincipalName","type":0,"options":1}]
'@ 
$dataSourceGuid_0 = [PSCustomObject]@{} 
$dataSourceGuid_0_Name = @'
mailbox-generate-users-with-permission-userprincipalname
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_0_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_0) 
<# End: DataSource "mailbox-generate-users-with-permission-userprincipalname" #>
<# End: HelloID Data sources #>

<# Begin: Dynamic Form "Mailbox - List users with permissions" #>
$tmpSchema = @"
[{"key":"userPrincipalName","templateOptions":{"label":"UserPrincipalName of Mailbox","required":true},"type":"input","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true},{"key":"gridUsersPermissions","templateOptions":{"label":"Users with permissions","required":false,"grid":{"columns":[{"headerName":"Permission","field":"Permission"},{"headerName":"Display Name","field":"DisplayName"},{"headerName":"UserPrincipalName","field":"UserPrincipalName"},{"headerName":"SamAccountName","field":"SamAccountName"},{"headerName":"Mail","field":"Mail"},{"headerName":"Employee Id","field":"EmployeeId"},{"headerName":"Description","field":"Description"},{"headerName":"Inherited From Group","field":"InheritedFromGroup"},{"headerName":"Group","field":"Group"}],"height":300,"rowSelection":"single"},"dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_0","input":{"propertyInputs":[{"propertyName":"UserPrincipalName","otherFieldValue":{"otherFieldKey":"userPrincipalName"}}]}},"useFilter":true,"useDefault":false},"type":"grid","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true}]
"@ 

$dynamicFormGuid = [PSCustomObject]@{} 
$dynamicFormName = @'
Mailbox - List users with permissions
'@ 
Invoke-HelloIDDynamicForm -FormName $dynamicFormName -FormSchema $tmpSchema  -returnObject ([Ref]$dynamicFormGuid) 
<# END: Dynamic Form #>

<# Begin: Delegated Form Access Groups and Categories #>
$delegatedFormAccessGroupGuids = @()
foreach($group in $delegatedFormAccessGroupNames) {
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/groups/$group")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        $delegatedFormAccessGroupGuid = $response.groupGuid
        $delegatedFormAccessGroupGuids += $delegatedFormAccessGroupGuid
        
        Write-Information "HelloID (access)group '$group' successfully found$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormAccessGroupGuid })"
    } catch {
        Write-Error "HelloID (access)group '$group', message: $_"
    }
}
$delegatedFormAccessGroupGuids = ($delegatedFormAccessGroupGuids | Select-Object -Unique | ConvertTo-Json -Compress)
$delegatedFormCategoryGuids = @()
foreach($category in $delegatedFormCategories) {
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/delegatedformcategories/$category")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        $tmpGuid = $response.delegatedFormCategoryGuid
        $delegatedFormCategoryGuids += $tmpGuid
        
        Write-Information "HelloID Delegated Form category '$category' successfully found$(if ($script:debugLogging -eq $true) { ": " + $tmpGuid })"
    } catch {
        Write-Warning "HelloID Delegated Form category '$category' not found"
        $body = @{
            name = @{"en" = $category};
        }
        $body = ConvertTo-Json -InputObject $body
        $uri = ($script:PortalBaseUrl +"api/v1/delegatedformcategories")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
        $tmpGuid = $response.delegatedFormCategoryGuid
        $delegatedFormCategoryGuids += $tmpGuid
        Write-Information "HelloID Delegated Form category '$category' successfully created$(if ($script:debugLogging -eq $true) { ": " + $tmpGuid })"
    }
}
$delegatedFormCategoryGuids = (ConvertTo-Json -InputObject $delegatedFormCategoryGuids -Compress)
<# End: Delegated Form Access Groups and Categories #>

<# Begin: Delegated Form #>
$delegatedFormRef = [PSCustomObject]@{guid = $null; created = $null} 
$delegatedFormName = @'
Mailbox - List users with permissions
'@
Invoke-HelloIDDelegatedForm -DelegatedFormName $delegatedFormName -DynamicFormGuid $dynamicFormGuid -AccessGroups $delegatedFormAccessGroupGuids -Categories $delegatedFormCategoryGuids -UseFaIcon "True" -FaIcon "fa fa-list" -returnObject ([Ref]$delegatedFormRef) 
<# End: Delegated Form #>

