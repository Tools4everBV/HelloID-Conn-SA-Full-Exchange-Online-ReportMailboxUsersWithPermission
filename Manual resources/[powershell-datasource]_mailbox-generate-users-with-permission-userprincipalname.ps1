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
