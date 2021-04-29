# Fixed values
$AutoMapping = $false

try {
    <#----- Exchange On-Premises: Start -----#>
    # Connect to Exchange
    try {
        $adminSecurePassword = ConvertTo-SecureString -String "$ExchangeAdminPassword" -AsPlainText -Force
        $adminCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ExchangeAdminUsername, $adminSecurePassword
        $sessionOption = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
        $exchangeSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $exchangeConnectionUri -Credential $adminCredential -SessionOption $sessionOption -ErrorAction Stop 
        #-AllowRedirection
        $null = Import-PSSession $exchangeSession -DisableNameChecking -AllowClobber
        HID-Write-Status -Message "Successfully connected to Exchange using the URI [$exchangeConnectionUri]" -Event Success
    }
    catch {
        HID-Write-Status -Message "Error connecting to Exchange using the URI [$exchangeConnectionUri]" -Event Error
        HID-Write-Status -Message "Error at line: $($_.InvocationInfo.ScriptLineNumber - 79): $($_.Exception.Message)" -Event Error
        if ($debug -eq $true) {
            HID-Write-Status -Message "$($_.Exception)" -Event Error
        }
        HID-Write-Summary -Message "Failed to connect to Exchange using the URI [$exchangeConnectionUri]" -Event Failed
        throw $_
    }

    Hid-Write-Status -Message "Checking if mailbox with identity '$($mailboxAlias)' exists" -Event Information
    $mailbox = Get-Mailbox -Identity $mailboxAlias -ErrorAction Stop
    if ($mailbox.Name.Count -eq 0) {
        throw "Could not find shared mailbox with identity '$($mailboxAlias)'"
    }
        
    
    # Add Send As Permissions for Mail-enabled Security Group for users
    try { 
        # Add Send As Permissions
        if ($usersToAddSendAs -ne "[]") {
            HID-Write-Status -Message "Starting to add send as members to mailbox $($mailboxAlias)" -Event Information
            $usersToAddJson = $usersToAddSendAs | ConvertFrom-Json
            foreach ($user in $usersToAddJson) {
                
                Add-ADPermission -Identity $mailboxDn -AccessRights ExtendedRight -ExtendedRights "Send As" -Confirm:$false -User $user.sAMAccountName -ErrorAction Stop
                
                Hid-Write-Status -Message "Assigned access rights [SendAs] for mailbox [$($mailboxAlias)] to [$($user.sAMAccountName)] successfully" -Event Success
                HID-Write-Summary -Message "Assigned access rights [SendAs] for mailbox [$($mailboxAlias)] to [$($user.sAMAccountName)] successfully" -Event Success
            }
        }
        
    }
    catch {
        HID-Write-Status -Message "Error assigning access rights [SendAs] for mailbox [$($mailboxAlias)] to [$($user.sAMAccountName)]. Error: $($_.Exception.Message)" -Event Error
        HID-Write-Summary -Message "Error assigning access rights [SendAs] for mailbox [$($mailboxAlias)] to [$($user.sAMAccountName)]" -Event Failed
        throw $_
    }

    # Remove Send As Permissions for Mail-enabled Security Group for users
    try { 
        # Remove Send As Permissions
        if ($usersToRemoveSendAs -ne "[]") {
            HID-Write-Status -Message "Starting to remove send as members to mailbox $($mailboxAlias)" -Event Information
            $usersToAddJson = $usersToRemoveSendAs | ConvertFrom-Json
            foreach ($user in $usersToAddJson) {
                
                Remove-ADPermission -Identity $mailboxDn -ExtendedRights "Send As" -Confirm:$false -User $user.sAMAccountName -ErrorAction Stop
                
                Hid-Write-Status -Message "Removing access rights [SendAs] for mailbox [$($mailboxAlias)] to [$($user.sAMAccountName)] successfully" -Event Success
                HID-Write-Summary -Message "Removing access rights [SendAs] for mailbox [$($mailboxAlias)] to [$($user.sAMAccountName)] successfully" -Event Success
            }
        }
        
    }
    catch {
        HID-Write-Status -Message "Error removing access rights [SendAs] for mailbox [$($mailboxAlias)] to [$($user.sAMAccountName)]. Error: $($_.Exception.Message)" -Event Error
        HID-Write-Summary -Message "Error removing access rights [SendAs] for mailbox [$($mailboxAlias)] to [$($user.sAMAccountName)]" -Event Failed
        throw $_
    }
}
catch {
    HID-Write-Status -Message "Error removing access rights for mailbox [$($mailboxAlias)] to the user [$($user.sAMAccountName)]. Error: $($_.Exception.Message)" -Event Error
    HID-Write-Summary -Message "Error removing access rights for mailbox [$($mailboxAlias)] to the user [$($user.sAMAccountName)]" -Event Failed
}
finally {
    # Disconnect from Exchange
    try {
        Remove-PsSession -Session $exchangeSession -Confirm:$false -ErrorAction Stop
        HID-Write-Status -Message "Successfully disconnected from Exchange" -Event Success
    }
    catch {
        HID-Write-Status -Message "Error disconnecting from Exchange" -Event Error
        HID-Write-Status -Message "Error at line: $($_.InvocationInfo.ScriptLineNumber - 79): $($_.Exception.Message)" -Event Error
        if ($debug -eq $true) {
            HID-Write-Status -Message "$($_.Exception)" -Event Error
        }
        HID-Write-Summary -Message "Failed to disconnect from Exchange" -Event Failed
        throw $_
    }
    <#----- Exchange On-Premises: End -----#>
}


