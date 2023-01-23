$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# variables configured in form
$mailboxAlias = $form.gridMailbox.Alias
$mailboxDn = $form.gridMailbox.DistinguishedName
$usersToAddSendAs = $form.sendasList.leftToRight
$usersToRemoveSendAs = $form.sendasList.rightToLeft

try {
    <#----- Exchange On-Premises: Start -----#>
    # Connect to Exchange
    try {
        $adminSecurePassword = ConvertTo-SecureString -String "$ExchangeAdminPassword" -AsPlainText -Force
        $adminCredential = [System.Management.Automation.PSCredential]::new($ExchangeAdminUsername,$adminSecurePassword)
        $sessionOption = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
        $exchangeSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $exchangeConnectionUri -Credential $adminCredential -SessionOption $sessionOption -ErrorAction Stop 
        #-AllowRedirection
        $session = Import-PSSession $exchangeSession -DisableNameChecking -AllowClobber
    
        Write-Information "Successfully connected to Exchange using the URI [$exchangeConnectionUri]" 
    
        $Log = @{
            Action            = "UpdateResource" # optional. ENUM (undefined = default) 
            System            = "Exchange On-Premise" # optional (free format text) 
            Message           = "Successfully connected to Exchange using the URI [$exchangeConnectionUri]" # required (free format text) 
            IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
            TargetDisplayName = $exchangeConnectionUri # optional (free format text) 
            TargetIdentifier  = $([string]$session.GUID) # optional (free format text) 
        }
        #send result back  
        Write-Information -Tags "Audit" -MessageData $log
    }
    catch {
        Write-Error "Error connecting to Exchange using the URI [$exchangeConnectionUri]. Error: $($_.Exception.Message)"
        $Log = @{
            Action            = "UpdateResource" # optional. ENUM (undefined = default) 
            System            = "Exchange On-Premise" # optional (free format text) 
            Message           = "Failed to connect to Exchange using the URI [$exchangeConnectionUri]." # required (free format text) 
            IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
            TargetDisplayName = $exchangeConnectionUri # optional (free format text) 
            TargetIdentifier  = $([string]$session.GUID) # optional (free format text) 
        }
        #send result back  
        Write-Information -Tags "Audit" -MessageData $log
    }

    #Write-Information "Checking if mailbox with identity '$($mailboxAlias)' exists"
    $mailbox = Get-Mailbox -Identity $mailboxAlias -ErrorAction Stop | Select-Object Guid
    if ($mailbox.Guid.Count -eq 0) {
        Write-Error "Could not find shared mailbox with identity '$($mailboxAlias)'"
    }
        
    # Add Send As Permissions for Mail-enabled Security Group for users
    try { 
        # Add Send As Permissions
        if ($usersToAddSendAs.count -gt 0) {
            Write-Information "Starting to add send as members to mailbox $($mailboxAlias)"
            
            foreach ($user in $usersToAddSendAs) {
                try {                    
                    Add-ADPermission -Identity $mailboxDn -AccessRights ExtendedRight -ExtendedRights "Send As" -Confirm:$false -User $user.sAMAccountName -ErrorAction Stop
                    Write-Information "Assigned access rights [SendAs] on mailbox [$($mailboxAlias)] for [$($user.sAMAccountName)] successfully."
                    $Log = @{
                        Action            = "UpdateResource" # optional. ENUM (undefined = default) 
                        System            = "Exchange On-Premise" # optional (free format text) 
                        Message           = "Assigned access rights [SendAs] on mailbox [$($mailboxAlias)] for [$($user.sAMAccountName)] successfully." # required (free format text) 
                        IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                        TargetDisplayName = $mailboxAlias # optional (free format text) 
                        TargetIdentifier  = $([string]$mailbox.Guid) # optional (free format text) 
                    }
                    #send result back  
                    Write-Information -Tags "Audit" -MessageData $log 
                }
                catch {
                    Write-Error "Error assigning access rights [SendAs] for $($user.sAMAccountName) on mailbox [$($mailboxAlias)]. Error: $($_.Exception.Message)" 
                    $Log = @{
                        Action            = "UpdateResource" # optional. ENUM (undefined = default) 
                        System            = "Exchange On-Premise" # optional (free format text) 
                        Message           = "Error assigning access rights to $($user.sAMAccountName) on mailbox [$($mailboxAlias)]" # required (free format text) 
                        IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                        TargetDisplayName = $mailboxAlias # optional (free format text) 
                        TargetIdentifier  = $([string]$mailbox.Guid) # optional (free format text) 
                    }
                    #send result back  
                    Write-Information -Tags "Audit" -MessageData $log
                }
            }
        }        
    }
    catch {
        Write-Error "Error assigning access rights [SendAs] for $($usersToAddSendAs.sAMAccountName) on mailbox [$($mailboxAlias)]. Error: $($_.Exception.Message)" 
        $Log = @{
            Action            = "UpdateResource" # optional. ENUM (undefined = default) 
            System            = "Exchange On-Premise" # optional (free format text) 
            Message           = "Error assigning access rights [SendAs] to $($usersToAddSendAs.sAMAccountName) on mailbox [$($mailboxAlias)]" # required (free format text) 
            IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
            TargetDisplayName = $mailboxAlias # optional (free format text) 
            TargetIdentifier  = $([string]$mailbox.Guid) # optional (free format text) 
        }
        #send result back  
        Write-Information -Tags "Audit" -MessageData $log
    }

    # Remove Send As Permissions for Mail-enabled Security Group for users
    try { 
        # Remove Send As Permissions
        if ($usersToRemoveSendAs.Count -gt 0) {
            Write-Information "Starting to remove send as members to mailbox $($mailboxAlias)"
            
            foreach ($user in $usersToRemoveSendAs) {
                try {
                    Remove-ADPermission -Identity $mailboxDn -ExtendedRights "Send As" -Confirm:$false -User $user.sAMAccountName -ErrorAction Stop
                
                    Write-Information "Removing access rights [SendAs] on mailbox [$($mailboxAlias)] for [$($user.sAMAccountName)] successfully"
                    $Log = @{
                        Action            = "UpdateResource" # optional. ENUM (undefined = default) 
                        System            = "Exchange On-Premise" # optional (free format text) 
                        Message           = "Removing access rights [SendAs] on mailbox [$($mailboxAlias)] for [$($user.sAMAccountName)] successfully." # required (free format text) 
                        IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                        TargetDisplayName = $mailboxAlias # optional (free format text) 
                        TargetIdentifier  = $([string]$mailbox.Guid) # optional (free format text) 
                    }
                    #send result back  
                    Write-Information -Tags "Audit" -MessageData $log
                }
                catch {
                    Write-Error "Error removing access rights [SendAs] on mailbox [$($mailboxAlias)] for [$($user.sAMAccountName)]. Error: $($_.Exception.Message)"
                    $Log = @{
                        Action            = "UpdateResource" # optional. ENUM (undefined = default) 
                        System            = "Exchange On-Premise" # optional (free format text) 
                        Message           = "Error removing access rights [SendAs] on mailbox [$($mailboxAlias)] for [$($user.sAMAccountName)]." # required (free format text) 
                        IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                        TargetDisplayName = $mailboxAlias # optional (free format text) 
                        TargetIdentifier  = $([string]$mailbox.Guid) # optional (free format text) 
                    }
                    #send result back  
                    Write-Information -Tags "Audit" -MessageData $log
                }
            }
        }
        
    }
    catch {
        Write-Error "Error removing access rights [SendAs] on mailbox [$($mailboxAlias)] for [$($usersToRemoveSendAs.sAMAccountName)]."
        $Log = @{
            Action            = "UpdateResource" # optional. ENUM (undefined = default) 
            System            = "Exchange On-Premise" # optional (free format text) 
            Message           = "Error removing access rights [SendAs] on mailbox [$($mailboxAlias)] for [$($ususersToRemoveSendAser.sAMAccountName)]." # required (free format text) 
            IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
            TargetDisplayName = $mailboxAlias # optional (free format text) 
            TargetIdentifier  = $([string]$mailbox.Guid) # optional (free format text) 
        }
        #send result back  
        Write-Information -Tags "Audit" -MessageData $log
    }
}
catch {
    Write-Error "Error setting access rights [SendAs] on mailbox [$($mailboxAlias)]. Error: $($_.Exception.Message)"
    $Log = @{
        Action            = "UpdateResource" # optional. ENUM (undefined = default) 
        System            = "Exchange On-Premise" # optional (free format text) 
        Message           = "Error setting access rights [SendAs] on mailbox [$($mailboxAlias)]." # required (free format text) 
        IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
        TargetDisplayName = $exchangeConnectionUri # optional (free format text) 
        TargetIdentifier  = $([string]$session.GUID) # optional (free format text) 
    }
    #send result back  
    Write-Information -Tags "Audit" -MessageData $log    
}
finally {
    # Disconnect from Exchange
    try {
        Remove-PsSession -Session $exchangeSession -Confirm:$false -ErrorAction Stop
        Write-Information "Successfully disconnected from Exchange using the URI [$exchangeConnectionUri]"     
        $Log = @{
            Action            = "UpdateResource" # optional. ENUM (undefined = default) 
            System            = "Exchange On-Premise" # optional (free format text) 
            Message           = "Successfully disconnected from Exchange using the URI [$exchangeConnectionUri]" # required (free format text) 
            IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
            TargetDisplayName = $exchangeConnectionUri # optional (free format text) 
            TargetIdentifier  = $([string]$session.GUID) # optional (free format text) 
        }
        #send result back  
        Write-Information -Tags "Audit" -MessageData $log
    }
    catch {
        Write-Error "Error disconnecting from Exchange.  Error: $($_.Exception.Message)"
        $Log = @{
            Action            = "UpdateResource" # optional. ENUM (undefined = default) 
            System            = "Exchange On-Premise" # optional (free format text) 
            Message           = "Failed to disconnect from Exchange using the URI [$exchangeConnectionUri]." # required (free format text) 
            IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
            TargetDisplayName = $exchangeConnectionUri # optional (free format text) 
            TargetIdentifier  = $([string]$session.GUID) # optional (free format text) 
        }
        #send result back  
        Write-Information -Tags "Audit" -MessageData $log 
    }
    <#----- Exchange On-Premises: End -----#>
}


