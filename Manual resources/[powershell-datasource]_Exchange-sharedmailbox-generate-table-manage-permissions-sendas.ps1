<#----- Exchange On-Premises: Start -----#>
# Connect to Exchange
try{
    $adminSecurePassword = ConvertTo-SecureString -String "$ExchangeAdminPassword" -AsPlainText -Force
    $adminCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ExchangeAdminUsername,$adminSecurePassword
    $sessionOption = New-PSSessionOption -SkipCACheck -SkipCNCheck #-SkipRevocationCheck
    $exchangeSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $exchangeConnectionUri -Credential $adminCredential -SessionOption $sessionOption -ErrorAction Stop 
    #-AllowRedirection
    $null = Import-PSSession $exchangeSession -DisableNameChecking -AllowClobber
    Write-Information -Message "Successfully connected to Exchange using the URI [$exchangeConnectionUri]"
} catch {
    Write-Information -Message "Error connecting to Exchange using the URI [$exchangeConnectionUri]"
    Write-Error -Message "Error at line: $($_.InvocationInfo.ScriptLineNumber - 79): $($_.Exception.Message)"
    if($debug -eq $true){
        Write-Error -Message "$($_.Exception)"
    }
    Write-Information -Message "Failed to connect to Exchange using the URI [$exchangeConnectionUri]"
    throw $_
}

# Read current mailbox
try{
    
    $permissions = Get-ADPermission -Identity $datasource.selectedMailbox.DistinguishedName | ?{($_.ExtendedRights -like "*send*") -and -not ($_.User -like "*NT AUTHORITY*")} | select  @{Name="Displayname"; Expression={(Get-Recipient $_.user.ToString()).Displayname.ToString()}}, @{Name="Samaccountname"; Expression={(Get-Recipient $_.user.ToString()).sAMAccountName.ToString()}}
    Write-Information -Message "Found mailbox [$($datasource.selectedMailbox.displayName)]"
    
    $permissions = $permissions | Sort-Object -Property Displayname
    foreach($permission in $permissions)
    {
        $displayValue = $permission.Displayname + " [" + $permission.Samaccountname + "]"
        $returnObject = @{sAMAccountName=$permission.Samaccountname;name=$displayValue;}
        Write-Output $returnObject
    }    
    
} catch {
    Write-Information -Message "Could not find mailbox [$($datasource.mailbox.UserPrincipalName)]"
    Write-Error -Message "Error at line: $($_.InvocationInfo.ScriptLineNumber - 79): $($_.Exception.Message)"
    if($debug -eq $true){
        Write-Information -Message "$($_.Exception)"
    }
    Write-Information -Message "Failed to find mailbox [$($adUser.userPrincipalName)]"
    throw $_
}

# Disconnect from Exchange
try{
    Remove-PsSession -Session $exchangeSession -Confirm:$false -ErrorAction Stop
    Write-Information -Message "Successfully disconnected from Exchange"
} catch {
    Write-Error -Message "Error disconnecting from Exchange"
    Write-Error -Message "Error at line: $($_.InvocationInfo.ScriptLineNumber - 79): $($_.Exception.Message)"
    if($debug -eq $true){
        Write-Error -Message "$($_.Exception)"
    }    
    Write-Error -Message "Failed to disconnect from Exchange"
    throw $_
}
<#----- Exchange On-Premises: End -----#>
