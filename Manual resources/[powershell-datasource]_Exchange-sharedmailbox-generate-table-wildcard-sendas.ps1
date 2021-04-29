<#----- Exchange On-Premises: Start -----#>
# Connect to Exchange
try{
    $adminSecurePassword = ConvertTo-SecureString -String "$ExchangeAdminPassword" -AsPlainText -Force
    $adminCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ExchangeAdminUsername,$adminSecurePassword
    $sessionOption = New-PSSessionOption -SkipCACheck -SkipCNCheck #-SkipRevocationCheck
    $exchangeSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $exchangeConnectionUri -Credential $adminCredential -SessionOption $sessionOption -Authentication Default -ErrorAction Stop 
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

try {
    $searchValue = $dataSource.searchMailbox
    $searchQuery = "*$searchValue*"
    $searchOUs = $ADsharedMailboxSearchOU
     
    
    if([String]::IsNullOrEmpty($searchValue) -eq $true){
        Write-Information "Geen Searchvalue"
        return
    }else{
        Write-Information "SearchQuery: $searchQuery"
        
        $mailboxes = Get-Mailbox -RecipientTypeDetails SharedMailbox -ResultSize:Unlimited -Filter "{Alias -like '$searchQuery' -or name -like '$searchQuery'}"

        $mailboxes = $mailboxes | Sort-Object -Property DisplayName
        $resultCount = @($mailboxes).Count
        Write-Information "Result count: $resultCount"
        if($resultCount -gt 0){
            foreach($mailbox in $mailboxes){
                $returnObject = @{displayName=$mailbox.DisplayName; UserPrincipalName=$mailbox.UserPrincipalName; Alias=$mailbox.Alias; DistinguishedName=$mailbox.DistinguishedName}
                Write-Output $returnObject
            }
        }
    }
} catch {
    $msg = "Error searching AD user [$searchValue]. Error: $($_.Exception.Message)"
    Write-Error $msg
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
