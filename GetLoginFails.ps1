#Requires -Version 3.0 -RunAsAdministrator
param (
    [Parameter(Mandatory = $false)]
    [String]
    $ComputerName = [System.Net.Dns]::GetHostName(),
    [Parameter(Mandatory = $false)]
    [String]
    $UserName,
    [Switch]
    $Detailed
)
function Get-FailureReason {
    Param($FailureReason)
    switch ($FailureReason) {
        '0xC0000064' { "Account does not exist"; break; }
        '0xC000006A' { "Incorrect password"; break; }
        '0xC000006D' { "Incorrect username or password"; break; }
        '0xC000006E' { "Account restriction"; break; }
        '0xC000006F' { "Invalid logon hours"; break; }
        '0xC000015B' { "Logon type not granted"; break; }
        '0xc0000070' { "Invalid Workstation"; break; }
        '0xC0000071' { "Password expired"; break; }
        '0xC0000072' { "Account disabled"; break; }
        '0xC0000133' { "Time difference at DC"; break; }
        '0xC0000193' { "Account expired"; break; }
        '0xC0000224' { "Password must change"; break; }
        '0xC0000234' { "Account locked out"; break; }
        '0x0' { "0x0"; break; }
        default { "Other"; break; }
    }
}
function Get-LogonType {
    Param($LogonType)
    switch ($LogonType) {
        '0' { 'Interactive'; break; }
        '2' { 'Interactive'; break; }
        '3' { 'Network'; break; }
        '4' { 'Batch'; break; }
        '5' { 'Service'; break; }
        '6' { 'Proxy'; break; }
        '7' { 'Unlock'; break; }
        '8' { 'Networkcleartext'; break; }
        '9' { 'NewCredentials'; break; }
        '10' { 'RemoteInteractive'; break; }
        '11' { 'CachedInteractive'; break; }
        '12' { 'CachedRemoteInteractive'; break; }
        '13' { 'CachedUnlock'; break; }
        Default {}
    }
}
#-Newest $Records
$Events = Get-EventLog -ComputerName $ComputerName -LogName 'security' -InstanceId 4625, 4624 | Sort-Object -Property TimeGenerated | ForEach-Object {
    if ($_.InstanceId -eq 4625) {
        $_ | Select-Object -Property @(
            @{Label = 'TimeGenerated'; Expression = { $_.TimeGenerated } },
            @{Label = 'EventID'; Expression = { $_.InstanceId } },
            @{Label = 'Category'; Expression = { $_.CategoryNumber } },
            @{Label = 'Username'; Expression = { $_.ReplacementStrings[5] } },
            @{Label = 'Domain'; Expression = { $_.ReplacementStrings[6] } },
            @{Label = 'UserSID'; Expression = { (($_.Message -Split 'rn' | Select-String 'Security ID')[1] -Split 's+')[3] } },
            # @{Label = 'UserSID'; Expression = { $_.ReplacementStrings[0] } },
            @{Label = 'Workstation'; Expression = { $_.ReplacementStrings[13] } },
            @{Label = 'SourceIP'; Expression = { $_.ReplacementStrings[19] } },
            @{Label = 'Port'; Expression = { $_.ReplacementStrings[20] } },
            @{Label = 'LogonType'; Expression = { $_.ReplacementStrings[8] } },
            @{Label = 'FailureStatus'; Expression = { Get-FailureReason($_.ReplacementStrings[7]) } },
            @{Label = 'FailureSubStatus'; Expression = { Get-FailureReason($_.ReplacementStrings[9]) } }
        )
    }
    elseif ($_.InstanceId -eq 4624 -and (Get-LogonType($_.ReplacementStrings[8])) -notlike 'Service') {
        $_ | Select-Object -Property @(
            @{Label = 'TimeGenerated'; Expression = { $_.TimeGenerated } },
            @{Label = 'EventID'; Expression = { $_.InstanceId } },
            @{Label = 'Category'; Expression = { $_.CategoryNumber } },
            @{Label = 'Username'; Expression = { $_.ReplacementStrings[5] } },
            @{Label = 'Domain'; Expression = { $_.ReplacementStrings[6] } },
            @{Label = 'UserSID'; Expression = { $_.ReplacementStrings[0] } },
            @{Label = 'Workstation'; Expression = { $_.ReplacementStrings[11] } },
            @{Label = 'SourceIP'; Expression = { $_.ReplacementStrings[18] } },
            @{Label = 'Port'; Expression = { $_.ReplacementStrings[19] } },
            @{Label = 'LogonType'; Expression = { Get-LogonType($_.ReplacementStrings[8]) } },
            @{Label = 'LogonID'; Expression = { Get-FailureReason($_.ReplacementStrings[7]) } },
            @{Label = 'LogonProcess'; Expression = { Get-FailureReason($_.ReplacementStrings[9]) } }
        )
    }
}
if ($Detailed) {
    if ($UserName) {
        $Events | Where-Object {
            $_.Username -like $UserName
        }
    }
    else {
        $Events | Where-Object {
            $_.Username -notlike "DWM*" -and
            $_.Username -notlike "UMFD*" -and
            $_.Username -notlike "SYSTEM"
        }
    }
}
else {
    $UserNames = if ($UserName) {
        ($Events | Select-Object -Property Username -Unique).Username | Where-Object {
            $_ -like "$UserName"
        }
    }
    else {
        ($Events | Select-Object -Property Username -Unique).Username | Where-Object {
            $_ -notlike "DWM*" -and
            $_ -notlike "UMFD*" -and
            $_ -notlike "SYSTEM"
        }
    }
    $UserNames | ForEach-Object {
        $CurrentUserName = $_
        $FailedLoginCount = 0
        for ($i = 0; $i -lt $Events.Count; $i++) {
            if ($Events[$i].EventID -eq 4625 -and $Events[$i].Username -like $CurrentUserName) {
                # User failed to login X times
                # Count the number of failed logins
                $FailedLoginCount++
            }
            elseif ($Events[$i].EventID -eq 4624 -and $Events[$i].Username -like $CurrentUserName) {

                $FailedLoginCount = 0
            }
        }
        if ($UserName) {
            $FailedLoginCount
        }
        else {
            [PSCustomObject]@{
                UserName            = $CurrentUserName
                FailedLoginAttempts = $FailedLoginCount
            }
        }
    }
}