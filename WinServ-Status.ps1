<#PSScriptInfo

.VERSION 1.6

.GUID 2cb94e4f-1e85-4712-9441-91abcaea8572

.AUTHOR Mike Galvin twitter.com/digressive & Dan Price twitter.com/therezin, based on code by Bhavik Solanki.

.COMPANYNAME

.COPYRIGHT (C) Mike Galvin. All rights reserved.

.TAGS Windows Server Status Report Monitor

.LICENSEURI

.PROJECTURI https://gal.vin/2017/07/28/windows-server-status/

.ICONURI

.EXTERNALMODULEDEPENDENCIES

.REQUIREDSCRIPTS

.EXTERNALSCRIPTDEPENDENCIES

.RELEASENOTES

#>

<#
    .SYNOPSIS
    Creates a status report of Windows Servers.

    .DESCRIPTION
    Creates a status report of Windows Servers.

    This script will:
    
    Generate a status report from a list of Windows servers.
    The report will highlight information if the alert threshold is exceeded.

    Please note: to send a log file using ssl and an SMTP password you must generate an encrypted
    password file. The password file is unique to both the user and machine.
    
    The command is as follows:

    $creds = Get-Credential
    $creds.Password | ConvertFrom-SecureString | Set-Content c:\foo\ps-script-pwd.txt
    
    .PARAMETER List
    The path to a TXT file containing the netbios names of the servers you wish to check.

    .PARAMETER O
    The path where the report file will be output to.

    .PARAMETER DiskAlert
    The percentage of disk usage that should cause the disk space alert to be raised.

    .PARAMETER CpuAlert
    The percentage of CPU usage that should cause the CPU alert to be raised.

    .PARAMETER MemAlert
    The percentage of memory usage that should cause the memory alert to be raised.

    .PARAMETER Refresh
    The number of seconds that she script should wait before running again. The minimum is 300 seconds (5 minutes)
    and the maximum is 28800 (8 hours). If not configured the script will run once and then end.

    .PARAMETER Light
    Configure the HTML results file to have a light theme.

    .PARAMETER Csv
    Export a CSV file, instead of a HTML file.

    .PARAMETER SendTo
    The e-mail address the log should be sent to.

    .PARAMETER From
    The e-mail address the log should be sent from.

    .PARAMETER Smtp
    The DNS name or IP address of the SMTP server.

    .PARAMETER User
    The user account to connect to the SMTP server.

    .PARAMETER Pwd
    The txt file containing the encrypted password for the user account.

    .PARAMETER UseSsl
    Configures the script to connect to the SMTP server using SSL.

    .EXAMPLE
    WinServ-Status.ps1 -List C:\foo\servers.txt -O C:\foo -DiskAlert 90 -CpuAlert 95 -MemAlert 85 -Refresh 300 -Light
    Using the switches above the script will execute using the list of servers and output a HTML report to C:\foo.
    The disk usage alert will highlight at 90% usage for any one drive, the CPU usage alert will highlight at 95% usage,
    and the memory usage alert will highlight at 85% usage. The status of the servers will refresh every 5 minutes, and
    the web page will have a light theme instead of a dark theme.
#>

## Set up command line switches and what variables they map to.
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$True)]
    [Alias("List")]
    [ValidateScript({Test-Path -Path $_ -PathType Leaf})]
    [string]$ServerFile,
    [Parameter(Mandatory=$True)]
    [Alias("O")]
    [ValidateScript({Test-Path $_ -PathType 'Container'})]
    [string]$OutputPath,
    [Alias("DiskAlert")]
    [ValidateRange(0,100)]
    [int]$DiskAlertThreshold,
    [Alias("CpuAlert")]
    [ValidateRange(0,100)]
    [int]$CpuAlertThreshold,
    [Alias("MemAlert")]
    [ValidateRange(0,100)]
    [int]$MemAlertThreshold,
    [Alias("Refresh")]
    [ValidateRange(300,28800)]
    [int]$RefreshTime,
    [switch]$Light,
    [switch]$Csv,
    [Alias("SendTo")]
    [string]$MailTo,
    [Alias("From")]
    [string]$MailFrom,
    [Alias("Smtp")]
    [string]$SmtpServer,
    [Alias("User")]
    [string]$SmtpUser,
    [Alias("Pwd")]
    [string]$SmtpPwd,
    [switch]$UseSsl)

## Function to get the up time from a server.
Function Get-UpTime
{
    param([string] $LastBootTime)
    $Uptime = (Get-Date) - [System.Management.ManagementDateTimeconverter]::ToDateTime($LastBootTime)
    "$($Uptime.Days) days $($Uptime.Hours)h $($Uptime.Minutes)m"
}

## Begining of the loop. At the bottom of the script the loop is broken if the refresh option is not configured.
Do
{
    ## If CSV is configured, setting the location and name of the report output. If CSV is not configured output a HTML file.
    If ($Csv)
    {
        $OutputFile = "$OutputPath\WinServ-Status-Report.csv"
        
        ## If the CSV file already exists, clear it
        $CsvT = Test-Path -Path $OutputFile

        If ($CsvT)
        {
            Clear-Content -Path $OutputFile
        }
    }

    Else
    {
        $OutputFile = "$OutputPath\WinServ-Status-Report.htm"
    }

    $ServerList = Get-Content $ServerFile
    $Result = @()

    ## Using variables for HTML and CSS so we don't need to use escape characters below.
    $Green = "00e600"
    $Grey = "e6e6e6"
    $Red = "ff4d4d"
    $Black = "1a1a1a"
    $Yellow = "ffff4d"
    $CssError = "error"
    $CssFormat = "format"
    $CssSpinner = "spinner"
    $CssRect1 = "rect1"
    $CssRect2 = "rect2"
    $CssRect3 = "rect3"
    $CssRect4 = "rect4"
    $CssRect5 = "rect5"

    ## Sort Servers based on whther they are online or offline
    $ServerList = $ServerList | Sort-Object

    ForEach ($ServerName in $ServerList)
    {
        $PingStatus = Test-Connection -ComputerName $ServerName -Count 1 -Quiet

        If ($PingStatus -eq $False)
        {
            $ServersOffline += @($ServerName)
        }

        Else
        {
            $ServersOnline += @($ServerName)
        }
    }

    $ServerListFinal = $ServersOffline + $ServersOnline

    ## Look through the final servers list.
    ForEach ($ServerName in $ServerListFinal)
    {
        $PingStatus = Test-Connection -ComputerName $ServerName -Count 1 -Quiet

        ## If server responds, get the stats for the server.
        If ($PingStatus)
        {
            $CpuAlert = $false
            $MemAlert = $false
            $DiskAlert = $false
            $OperatingSystem = Get-WmiObject Win32_OperatingSystem -ComputerName $ServerName
            $CpuUsage = Get-WmiObject Win32_Processor -Computername $ServerName | Measure-Object -Property LoadPercentage -Average | ForEach-Object {$_.Average; If($_.Average -ge $CpuAlertThreshold){$CpuAlert = $True};}
            $Uptime = Get-Uptime($OperatingSystem.LastBootUpTime)
            $MemUsage = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $ServerName | ForEach-Object {“{0:N0}” -f ((($_.TotalVisibleMemorySize - $_.FreePhysicalMemory) * 100)/ $_.TotalVisibleMemorySize); If((($_.TotalVisibleMemorySize - $_.FreePhysicalMemory) * 100)/ $_.TotalVisibleMemorySize -ge $MemAlertThreshold){$MemAlert = $True};}
            $DiskUsage = Get-WmiObject Win32_LogicalDisk -ComputerName $ServerName | Where-Object {$_.DriveType -eq 3} | Foreach-Object {$_.DeviceID, [Math]::Round((($_.Size - $_.FreeSpace) * 100)/ $_.Size); If([Math]::Round((($_.Size - $_.FreeSpace) * 100)/ $_.Size) -ge $DiskAlertThreshold){$DiskAlert = $True};}
	    }
	
        ## Put the results together in an array.
        $Result += New-Object PSObject -Property @{
	        ServerName = $ServerName
		    Status = $PingStatus
            CpuUsage = $CpuUsage
            CpuAlert = $CpuAlert
		    Uptime = $Uptime
            MemUsage = $MemUsage
            MemAlert = $MemAlert
            DiskUsage = $DiskUsage
            DiskAlert = $DiskAlert
	    }

        ## Clear the variables after obtaining and storing the results, otherwise data is duplicated.
        If ($ServerListFinal)
        {
            Clear-Variable ServerListFinal
        }

        If ($ServersOffline)
        {
            Clear-Variable ServersOffline
        }

        If ($ServersOnline)
        {
            Clear-Variable ServersOnline
        }

        If ($PingStatus)
        {
            Clear-Variable PingStatus
        }

        If ($CpuUsage)
        {
            Clear-Variable CpuUsage
        }

        If ($Uptime)
        {
            Clear-Variable Uptime
        }

        If ($MemUsage)
        {
            Clear-Variable MemUsage
        }

        If ($DiskUsage)
        {
            Clear-Variable DiskUsage
        }
    }

    ## If there is a result put the report together.
    If ($Result -ne $null)
    {
        ## If CSV report is specified, output a CSV file. If CSV is not configured output a HTML file.
        If ($Csv)
        {
            ForEach($Entry in $Result)
            {
                If ($Entry.Status -eq $True)
                {
                    Add-Content -Path "$OutputFile" -Value "$($Entry.ServerName),Online,CPU: $($Entry.CpuUsage),Mem: $($Entry.MemUsage),$($Entry.DiskUsage),$($Entry.Uptime)"
                }

                Else
                {
                    Add-Content -Path "$OutputFile" -Value "$($Entry.ServerName),Offline"
                }
            }
        }

        Else
        {
            ## If the light theme is specified, use a lighter css theme. If not, use the dark css theme.
            If ($Light)
            {
                $HTML = '<style type="text/css">
                    p {font-family:Gotham, "Helvetica Neue", Helvetica, Arial, sans-serif;font-size:14px}
                    p {color:#000000;}
                    #Header{font-family:Gotham, "Helvetica Neue", Helvetica, Arial, sans-serif;width:100%;border-collapse:collapse;}
                    #Header td, #Header th {font-size:14px;text-align:left;}
                    #Header tr.alt td {color:#ffffff;background-color:#404040;}
                    #Header tr:nth-child(even) {background-color:#404040;}
                    #Header tr:nth-child(odd) {background-color:#737373;}
                    body {background-color: #d9d9d9;}
                    .spinner {width: 40px;height: 20px;font-size: 14px;padding: 5px;}
                    .spinner > div {background-color: #00e600;height: 100%;width: 3px;display: inline-block;animation: sk-stretchdelay 3.2s infinite ease-in-out;}
                    .spinner .rect2 {animation-delay: -3.1s;}
                    .spinner .rect3 {animation-delay: -3.0s;}
                    .spinner .rect4 {animation-delay: -2.9s;}
                    .spinner .rect5 {animation-delay: -2.8s;}
                    @keyframes sk-stretchdelay {0%, 40%, 100% {transform: scaleY(0.4);} 20% {transform: scaleY(1.0);}}
                    .format {position: relative;overflow: hidden;padding: 5px;}
                    .error {-webkit-animation-name: alert;animation-duration: 4s;animation-iteration-count: infinite;animation-direction: alternate;padding: 5px;}
                    @keyframes alert {from {background-color:rgba(117,0,0,0);} to {background-color:rgba(117,0,0,1);}}
                    </style>
                    <head><meta http-equiv="refresh" content="300"></head>'

                $HTML += "<html><body>
                    <p><font color=#$Black>Last update: $(Get-Date -Format G)</font></p>
                    <table border=0 cellpadding=0 cellspacing=0 id=header>"
            }

            ## If the light theme is not specified, use a darker css theme.
            Else
            {
                $HTML = '<style type="text/css">
                    p {font-family:Gotham, "Helvetica Neue", Helvetica, Arial, sans-serif;font-size:14px}
                    p {color:#ffffff;}
                    #Header{font-family:Gotham, "Helvetica Neue", Helvetica, Arial, sans-serif;width:100%;border-collapse:collapse;}
                    #Header td, #Header th {font-size:14px;text-align:left;}
                    #Header tr:nth-child(even) {background-color:#0F0F0F;}
                    #Header tr:nth-child(odd) {background-color:#1B1B1B;}
                    body {background-color: #0F0F0F;}
                    .spinner {width: 40px;height: 20px;font-size: 14px;padding: 5px;}
                    .spinner > div {background-color: #00e600;height: 100%;width: 3px;display: inline-block;animation: sk-stretchdelay 3.2s infinite ease-in-out;}
                    .spinner .rect2 {animation-delay: -3.1s;}
                    .spinner .rect3 {animation-delay: -3.0s;}
                    .spinner .rect4 {animation-delay: -2.9s;}
                    .spinner .rect5 {animation-delay: -2.8s;}
                    @keyframes sk-stretchdelay {0%, 40%, 100% {transform: scaleY(0.4);} 20% {transform: scaleY(1.0);}}
                    .format {position: relative;overflow: hidden;padding: 5px;}
                    .error {animation-name: alert;animation-duration: 4s;animation-iteration-count: infinite;animation-direction: alternate;padding: 5px;}
                    @keyframes alert {from {background-color:rgba(117,0,0,0);} to {background-color:rgba(117,0,0,1);}}
                    </style>
                    <head><meta http-equiv="refresh" content="300"></head>'

                $HTML += "<html><body>
                    <p><font color=#$Grey>Last update: $(Get-Date -Format G)</font></p>
                    <table border=0 cellpadding=0 cellspacing=0 id=header>"
            }

            ## Highlight the alerts if the alerts are triggered.
            ForEach($Entry in $Result)
            {
                If ($RefreshTime -ne 0)
                {

                    If ($Entry.Status -eq $True)
                    {
                        $HTML += "<td><div class=$CssSpinner><div class=$CssRect1></div> <div class=$CssRect2></div> <div class=$CssRect3></div> <div class=$CssRect4></div> <div class=$CssRect5></div></div></td>"
                    }
                

                    Else
                    {
                        $HTML += "<td><div class=$CssError><font color=#$Red>OFFL</font></div></td>"
                    }
                }

                If ($Entry.Status -eq $True)
                {
                    $HTML += "<td><div class=$CssFormat><font color=#$Green>$($Entry.ServerName)</font></div></td>"
                }

                Else
                {
                    $HTML += "<td><div class=$CssError><font color=#$Red>$($Entry.ServerName)</font></div></td>"
                }

                If ($Entry.CpuUsage -ne $null)
                {
                    If ($Entry.CpuAlert -eq $True)
                    {
                        $HTML += "<td><div class=$CssFormat><font color=#$Yellow>CPU: $($Entry.CpuUsage)%</font></div></td>"
                    }

                    Else
                    {
                        $HTML += "<td><div class=$CssFormat><font color=#$Green>CPU: $($Entry.CpuUsage)%</font></div></td>"
                    }
                }
            
                Else
                {
                    $HTML += "<td><div class=$CssError><font color=#$Red>OFFL</font></div></td>"
                }

                If ($Entry.MemUsage -ne $null)
                {
                    If ($Entry.MemAlert -eq $True)
                    {
                        $HTML += "<td><div class=$CssFormat><font color=#$Yellow>Mem: $($Entry.MemUsage)%</font></div></td>"
                    }

                    Else
                    {
                        $HTML += "<td><div class=$CssFormat><font color=#$Green>Mem: $($Entry.MemUsage)%</font></div></td>"
                    }
                }

                Else
                {
                    $HTML += "<td><div class=$CssError><font color=#$Red>OFFL</font></div></td>"
                }

                If ($Entry.DiskUsage -ne $null)
                {
                    If ($Entry.DiskAlert -eq $True)
                    {
                        $HTML += "<td><div class=$CssFormat><font color=#$Yellow>$($Entry.DiskUsage)%</font></div></td>"
                    }

                    Else
                    {
                        $HTML += "<td><div class=$CssFormat><font color=#$Green>$($Entry.DiskUsage)%</font></div></td>"
                    }
                }

                Else
                {
                    $HTML += "<td><div class=$CssError><font color=#$Red>OFFL</font></div></td>"
                }

                If ($Entry.Status -eq $True)
                {
                    $HTML += "<td><div class=$CssFormat><font color=#$Green>$($Entry.Uptime)</font></div></td>
                            </tr>"
                }

                Else
                {
                    $HTML += "<td><div class=$CssError><font color=#$Red>OFFL</font></div></td>
                            </tr>"
                }
            }

            ## Finish the HTML file.
            $HTML += "</table></body></html>"

            ## Output the HTML file
            $HTML | Out-File $OutputFile
        }

        ## If email was configured, set the variables for the email subject and body.
        If ($SmtpServer)
        {
            $MailSubject = "Server Status Report"
            $MailBody = Get-Content -Path $OutputFile | Out-String

            ## If an email password was configured, create a variable with the username and password.
            If ($SmtpPwd)
            {
                $SmtpPwdEncrypt = Get-Content $SmtpPwd | ConvertTo-SecureString
                $SmtpCreds = New-Object System.Management.Automation.PSCredential -ArgumentList ($SmtpUser, $SmtpPwdEncrypt)

                ## If ssl was configured, send the email with ssl.
                If ($UseSsl)
                {
                    Send-MailMessage -To $MailTo -From $MailFrom -Subject $MailSubject -Body $MailBody -BodyAsHtml -SmtpServer $SmtpServer -UseSsl -Credential $SmtpCreds
                }

                ## If ssl wasn't configured, send the email without ssl.
                Else
                {
                    Send-MailMessage -To $MailTo -From $MailFrom -Subject $MailSubject -Body $MailBody -BodyAsHtml -SmtpServer $SmtpServer -Credential $SmtpCreds
                }
            }

            ## If an email username and password were not configured, send the email without authentication.
            Else
            {
                Send-MailMessage -To $MailTo -From $MailFrom -Subject $MailSubject -Body $MailBody -BodyAsHtml -SmtpServer $SmtpServer
            }
        }

        ## If the refresh time option is configured, wait the specifed number of seconds then loop.
        If ($RefreshTime -ne 0)
        {
            Start-Sleep -Seconds $RefreshTime
        }
    }
}

## If the refresh time option is not configured, stop the loop.
Until ($RefreshTime -eq 0)

## End