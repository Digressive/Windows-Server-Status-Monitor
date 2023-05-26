# Windows Server Status Monitor (WSSM)

## PowerShell based Windows Server monitor

For full instructions and documentation, [visit my blog post](https://gal.vin/posts/windows-server-status/)

Please consider donating to support my work:

* You can support me on a monthly basis [using Patreon.](https://www.patreon.com/mikegalvin)
* You can support me with a one-time payment [using PayPal](https://www.paypal.me/digressive) or by [using Kofi.](https://ko-fi.com/mikegalvin)

Windows Server Status Monitor can also be downloaded from:

* [The PowerShell Gallery](https://www.powershellgallery.com/packages/WinServ-Status)

Please report any problems via the ‘issues’ tab on GitHub.

-Mike

## Features and Requirements

* The utility will display the server name, uptime, CPU, memory and storage information, online status.
* The utility can be configured with a customisable alerts for the CPU, memory and storage.
* The utility can display the results as either a CSV file or a HTML file.
* The utility can be configured to monitor continuously, or run once.
* The utility can be configured to e-mail the results.
* This utility has been tested running on Windows 10 and Windows Server 2016, monitoring PCs and Servers running Windows 10, Windows Server 2016, Windows Server 2012 R2, and Windows Server 2008 R2.
* The utility must be run as a user with administrator-level privileges to the systems it is monitoring.

## Generating A Password File For SMTP Authentication

The password used for SMTP server authentication must be in an encrypted text file. To generate the password file, run the following command in PowerShell, on the computer that is going to run the script and logged in with the user that will be running the script. When you run the command you will be prompted for a username and password. Enter the username and password you want to use to authenticate to your SMTP server.

Please note: This is only required if you need to authenticate to the SMTP server when send the log via e-mail.

``` powershell
$creds = Get-Credential
$creds.Password | ConvertFrom-SecureString | Set-Content c:\scripts\ps-script-pwd.txt
```

After running the commands, you will have a text file containing the encrypted password. When configuring the -Pwd switch enter the path and file name of this file.

## Configuration

Here’s a list of all the command line switches and example configurations.

| Command Line Switch | Description | Example |
| ------------------- | ----------- | ------- |
| -List | The path to a TXT file containing the NetBIOS names of the servers you wish to check. | [path\]servers.txt |
| -O | The path where the report file will be output to. | [path\] |
| -DiskAlert | The percentage of disk usage that should cause the disk space alert to be raised. | [number] |
| -CpuAlert | The percentage of CPU usage that should cause the CPU alert to be raised. | [number] |
| -MemAlert | The percentage of memory usage that should cause the memory alert to be raised. | [number] |
| -Refresh | The number of seconds that she script should wait before running again. The minimum is 300 seconds (5 minutes) and the maximum is 28800 (8 hours). If not configured the script will run once and then exit. | [number] |
| -Light | Configure the HTML results file to have a light theme. | N/A |
| -csv | Export a CSV file, instead of a HTML file. | [path\]|
| -Subject | Specify a subject line. If you leave this blank the default subject will be used | "'[Server: Notification]'" |
| -SendTo | The e-mail address the log should be sent to. For multiple address, separate with a comma. | [example@contoso.com] |
| -From | The e-mail address the log should be sent from. | [example@contoso.com] |
| -Smtp | The DNS name or IP address of the SMTP server. | [smtp server address] |
| -User | The user account to authenticate to the SMTP server. | [example@contoso.com] |
| -Pwd | The txt file containing the encrypted password for SMTP authentication. | [path\]ps-script-pwd.txt |
| -UseSsl | Configures the utility to connect to the SMTP server using SSL. | N/A |

## Example

``` txt
WinServ-Status.ps1 -List C:\foo\servers.txt -O C:\foo -DiskAlert 90 -CpuAlert 95 -MemAlert 85 -Refresh 300 -Light
```

Using the switches above the script will execute using the list of servers and output a HTML report to C:\foo. The disk usage alert will highlight at 90% usage for any one drive, the CPU usage alert will highlight at 95% usage, and the memory usage alert will highlight at 85% usage. The status of the servers will refresh every 5 minutes, and the HTML file will have a light theme instead of a dark theme.

## Change Log

### 2019-09-04 v1.7

* Added custom subject line for e-mail.

### 2019-02-23 v1.6

* Updated the style of the web page with a cleaner look.
* Added 'online' CSS animation when the web page is in monitor mode - this is configured by using the refresh switch. It will not display when in report mode (no refresh switch).

### 2018-06-10 v1.5

* Added light theme for the web page.
* Added ability to export a CSV file instead of a web page.
* Improved the Offline visual effect on the web page.

### 2018-05-24 v1.4

* Servers are now sorted alphabetically, regardless of how they are entered in the text file.
* Offline servers are automatically shuffled to the top of the report.
* Added validation for the command line parameters.
* Removed IP addresses, and table headers to make room for more information.
* Due to removing table headers, added component name to CPU and RAM usage columns.
* Added new effect using CSS animation for offline servers.
* Added different shade of black for alternate table rows.

### 2017-10-16 v1.3

* Changed SMTP authentication to require an encrypted password file.
* Added instructions on how to generate an encrypted password file.

### 2017-10-09 v1.2

* Added necessary information to add the script to the PowerShell Gallery.

### 2018-09-27 v1.1

* Added capability for the script to run and monitor server status continuously.
* Added icons to warning and error states to assist in at-a-glace reporting.
* Added memory and CPU usage.
* Added warning thresholds for memory and CPU usage.
* Changed disk usage reporting from "percent free" to actual disk usage to match the added CPU and memory usage.
* Changed the warning threshold to of disk usage to match the change.
* Changed the visual style of the report.
* Changed visual style of warnings and errors.
* Changed code formatting for readability.

### 2017-07-28 v1.0

* First public release.
