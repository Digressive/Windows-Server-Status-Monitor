# Windows Server Status Monitor (WSSM)

PowerShell based Windows Server monitor

For full instructions and documentation, [visit my blog post](https://gal.vin/posts/windows-server-status/)

Please consider donating to support my work:

* You can support me on a monthly basis [using Patreon.](https://www.patreon.com/mikegalvin)
* You can support me with a one-time payment [using PayPal](https://www.paypal.me/digressive) or by [using Kofi.](https://ko-fi.com/mikegalvin)

Windows Server Status Monitor can also be downloaded from:

* [The PowerShell Gallery](https://www.powershellgallery.com/packages/WinServ-Status)

Join the [Discord](http://discord.gg/5ZsnJ5k) or Tweet me if you have questions: [@mikegalvin_](https://twitter.com/mikegalvin_)

-Mike

## Features and Requirements

* The utility will display the server name, uptime, CPU, memory and storage information, online status.
* The utility can be configured with a customisable alerts for the CPU, memory and storage.
* The utility can display the results as either a CSV file or a HTML file.
* The utility can be configured to monitor continuously, or run once.
* The utility can be configured to e-mail the results.
* This utility has been tested running on Windows 10 and Windows Server 2016, monitoring PCs and Servers running Windows 10, Windows Server 2016, Windows Server 2012 R2, and Windows Server 2008 R2.
* The utility must be run as a user with administrator-level privileges to the systems it is monitoring.

### Generating A Password File

The password used for SMTP server authentication must be in an encrypted text file. To generate the password file, run the following command in PowerShell, on the computer that is going to run the script and logged in with the user that will be running the script. When you run the command you will be prompted for a username and password. Enter the username and password you want to use to authenticate to your SMTP server.

Please note: This is only required if you need to authenticate to the SMTP server when send the log via e-mail.

``` powershell
$creds = Get-Credential
$creds.Password | ConvertFrom-SecureString | Set-Content c:\scripts\ps-script-pwd.txt
```

After running the commands, you will have a text file containing the encrypted password. When configuring the -Pwd switch enter the path and file name of this file.

### Configuration

Here’s a list of all the command line switches and example configurations.

``` txt
-List
```

The path to a TXT file containing the NetBIOS names of the servers you wish to check.

``` txt
-O
```

The path where the report file will be output to.

``` txt
-DiskAlert
```

The percentage of disk usage that should cause the disk space alert to be raised.

``` txt
-CpuAlert
```

The percentage of CPU usage that should cause the CPU alert to be raised.

``` txt
-MemAlert
```

The percentage of memory usage that should cause the memory alert to be raised.

``` txt
-Refresh
```

The number of seconds that she script should wait before running again. The minimum is 300 seconds (5 minutes) and the maximum is 28800 (8 hours). If not configured the script will run once and then exit.

``` txt
-Light
```

Configure the HTML results file to have a light theme.

``` txt
-csv
```

Export a CSV file, instead of a HTML file.

``` txt
-Subject
```

The email subject that the email should have. Encapsulate with single or double quotes.

``` txt
-SendTo
```

The e-mail address the log should be sent to.

``` txt
-From
```

The e-mail address the log should be sent from.

``` txt
-Smtp
```

The DNS name or IP address of the SMTP server.

``` txt
-User
```

The user account to connect to the SMTP server.

``` txt
-Pwd
```

The txt file containing the encrypted password for the user account.

``` txt
-UseSsl
```

Configures the script to connect to the SMTP server using SSL.

### Example

``` txt
WinServ-Status.ps1 -List C:\foo\servers.txt -O C:\foo -DiskAlert 90 -CpuAlert 95 -MemAlert 85 -Refresh 300 -Light
```

Using the switches above the script will execute using the list of servers and output a HTML report to C:\foo. The disk usage alert will highlight at 90% usage for any one drive, the CPU usage alert will highlight at 95% usage, and the memory usage alert will highlight at 85% usage. The status of the servers will refresh every 5 minutes, and the HTML file will have a light theme instead of a dark theme.
