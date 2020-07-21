#Created by Adam Clark, David Betteridge, and Timothy Hoffman

#******************************************************************************************
#*                                        Variables                                       *
#******************************************************************************************

#SET GLOBAL ERROR HANDLING
$ErrorActionPreference = “silentlycontinue”

#Pull variables from variables.txt
Get-Content "$PSScriptRoot\Variables.txt" | ForEach-Object{
    $var = $_.Split('=')
    New-Variable -Name $var[0] -Value $var[1]
}

#SET DATE
$DATE_PATH = Get-Date -format "yyyy-MM-dd"
$DATE_FULL = Get-Date
$DATE_DAY = Get-Date -format "dd"
$DATE_MONTH = Get-Date -format "MM"
$DATE_YEAR = Get-Date -format "yyyy"
$DATE =  "$DATE_YEAR-$DATE_MONTH-$DATE_DAY"
$DATECUT =  $DATE_FULL.ToShortDateString()



#SET SHARE PATH
$SHARE = "$Results\$DATE_YEAR\$DATE_MONTH\$DATE_DAY"

#SET LOG PATH
$DIR = "$SHARE\$env:COMPUTERNAME\"

#SET SCAN PATH
$SCANDIR = "C:\"

#SET SCHEDULED TASKS PATH
$PATH = "C:\Windows\System32\Tasks\"

#GET IP ADDRESS
$IP = Get-WmiObject Win32_NetworkAdapterConfiguration | where { $_.IpAddress -like "$LocalSubnet" } | select -ExpandProperty ipaddress | select -First 1

#GET MAC ADDRESS
$MAC = Get-WmiObject Win32_NetworkAdapterConfiguration | where { $_.IpAddress -like "$LocalSubnet" } | select -ExpandProperty MACAddress | select -First 1

#GET INSTALLED PRODUCTS
$Win32_PROD = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object Publisher,DisplayName,DisplayVersion,InstallDate,InstallLocation,InstallSource | where Displayname -ne $NULL
$Win64_PROD = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object Publisher,DisplayName,DisplayVersion,InstallDate,InstallLocation,InstallSource | where Displayname -ne $NULL

$PROD = $Win32_PROD + $Win64_PROD

#GET LAST BOOT TIME
$BOOTTIME = get-wmiobject win32_operatingsystem | select @{LABEL = 'LastBootUpTime'; EXPRESSION = {$_.ConverttoDateTime($_.lastbootuptime)}}

#GET COMPUTER INFORMATION
$COMPUTER = Get-WmiObject -Class Win32_ComputerSystem

#GET COMPUTER SERIAL NUMBER
$SERIAL = (Get-WmiObject Win32_BIOS).SerialNumber

#GET COMPUTER MAKE/MODEL
$MAKEMODEL = Get-CimInstance -ClassName Win32_ComputerSystem

#GET PATCH REBOOT PENDING
$PatchReboot = Get-ChildItem -Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"

#GET COMPONENT STORE REBOOT PENDING
$ComponentBasedReboot = Get-ChildItem -Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"

#GET FILENAME REBOOT PENDING
$PendingFileRenameOperations = (Get-ItemProperty -Path "REGISTRY::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager").PendingFileRenameOperations

#GET SCCM REBOOT PENDING
$ConfigurationManagerReboot = Invoke-WmiMethod -Namespace "ROOT\ccm\ClientSDK" -Class CCM_ClientUtilities -Name DetermineIfRebootPending | Select-Object -ExpandProperty "RebootPending"

#GET C: DISK SIZE AND FREE SPACE

$HDDinfo = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID = 'C:'" | Select-Object -Property DeviceID, DriveType, VolumeName, 
@{L='FreeSpaceGB';E={"{0:N2}" -f ($_.FreeSpace /1GB)}},
@{L="Capacity";E={"{0:N2}" -f ($_.Size/1GB)}} 

#GET DNS CACHE
$dnscache = Get-DnsClientCache

#Get Logged on User
$user = (Get-WmiObject -Class Win32_ComputerSystem).Username

#GET ACTIVE SESSIONS

$Out_Sessions = Get-WmiObject Win32_NetworkConnection 

#GET OS information
$OS = (Get-WMIObject win32_operatingsystem).caption
$OS_ARCH = (Get-WmiObject Win32_OperatingSystem).OSArchitecture
$OS_Ver = (Get-WmiObject -class Win32_OperatingSystem).version
$OS_Inst = ([WMI]'').ConvertToDateTime((Get-WmiObject Win32_OperatingSystem).InstallDate)

#CREATE DIRECTORY
if (Test-Path $DIR) {
     Remove-Item $DIR -Force -Recurse}

New-Item $DIR -ItemType directory

#******************************************************************************************
#*                                        Functions                                       *
#******************************************************************************************

function Get-Admins {
     PROCESS {
          Add-Type -AssemblyName System.DirectoryServices.AccountManagement
          $LADMINS = net localgroup administrators | where  {$_ -and $_ -notlike "The command completed successfully." -and $_ -notlike ""} | select -Skip 4
          foreach ($LINE1 in $LADMINS) {
               $LOCK = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True'" | where {$_.name -like $LINE1} | Select-Object Lockout
               if ($LOCK.Lockout -eq $false) {
                    $DS = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Machine)
                    $BLANK = $DS.ValidateCredentials($LINE1,"")
                    $LOCK = $false
               }
               else {
                    $LOCK = $true
                    $BLANK = "N/A"
               }
               $PROPERTIES1 = @{
                    Group = "Administrators"
                    Name = ($LINE1)
                    Lockout = ($LOCK)
                    IsBlank = ($BLANK)
               }
               New-Object -TypeName PSObject -Property $PROPERTIES1
          }
     }
}

function Get-NetStat {
     PROCESS {
          $DATA = netstat -anop TCP
          $DATA = $DATA[4..($DATA.count)]
          foreach ($LINE in $DATA) {
               $LINE = $LINE -replace '^\s+', ''
               $LINE = $LINE -split '\s+'
               $PROPERTIES = @{
                    Protocol = $LINE[0]
                    LocalAddressIP = ($LINE[1] -split ":")[0]
                    LocalAddressPort = ($LINE[1] -split ":")[1]
                    ForeignAddressIP = ($LINE[2] -split ":")[0]
                    ForeignAddressPort = ($LINE[2] -split ":")[1]
                    State = $LINE[3]
                    PID = $LINE[4]
                    ProcessName = $(Get-Process -Id $Line[4]).ProcessName
                    }
               New-Object -TypeName PSObject -Property $PROPERTIES
               }
          }
     }

function Get-Updates {
    PROCESS {
        $updates = wmic qfe list | where {$_ -ne ""}
        $updates = $updates[1..($updates.count)]
            foreach ($update in $updates){
                $update = $update -replace '^\s\s+', ''
                $update = $update -split '\s\s+'
                $UProperties = @{
                HotFixID = $update[3]
                InstalledOn = $update[4]
                Description = $update[2]
            }
            New-Object -TypeName PSObject -Property $UProperties
            }
    }
}


<#
function Get-Tasks {
     PROCESS {
          $TASKS = Get-ChildItem -Recurse -Path $PATH -File
          foreach ($TASK in $TASKS) {
               $ABSOLUTEPATH = $TASK.directory.fullname + "\" + $TASK.Name
               $TASKINFO = [xml](Get-Content $ABSOLUTEPATH)
               $PROPERTIES2 = @{
                   Task = $TASK.name
                   User = $TASKINFO.task.principals.principal.userid
                   Enabled = $TASKINFO.task.settings.enabled
                   Application = $TASKINFO.task.actions.exec.command
                   }
               New-Object -TypeName PSObject -Property $PROPERTIES2
               }
          }
     }
#>

function Get-SMB {
     PROCESS {
          $OSVersion = Get-WmiObject -Class Win32_OperatingSystem | Select Name
          If ($OSVersion -like "*Windows Server 2012 R2*") {
               $SMB1_Installed = Get-WindowsFeature FS-SMB1 | Select Installed
               If ($SMB1_Installed.Installed -eq $true) {
                    $SMB_RETURN = $true
                    $wshell = New-Object -ComObject Wscript.Shell
                    $wshell.Popup("This system is currently running SMBv1 and is vulnerable to cyber attack.  Please contact the 4ID Helpdesk or 4ID G6 CND at (719)503-9442 for corrective action.",0,"4ID Information Assurance Warning",0x1)
               }
               Else {
                    $SMB_RETURN = $false
               }
          }
          Else {
               $SMB1_Installed = Get-WindowsOptionalFeature -Online -featurename smb1protocol | select state               
               If ($SMB1_Installed.State -eq "Enabled") {
                    $SMB_RETURN = $true
                    $wshell = New-Object -ComObject Wscript.Shell
                    $wshell.Popup("This system is currently running SMBv1 and is vulnerable to cyber attack.  Please contact the 4ID Helpdesk or 4ID G6 CND at (719)503-9442 for corrective action.",0,"4ID Information Assurance Warning",0x1)
               }
               else {
               $SMB_RETURN = $false
               }
     New-Object -TypeName PSObject $SMB_RETURN
               }
     }
}



function Get-MasterKey {
     PROCESS {
          $IPV6 = $false
                $arrInterfaces = (Get-WmiObject -class Win32_NetworkAdapterConfiguration -filter "ipenabled = TRUE").IPAddress
                foreach ($i in $arrInterfaces) {$IPV6 = $IPV6 -or $i.contains(":")}
          $AGENT = $PROD | Select Name | Where-Object {$_.Name -eq "McAfee Agent"}
          if ($AGENT.name -like 'McAfee Agent') { 
               $AGENTPRES = $true
          }
          else {
               $AGENTPRES = $false
          }
          $ENS = $PROD | Select Name | Where-Object {$_.Name -eq "Mcaffee enterprises security platform"}
          if ($ENS.name -like 'Mcaffee enterprises security platform') { 
               $ENSPRES = $true
          }
          else {
               $ENSPRES = $false
          }
          $SCCM = $PROD | Select Name | Where-Object {$_.Name -eq "Configuration Manager Client"}
          if ($SCCM.name -like 'Configuration Manager Client') { 
               $SCCMPRES = $true
          }
          else {
               $SCCMPRES = $false
          }
          if ($VSEPRES -eq $true) {
               $VSEDAT = C:\"Program Files"\"Common Files"\McAfee\SystemCore\csscan.exe -Versions | findstr "DAT"
               $VSEDAT = $VSEDAT -replace '^\s+', ''
               $VSEDAT = $VSEDAT -split '\s+'
               $VSEDAT = [int]$VSEDAT[2]
          }
          else {$VSEDAT = "N/A"
          }
          if (($PatchReboot -eq $null) -and ($ComponentBasedReboot -eq $null) -and ($PendingFileRenameOperations -eq $null) -and($ConfigurationManagerReboot -eq $false)) {
               $REBOOT= $false
          }
          else {
               $REBOOT = $true
}
          $PROPERTIES4 = @{
              Username = $env:USERNAME
              IP = $IP
              IPv6 = $IPV6
              MAC = $MAC
              SerialNumber = $SERIAL
              Make = $MAKEMODEL.Manufacturer
              Model = $MAKEMODEL.Model
              LastBootTime = $BOOTTIME.LastBootUpTime
              RebootRequired = $REBOOT
              OnDomain = $COMPUTER.partofdomain
              Domain = $COMPUTER.Domain
              Agent = $AGENTPRES
              ENS = $ENSPRES
              DATNum = $VSEDAT
              SCCM = $SCCMPRES
              HddSizeGB = $HDDinfo.Capacity
              HddFreeGB = $HDDinfo.FreeSpaceGB
              LoggedOnUser = $user
              OperatingSystem = $OS
              OSArchitecture = $OS_ARCH
              OSBuild = $OS_Ver
              OSInstallDate = $OS_Inst

          }
          New-Object -TypeName PSObject -Property $PROPERTIES4
     }
}

function Unlock-LAPS {
     PROCESS {
          $USERNAME = "aceaccislwa"
          [ADSI]$USER = [ADSI] "WinNT://$env:COMPUTERNAME/$USERNAME"
          if ($USER.isaccountlocked -ne $null) {
               if ($user.IsAccountLocked -ne $false) {
                    try {
                         $USER.IsAccountLocked = $false
                         $user.SetInfo()
                         }
                    catch{}
               }
          else {}
          }
     }
}

#******************************************************************************************
#*                    Gather Master Key, add key, and dump to CSV                         *
#******************************************************************************************

Get-MasterKey | Select-Object -Property Username,LastBootTime,RebootRequired,IP,IPv6,Make,Model,SerialNumber,MAC,HDDsizeGB,HDDfreeGB,OnDomain,Domain,Agent,ENS,DATNum,SCCM,LoggedOnUser,OperatingSystem,OSArchitecture,OSBuild,OSInstallDate | ForEach-Object {
     $_ | Add-Member -MemberType NoteProperty -Name PSComputerName -Value $env:COMPUTERNAME -PassThru | Add-Member -MemberType NoteProperty -Name Date -Value $DATECUT -PassThru } | Select-Object PsComputerName,Date,Username,IP,IPv6,Make,Model,SerialNumber,MAC,HDDSizeGB,HDDFreeGB,OnDomain,Domain,LastBootTime,RebootRequired,Agent,ENS,DATNum,SCCM,LoggedOnUser,OperatingSystem,OSArchitecture,OSBuild,OSInstallDate | Export-Csv $DIR$env:COMPUTERNAME"_Master.csv" -NoTypeInformation

#******************************************************************************************
#*                     Gather processes, add key, and dump to CSV                         *
#******************************************************************************************

Get-CimInstance -Class Win32_Process | select-object ProcessName,ProcessId,parentProcessID,CreationDate,executablePath,CommandLine | ForEach -Process {
     $_ | Add-Member -MemberType NoteProperty -Name PSComputerName -Value $env:COMPUTERNAME -PassThru | Add-Member -MemberType NoteProperty -Name Date -Value $DATECUT -PassThru | Add-Member -MemberType NoteProperty -Name ParentProcessName -Value $(Get-Process -Id $_.parentProcessID).ProcessName -PassThru }| Select-Object PsComputerName,Date,Processname,ProcessID,ParentProcessId,ParentProcessName,executablePath,CommandLine,creationdate | Export-Csv $DIR$env:COMPUTERNAME"_Processes.csv" -NoTypeInformation

#******************************************************************************************
#*                      Gather products, add key, and dump to CSV                         *
#******************************************************************************************

$PROD | Select-Object -Property Publisher,DisplayName,DisplayVersion,InstallDate,InstallSource,InstallLocation| ForEach-Object {
     $_ | Add-Member -MemberType NoteProperty -Name PSComputerName -Value $env:COMPUTERNAME -PassThru | Add-Member -MemberType NoteProperty -Name Date -Value $DATECUT -PassThru } | Select-Object PsComputerName,Date,Publisher,DisplayName,DisplayVersion,InstallDate,InstallSource,InstallLocation | Export-Csv $DIR$env:COMPUTERNAME"_Products.csv" -NoTypeInformation

#******************************************************************************************
#*       Gather members of the local administrators group, add key, and dump to CSV       *
#******************************************************************************************

Get-Admins Select-Object -Property Group,Name,Lock,IsBlank | ForEach-Object {
     $_ | Add-Member -MemberType NoteProperty -Name PSComputerName -Value $env:COMPUTERNAME -PassThru | Add-Member -MemberType NoteProperty -Name Date -Value $DATECUT -PassThru } | Select-Object PsComputerName,Date,Group,Name,Lock,IsBlank | Export-Csv $DIR$env:COMPUTERNAME"_Admins.csv" -NoTypeInformation

#******************************************************************************************
#*                 Gather all local accounts, add key, and dump to CSV                    *
#******************************************************************************************

Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True'" | Select-Object Name,InstallDate,Disabled,Lockout,PasswordRequired,PasswordExpires | ForEach-Object {
     $_ | Add-Member -MemberType NoteProperty -Name PSComputerName -Value $env:COMPUTERNAME -PassThru | Add-Member -MemberType NoteProperty -Name Date -Value $DATECUT -PassThru } | Select-Object PSComputerName,Date,Name,InstallDate,Disabled,Lockout,PasswordRequired,PasswordExpires | Export-Csv $DIR$env:COMPUTERNAME"_LocalAccounts.csv" -NoTypeInformation

#*******************************************************************************************
#*                       Gather Netstat, add key, and dump to CSV                          *
#*******************************************************************************************

Get-NetStat Select-Object -Property Protocol,LocalAddressIP,LocalAddressPort,ForeignAddressIP,ForeignAddressPort,State,PID | ForEach-Object {
     $_ | Add-Member -MemberType NoteProperty -Name PSComputerName -Value $env:COMPUTERNAME -PassThru | Add-Member -MemberType NoteProperty -Name Date -Value $DATECUT -PassThru } | Select-Object PsComputerName,Date,Protocol,LocalAddressIP,LocalAddressPort,ForeignAddressIP,ForeignAddressPort,State,PID,ProcessName | Export-Csv $DIR$env:COMPUTERNAME"_NetStat.csv" -NoTypeInformation

#*******************************************************************************************
#*                       Gather Windows Updates, add key, and dump to CSV                  *
#*******************************************************************************************

Get-Updates Select-Object -Property HotFixID,InstalledOn,Description | ForEach-Object {
     $_ | Add-Member -MemberType NoteProperty -Name PSComputerName -Value $env:COMPUTERNAME -PassThru | Add-Member -MemberType NoteProperty -Name Date -Value $DATECUT -PassThru } | Select-Object PsComputerName,Date,Description,HotFixID,InstalledOn | Export-Csv $DIR$env:COMPUTERNAME"_updates.csv" -NoTypeInformation

#*******************************************************************************************
#*                    Gather Startup Commands, add key, and dump to CSV                    *
#*******************************************************************************************

Get-WmiObject -Class Win32_StartupCommand | Select-Object Name,Command,Location,User | ForEach-Object {
     $_ | Add-Member -MemberType NoteProperty -Name PSComputerName -Value $env:COMPUTERNAME -PassThru | Add-Member -MemberType NoteProperty -Name Date -Value $DATECUT -PassThru } | Select-Object PSComputerName,Date,Name,Command,Location,User | Export-Csv $DIR$env:COMPUTERNAME"_Startup.csv" -NoTypeInformation

#*******************************************************************************************
#*                       Gather Services, add key, and dump to CSV                         *
#*******************************************************************************************

Get-WmiObject -Class Win32_Service | Select-Object DisplayName,Name,PathName,ProcessId,StartMode,State,Status | ForEach-Object {
     $_ | Add-Member -MemberType NoteProperty -Name PSComputerName -Value $env:COMPUTERNAME -PassThru | Add-Member -MemberType NoteProperty -Name Date -Value $DATECUT -PassThru } | Select-Object PSComputerName,Date,DisplayName,Name,PathName,ProcessId,StartMode,State,Status | Export-Csv $DIR$env:COMPUTERNAME"_Services.csv" -NoTypeInformation 

#*******************************************************************************************
#*        Gather .exe files created w/in the last 24 hours, add key, and dump to CSV       *
#*******************************************************************************************

Get-ChildItem -path $SCANDIR -Recurse -force -file | where-object {($_.extension -eq ".exe") -and ($_.CreationTime -gt (get-date).AddDays(-1))} | ForEach-Object {
     $_ | Add-Member -MemberType NoteProperty -Name PSComputerName -Value $env:COMPUTERNAME -PassThru | Add-Member -MemberType NoteProperty -Name Date -Value $DATECUT -PassThru } | Select-Object PSComputerName,Date,Name,Directory,@{N='FileHash';E={(Get-FileHash $_.FullName -Algorithm SHA1).Hash}},Length,LastWriteTime,@{N='SignerCertificate';E={(Get-AuthenticodeSignature $_.FullName).signercertificate.Issuer}},@{N='CertificateVerification';E={(Get-AuthenticodeSignature $_.FullName).status}} | Export-Csv $DIR$env:COMPUTERNAME"_NewEXE.csv" -NoTypeInformation 

#*******************************************************************************************
#*        Gather all  files created w/in the last 24 hours, add key, and dump to CSV       *
#*******************************************************************************************

Get-ChildItem -path $SCANDIR -Recurse -force -file | Where-Object {$_.CreationTime -gt (get-date).AddDays(-1)} | ForEach-Object {
     $_ | Add-Member -MemberType NoteProperty -Name PSComputerName -Value $env:COMPUTERNAME -PassThru | Add-Member -MemberType NoteProperty -Name Date -Value $DATECUT -PassThru } | Select-Object PSComputerName,Date,Name,Directory,@{N='FileHash';E={(Get-FileHash $_.FullName -Algorithm SHA1).Hash}},Length,LastWriteTime,@{N='SignerCertificate';E={(Get-AuthenticodeSignature $_.FullName).signercertificate.Issuer}},@{N='CertificateVerification';E={(Get-AuthenticodeSignature $_.FullName).status}} | Export-Csv $DIR$env:COMPUTERNAME"_NewFile.csv" -NoTypeInformation 

#*******************************************************************************************
#*                   Gather all open shares, add key, and dump to CSV                      *
#*******************************************************************************************

get-wmiobject win32_share | Select-Object Name,Path,Descrition | ForEach-Object {
     $_ | Add-Member -MemberType NoteProperty -Name PSComputerName -Value $env:COMPUTERNAME -PassThru | Add-Member -MemberType NoteProperty -Name Date -Value $DATECUT -PassThru } | Select-Object PSComputerName,Date,Name,Path,Descrition | Export-Csv $DIR$env:COMPUTERNAME"_Shares.csv" -NoTypeInformation 

#*******************************************************************************************
#*                 Gather all Scheduled Tasks, add key, and dump to CSV                    *
#*******************************************************************************************
<#
Get-Tasks Select-Object -Property Task,User,Enabled,Application | ForEach-Object {
     $_ | Add-Member -MemberType NoteProperty -Name PSComputerName -Value $env:COMPUTERNAME -PassThru | Add-Member -MemberType NoteProperty -Name Date -Value $DATECUT -PassThru } | Select-Object PsComputerName,Date,Task,User,Enabled,Application | Export-Csv $DIR$env:COMPUTERNAME"_Tasks.csv" -NoTypeInformation
#>
Get-ScheduledTask | Select-Object State,Source,TaskName,TaskPath,URI | ForEach-Object {
     $_ | Add-Member -MemberType NoteProperty -Name PSComputerNAme -Value $env:COMPUTERNAME -PassThru | Add-Member -MemberType NoteProperty -Name Date -Value $DATECUT -PassThru -Force} | Select-Object PsComputerName,Date,TaskName,TaskPath,State,Source | Export-Csv $DIR$env:COMPUTERNAME"_Tasks.csv" -NoTypeInformation

#*******************************************************************************************
#*                Gather all Installed Printers, add key, and dump to CSV                  *
#*******************************************************************************************

get-wmiobject win32_printer | Select-Object Location,Name,PrinterState,PrinterStatus,ShareName,SystemName | ForEach-Object {
     $_ | Add-Member -MemberType NoteProperty -Name PSComputerName -Value $env:COMPUTERNAME -PassThru | Add-Member -MemberType NoteProperty -Name Date -Value $DATECUT -PassThru } | Select-Object PSComputerName,Date,Location,Name,PrinterState,PrinterStatus,ShareName,SystemName | Export-Csv $DIR$env:COMPUTERNAME"_Printers.csv" -NoTypeInformation 

#*******************************************************************************************
#*                Gather DNS Cache, add key, and dump to CSV                  *
#*******************************************************************************************
$dnscache | Select-Object -Property Entry,RecordName,RecordType,Status,TimeToLive,DataLength,Data | Foreach-Object {
    $_ | Add-Member -MemberType NoteProperty -Name PSComputerName -Value $env:COMPUTERNAME -PassThru | Add-Member -MemberType NoteProperty -Name Date -Value $DATECUT -PassThru } | Select-Object PSComputerName,Date,Entry,RecordName,RecordType,Status,TimeToLive,DataLength,Data | Export-Csv $DIR$env:COMPUTERNAME"_DNS.csv" -NoTypeInformation

#*******************************************************************************************
#*                Gather active sessions, add key, and dump to CSV                  *
#*******************************************************************************************
$Out_Sessions | Select-Object -Property LocalName,RemoteName,ConnectionState,Status | Foreach-Object {
    $_ | Add-Member -MemberType NoteProperty -Name PSComputerName -Value $env:COMPUTERNAME -PassThru | Add-Member -MemberType NoteProperty -Name Date -Value $DATECUT -PassThru } | Select-Object PSComputerName,Date,LocalName,RemoteName,ConnectionState,Status| Export-Csv $DIR$env:COMPUTERNAME"_OutSessions.csv" -NoTypeInformation

<#******************************************************************************************
 *                                    End of Script :)                                     *
 *****************************************************************************************#>

 <#


 Created on 23 July 2018
 Modified on 31 July 2018
     Added MAKE/MODEL/MAC/SerialNumber (MasterKey function)
 Modified on 06 August 2018
     Changed "$DATECUT" variable to simple date format for ease of importing into SQL (SET DATE variable set)
     Added Reboot Pending section (MasterKey function)
 Modified on 07 August 2018
     Added Test for Locked Out Local Admin Accounts (get-admin function)
     Added Test for Blank PW on Local Admin Accounts that are not locked out (get-admin function)
 Modified on 09 August 2018
     Commented out get-task function and dump because it fails unless run as workstation admin in local admin context (even with system privliges)
     Added get-scheduled tasks functionality to pull diretly from WMI
 Modified on 24 August 2018
     Added function to unlock LAPSLW (Unlock-LAPS)
 Modified 16 April 2020
    Added Windows updates query
 Modified 27 April 2020
    Added DNS Cache query
    Added Active Sessions query
Modified 4 May 2020
    Altered how processes are collected to include parentPID
Modified 11 May 2020
    Refined process collectin to include ParentProcessName
    Chagned how products were pulled from using Get-WmiObject -Class Win32_Product to pulling from the registry
    Added query for logged-in user
Modified 12 May 2020
    Added Hash to new files and executables
Modified 18 May 2020
    Added OS version, architecture information
#>