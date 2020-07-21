
<#
 Created by Timothy Hoffman, timothy.hoffman.83@gmail.com

 This script is designed to be used in conjunction with the Collector and Summarize scrits.

 This acts as the user interface to the summarized results of the collection script.

 For best results, run the collector script daily at any time.  And run the summarize script daily, at Midnight, 
 after the collection script has ran on all systems.  
  This will provide the Eye with the necessary results it needs to work properly.

 #>
$Title = '
    ______                    ____   _____                            
   / ____/_  _____     ____  / __/  / ___/____ ___  ___________  ____ 
  / __/ / / / / _ \   / __ \/ /_    \__ \/ __ `/ / / / ___/ __ \/ __ \
 / /___/ /_/ /  __/  / /_/ / __/   ___/ / /_/ / /_/ / /  / /_/ / / / /
/_____/\__, /\___/   \____/_/     /____/\__,_/\__,_/_/   \____/_/ /_/ 
      /____/                                                          

'
#****************************************************************************************
#                      Pull the variables from variables.txt
#****************************************************************************************
#SET GLOBAL ERROR HANDLING
$ErrorActionPreference = “silentlycontinue”

#Pull variables from variables.txt
Get-Content "$PSScriptRoot\Variables.txt" | ForEach-Object{
    $var = $_.Split('=')
    New-Variable -Name $var[0] -Value $var[1]
}


#****************************************************************************************
#                    These variables do not need to be adjusted
#****************************************************************************************
$DATE_DAY = Get-Date -format "dd"
$DATE_MONTH = Get-Date -format "MM"
$DATE_YEAR = Get-Date -format "yyyy"
$DATE = Get-Date -format "yyyy-MM-dd"
$Yesterday_Day = (get-date).date.adddays(-1).ToString("dd")
$Yesterday_Month = (get-date).date.adddays(-1).ToString("MM")
$Yesterday_year = (get-date).date.adddays(-1).ToString("yyyy")




#****************************************************************************************
#                                         Main Menu
#****************************************************************************************
function mainMenu {
    $mainMenu = 'X'
    while($mainMenu -ne ''){
        Clear-Host
        Write-Host -ForegroundColor Red "`n`t`t $Title `n"
        Write-Host -ForegroundColor Cyan "  Main Menu "
        Write-Host -ForegroundColor Green -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor Green -NoNewline "]"; `
            Write-Host -ForegroundColor Green " Local Administrator Group Queries"
        Write-Host -ForegroundColor Green -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor Green -NoNewline "]"; `
            Write-Host -ForegroundColor Green " Local User Account Queries"
        Write-Host -ForegroundColor Green -NoNewline "`n["; Write-Host -NoNewline "3"; Write-Host -ForegroundColor Green -NoNewline "]"; `
            Write-Host -ForegroundColor Green " Product Queries"
        Write-Host -ForegroundColor Green -NoNewline "`n["; Write-Host -NoNewline "4"; Write-Host -ForegroundColor Green -NoNewline "]"; `
            Write-Host -ForegroundColor Green " Process Queries"
        Write-Host -ForegroundColor Green -NoNewline "`n["; Write-Host -NoNewline "5"; Write-Host -ForegroundColor Green -NoNewline "]"; `
            Write-Host -ForegroundColor Green " Service Queries"
        Write-Host -ForegroundColor Green -NoNewline "`n["; Write-Host -NoNewline "6"; Write-Host -ForegroundColor Green -NoNewline "]"; `
            Write-Host -ForegroundColor Green " Local Shares Queries"
        Write-Host -ForegroundColor Green -NoNewline "`n["; Write-Host -NoNewline "7"; Write-Host -ForegroundColor Green -NoNewline "]"; `
            Write-Host -ForegroundColor Green " Startup Queries"
        Write-Host -ForegroundColor Green -NoNewline "`n["; Write-Host -NoNewline "8"; Write-Host -ForegroundColor Green -NoNewline "]"; `
            Write-Host -ForegroundColor Green " Printers Queries"
        Write-Host -ForegroundColor Green -NoNewline "`n["; Write-Host -NoNewline "9"; Write-Host -ForegroundColor Green -NoNewline "]"; `
            Write-Host -ForegroundColor Green " Network Status Queries"
        Write-Host -ForegroundColor Green -NoNewline "`n["; Write-Host -NoNewline "10"; Write-Host -ForegroundColor Green -NoNewline "]"; `
            Write-Host -ForegroundColor Green " Executables Queries"
        Write-Host -ForegroundColor Green -NoNewline "`n["; Write-Host -NoNewline "11"; Write-Host -ForegroundColor Green -NoNewline "]"; `
            Write-Host -ForegroundColor Green " Files Queries"
        Write-Host -ForegroundColor Green -NoNewline "`n["; Write-Host -NoNewline "12"; Write-Host -ForegroundColor Green -NoNewline "]"; `
            Write-Host -ForegroundColor Green " System details Queries"
        Write-Host -ForegroundColor Green -NoNewline "`n["; Write-Host -NoNewline "13"; Write-Host -ForegroundColor Green -NoNewline "]"; `
            Write-Host -ForegroundColor Green " Windows Update Queries"
        Write-Host -ForegroundColor Green -NoNewline "`n["; Write-Host -NoNewline "14"; Write-Host -ForegroundColor Green -NoNewline "]"; `
            Write-Host -ForegroundColor Green " DNS Cache Queries"
        Write-Host -ForegroundColor Green -NoNewline "`n["; Write-Host -NoNewline "15"; Write-Host -ForegroundColor Green -NoNewline "]"; `
            Write-Host -ForegroundColor Green " Active Outbound Session Queries"
        Write-Host -ForegroundColor Green -NoNewline "`n["; Write-Host -NoNewline "16"; Write-Host -ForegroundColor Green -NoNewline "]"; `
            Write-Host -ForegroundColor Green " Scheduled Tasks Queries"
        $mainMenu = Read-Host "`nSelection (leave blank to quit)"
        # Launch submenu1
        if($mainMenu -eq 1){
            $Type = 'Admins'
            $Print = "local Administrator accounts"
            $P1 = "Name"
            $P2 = "Group"
            $P3 = "IsBlank"
            subMenu1
        }
        # Launch submenu2
        if($mainMenu -eq 2){
            $Type = 'LocalAccounts'
            $Print = "local accounts"
            $P1 = "Name"
            $P2 = "Disabled"
            $P3 = "Lockout"
            subMenu1
        }
        # Launch submenu3
        if($mainMenu -eq 3){
            $Type = 'Products'
            $Print = "Software Products"
            $P1 = "DisplayName"
            $P2 = "DisplayVersion"
            $P3 = "Publisher"
            subMenu1
        }
        # Launch submenu4
        if($mainMenu -eq 4){
            $Type = 'Processes'
            $Print = "Processes"
            $P1 = "ProcessName"
            $P2 = "ParentProcessName"
            $P3 = "executablePath"
            subMenu1
        }
        # Launch submenu5
        if($mainMenu -eq 5){
            $Type = 'Services'
            $Print = "Services"
            $P1 = "DisplayName"
            $P2 = "Name"
            $P3 = "StartMode"
            subMenu1
        }
        # Launch submenu6
        if($mainMenu -eq 6){
            $Type = 'Shares'
            $Print = "Local Shares"
            $P1 = "Name"
            $P2 = "Path"
            $P3 = "Description"
            subMenu1
        }
        # Launch submenu7
        if($mainMenu -eq 7){
            $Type = 'Startup'
            $Print = "Startup Items"
            $P1 = "Name"
            $P2 = "Command"
            $P3 = "Location"
            subMenu1
        }
        # Launch submenu8
        if($mainMenu -eq 8){
            $Type = 'Printers'
            $Print = "Printers"
            $P1 = "Name"
            $P2 = "ShareName"
            $P3 = "PrinterStatus"
            subMenu1
        }
        # Launch submenu9
        if($mainMenu -eq 9){
            $Type = 'NetStat'
            $Print = "Network Status"
            $P1 = "LocalAddressIP"
            $P2 = "ForeignAddressIP"
            $P3 = "ForeignAddressPort"
            subMenu3
        }
        # Launch submenu10
        if($mainMenu -eq 10){
            $Type = 'NewEXE'
            $Print = "Executable Files"
            $P1 = "Name"
            $P2 = "Directory"
            $P3 = "Filehash"
            subMenu1
        }
        # Launch submenu11
        if($mainMenu -eq 11){
            $Type = 'NewFile'
            $Print = "New Files"
            $P1 = "Name"
            $P2 = "Directory"
            $P3 = "Filehash"
            subMenu1
        }
        # Launch submenu12
        if($mainMenu -eq 12){
            $Type = "Master"
            $Print = "System Details"
            $P1 = "IP"
            $P2 = "SerialNumber"
            $P3 = "MAC"
            subMenu2
        }
        # Launch submenu13
        if($mainMenu -eq 13){
            $Type = 'updates'
            $Print = "Windows Updates"
            $P1 = "HotFixID"
            $P2 = "InstalledOn"
            $P3 = "Description"
            subMenu1
        }
        # Launch submenu14
        if($mainMenu -eq 14){
            $Type = 'DNS'
            $Print = "DNS cached entries"
            $P1 = "Entry"
            $P2 = "DataLength"
            $P3 = "Data"
            subMenu1
        }
        # Launch submenu15
        if($mainMenu -eq 15){
            $Type = 'OutSessions'
            $Print = "external sessions"
            $P1 = "LocalName"
            $P2 = "RemoteName"
            $P3 = "ConnectionState"
            subMenu1
        }
        # Launch submenu16
        if($mainMenu -eq 16){
            $Type = 'tasks'
            $Print = "Scheduled Tasks"
            $P1 = "TaskName"
            $P2 = "TaskPath"
            $P3 = "State"
            subMenu1
        }
    }
}

#****************************************************************************************
#                                         Sub Menu 1
#****************************************************************************************

# Sub Menu 1
function subMenu1 {
    $subMenu1 = 'X'
    while($subMenu1 -ne ''){
        Clear-Host
        Write-Host -ForegroundColor Red "`n`t`t $Title`n"
        Write-Host -ForegroundColor Cyan "  $Print Queries"
        Write-Host -ForegroundColor Green -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor Green -NoNewline "]"; `
            Write-Host -ForegroundColor Green " New $Print discovered in XX days"
        Write-Host -ForegroundColor Green -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor Green -NoNewline "]"; `
            Write-Host -ForegroundColor Green " $Print discoverd in XX days"
        Write-Host -ForegroundColor Green -NoNewline "`n["; Write-Host -NoNewline "3"; Write-Host -ForegroundColor Green -NoNewline "]"; `
            Write-Host -ForegroundColor Green " $Print discoverd in custom date"
        Write-Host -ForegroundColor Green -NoNewline "`n["; Write-Host -NoNewline "4"; Write-Host -ForegroundColor Green -NoNewline "]"; `
            Write-Host -ForegroundColor Green " $Print on a specific workstation - latest"
        Write-Host -ForegroundColor Green -NoNewline "`n["; Write-Host -NoNewline "5"; Write-Host -ForegroundColor Green -NoNewline "]"; `
            Write-Host -ForegroundColor Green " $Print on a specific workstation - all time"        
        Write-Host -ForegroundColor Green -NoNewline "`n["; Write-Host -NoNewline "6"; Write-Host -ForegroundColor Green -NoNewline "]"; `
            Write-Host -ForegroundColor Green " Workstations with a specific $Print - last day"
        Write-Host -ForegroundColor Green -NoNewline "`n["; Write-Host -NoNewline "7"; Write-Host -ForegroundColor Green -NoNewline "]"; `
            Write-Host -ForegroundColor Green " Workstations with a specific $Print - all time"
        Write-Host -ForegroundColor Green -NoNewline "`n["; Write-Host -NoNewline "8"; Write-Host -ForegroundColor Green -NoNewline "]"; `
            Write-Host -ForegroundColor Green " Workstations without a specific $Print - last day"
        $subMenu1 = Read-Host "`nSelection (leave blank to quit)"
        $timeStamp = Get-Date -Uformat %m%d%y%H%M
        # Option 1
        if($subMenu1 -eq 1){
           1_New_Days
        }
        # Option 2
        if($subMenu1 -eq 2){
            2_Summary_Days
        }
        # Option 3
        if($subMenu1 -eq 3){
            3_Summary_Date
        }
        # Option 4
        if($subMenu1 -eq 4){
            4_By_System_Latest
        }
        # Option 5
        if($subMenu1 -eq 5){
            5_By_System_AllTime
        }
        # Option 6
        if($subMenu1 -eq 6){
            6_Item_On_System_Latest
        }
        # Option 7
        if($subMenu1 -eq 7){
            8_Item_On_System_alltime
        }
        # Option 8
        if($subMenu1 -eq 7){
            7_Item_Not_On_System_Latest
        }
    }
}

#****************************************************************************************
#                                   Sub Menu 2 - System Details
#****************************************************************************************

# Sub Menu 2 - System Details Group Queries
function subMenu2 {
    $subMenu2 = 'X'
    while($subMenu2 -ne ''){
        Clear-Host
        Write-Host -ForegroundColor Red "`n`t`t $Title`n"
        Write-Host -ForegroundColor Cyan "  $Print Queries"
        Write-Host -ForegroundColor Green -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor Green -NoNewline "]"; `
            Write-Host -ForegroundColor Green " New $Print discovered in XX days"
        Write-Host -ForegroundColor Green -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor Green -NoNewline "]"; `
            Write-Host -ForegroundColor Green " $Print summary - Full Details"
        Write-Host -ForegroundColor Green -NoNewline "`n["; Write-Host -NoNewline "3"; Write-Host -ForegroundColor Green -NoNewline "]"; `
            Write-Host -ForegroundColor Green " Systems with NO McAfee Agent"
        Write-Host -ForegroundColor Green -NoNewline "`n["; Write-Host -NoNewline "4"; Write-Host -ForegroundColor Green -NoNewline "]"; `
            Write-Host -ForegroundColor Green " Systems with a McAfee Agent"
        Write-Host -ForegroundColor Green -NoNewline "`n["; Write-Host -NoNewline "5"; Write-Host -ForegroundColor Green -NoNewline "]"; `
            Write-Host -ForegroundColor Green " Systems with NO SCCM Agent"
        Write-Host -ForegroundColor Green -NoNewline "`n["; Write-Host -NoNewline "6"; Write-Host -ForegroundColor Green -NoNewline "]"; `
            Write-Host -ForegroundColor Green " Systems with an SCCM Agent"
        Write-Host -ForegroundColor Green -NoNewline "`n["; Write-Host -NoNewline "7"; Write-Host -ForegroundColor Green -NoNewline "]"; `
            Write-Host -ForegroundColor Green " Systems NOT on the domain"
        Write-Host -ForegroundColor Green -NoNewline "`n["; Write-Host -NoNewline "8"; Write-Host -ForegroundColor Green -NoNewline "]"; `
            Write-Host -ForegroundColor Green " Systems on the domain"
        $subMenu2 = Read-Host "`nSelection (leave blank to quit)"
        $timeStamp = Get-Date -Uformat %m%d%y%H%M
        # Option 1
        if($subMenu2 -eq 1){
           1_New_Days
        }
        # Option 2
        if($subMenu2 -eq 2){
            21_Master_List_Date
        }
        # Option 3
        if($subMenu2 -eq 3){
        $agent = "Agent"
        $value = "FALSE"
        $Title = "Systems without a McAffee Agent"
            23_Agents_latest
        }
        # Option 4
        if($subMenu2 -eq 4){
        $agent = "Agent"
        $value = "TRUE"
        $Title = "Systems wit a McAffee Agent"
            23_Agents_latest
        }
        # Option 5
        if($subMenu2 -eq 5){
        $agent = "SCCM"
        $value = "FALSE"
        $Title = "Systems without an SCCM Agent"
            23_Agents_latest
        }
        # Option 6
        if($subMenu2 -eq 6){
        $agent = "SCCM"
        $value = "TRUE"
        $Title = "Systems wit an SCCM Agent"
            23_Agents_latest
        }
        # Option 7
        if($subMenu2 -eq 7){
        $agent = "onDomain"
        $value = "FALSE"
        $Title = "Systems not on the domain"
            23_Agents_latest
        }
        # Option 8
        if($subMenu2 -eq 8){
        $agent = "onDomain"
        $value = "TRUE"
        $Title = "Systems on the domain"
            23_Agents_latest
        }
    }
}


#****************************************************************************************
#                                   Sub Menu 3 - Netstat Queries
#****************************************************************************************

# Sub Menu 3 - Network Queries
function subMenu3 {
    $subMenu3 = 'X'
    while($subMenu3 -ne ''){
        Clear-Host
        Write-Host -ForegroundColor Red "`n`t`t $Title`n"
        Write-Host -ForegroundColor Cyan "  $Print Queries"
        Write-Host -ForegroundColor Green -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor Green -NoNewline "]"; `
            Write-Host -ForegroundColor Green " New network connections in XX days"
        Write-Host -ForegroundColor Green -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor Green -NoNewline "]"; `
            Write-Host -ForegroundColor Green " Summary of network connections for XX Days"        
        Write-Host -ForegroundColor Green -NoNewline "`n["; Write-Host -NoNewline "3"; Write-Host -ForegroundColor Green -NoNewline "]"; `
            Write-Host -ForegroundColor Green " Query by local address"
        Write-Host -ForegroundColor Green -NoNewline "`n["; Write-Host -NoNewline "4"; Write-Host -ForegroundColor Green -NoNewline "]"; `
            Write-Host -ForegroundColor Green " Query by remote address"
        Write-Host -ForegroundColor Green -NoNewline "`n["; Write-Host -NoNewline "5"; Write-Host -ForegroundColor Green -NoNewline "]"; `
            Write-Host -ForegroundColor Green " Query by remote port"
        Write-Host -ForegroundColor Green -NoNewline "`n["; Write-Host -NoNewline "6"; Write-Host -ForegroundColor Green -NoNewline "]"; `
            Write-Host -ForegroundColor Green " Query by protocol"
        Write-Host -ForegroundColor Green -NoNewline "`n["; Write-Host -NoNewline "7"; Write-Host -ForegroundColor Green -NoNewline "]"; `
            Write-Host -ForegroundColor Green " Query by session state listening"
        Write-Host -ForegroundColor Green -NoNewline "`n["; Write-Host -NoNewline "8"; Write-Host -ForegroundColor Green -NoNewline "]"; `
            Write-Host -ForegroundColor Green " Query by session state established"
        Write-Host -ForegroundColor Green -NoNewline "`n["; Write-Host -NoNewline "9"; Write-Host -ForegroundColor Green -NoNewline "]"; `
            Write-Host -ForegroundColor Green " Query by Process ID"
        Write-Host -ForegroundColor Green -NoNewline "`n["; Write-Host -NoNewline "10"; Write-Host -ForegroundColor Green -NoNewline "]"; `
            Write-Host -ForegroundColor Green " Query by Process name"
        Write-Host -ForegroundColor Green -NoNewline "`n["; Write-Host -NoNewline "11"; Write-Host -ForegroundColor Green -NoNewline "]"; `
            Write-Host -ForegroundColor Green " Query Ports except custom ports.  Up to three may be entered"
        Write-Host -ForegroundColor Green -NoNewline "`n["; Write-Host -NoNewline "12"; Write-Host -ForegroundColor Green -NoNewline "]"; `
            Write-Host -ForegroundColor Green " Query Ports without ports 0,80, and 443"
        Write-Host -ForegroundColor Green -NoNewline "`n["; Write-Host -NoNewline "13"; Write-Host -ForegroundColor Green -NoNewline "]"; `
            Write-Host -ForegroundColor Green " Query for non-local remote IP addresses"
        Write-Host -ForegroundColor Green -NoNewline "`n["; Write-Host -NoNewline "14"; Write-Host -ForegroundColor Green -NoNewline "]"; `
            Write-Host -ForegroundColor Green " Query by remote address - all time"
        Write-Host -ForegroundColor Green -NoNewline "`n["; Write-Host -NoNewline "15"; Write-Host -ForegroundColor Green -NoNewline "]"; `
            Write-Host -ForegroundColor Green " Query by host Name - latest"
        Write-Host -ForegroundColor Green -NoNewline "`n["; Write-Host -NoNewline "16"; Write-Host -ForegroundColor Green -NoNewline "]"; `
            Write-Host -ForegroundColor Green " Query by host name - all time"
        $subMenu3 = Read-Host "`nSelection (leave blank to quit)"
        $timeStamp = Get-Date -Uformat %m%d%y%H%M
        # Option 1
        if($subMenu3 -eq 1){
           1_New_Days
        }
        # Option 2
        if($subMenu3 -eq 2){
           21_Master_List_Date
        }
        # Option 3
        if($subMenu3 -eq 3){
        $agent = "LocalAddressIP"
        $value = read-host -Prompt "Please enter the local IP you want to search for"
        $Title = "Network connections with $value as the local IP"
            23_Agents_latest
        }
        # Option 4
        if($subMenu3 -eq 4){
        $agent = "ForeignAddressIP"
        $value = read-host -Prompt "Please enter the remote IP you want to search for"
        $Title = "Network connections with $value as the remote IP"
            23_Agents_latest
        }
        # Option 5
        if($subMenu3 -eq 5){
        $agent = "ForeignAddressPort"
        $value = read-host -Prompt "Please enter the remote port you want to search for"
        $Title = "Network connections using $value as the remote port"
            23_Agents_latest
        }
        # Option 6
        if($subMenu3 -eq 6){
        $agent = "Protocol"
        $value = read-host -Prompt "Please enter the protocol you want to search for"
        $Title = "Network connections using $value as the protocol"
            23_Agents_latest
        }
        # Option 7
        if($subMenu3 -eq 7){
        $agent = "State"
        $value = "LISTENING"
        $Title = "Network Connections in a $value state"
            23_Agents_latest
        }
        # Option 8
        if($subMenu3 -eq 8){
        $agent = "State"
        $value = "ESTABLISHED"
        $Title = "Network Connections in a $value state"
            23_Agents_latest
        }
        # Option 9
        if($subMenu3 -eq 9){
        $agent = "PID"
        $value = read-host -Prompt "Please enter the PID you want to search for"
        $Title = "Network Connections being used by PID $value"
            23_Agents_latest
        }
        # Option 10
        if($subMenu3 -eq 10){
        $agent = "ProcessName"
        $value = read-host -Prompt "Please enter the Process you want to search for"
        $Title = "Network Connections being used by Process $value"
            23_Agents_latest
        }
        # Option 11
        if($subMenu3 -eq 11){
        $agent = "ForeignAddressPort"
        $NP1 = read-host -Prompt "Enter the first port you whish to exclude and press enter"
        $NP2 = read-host -Prompt "Enter the second port you whish to exclude and press enter. Leave blank if you do not whish to use"
        $NP3 = read-host -Prompt "Enter the third port you whish to exclude and press enter. Leave blank if you do not whish to use"
        $Title = "Ports in use minus $NP1,$NP2 and $NP3"
            25_netstat_noweb
        }
        # Option 12
        if($subMenu3 -eq 12){
        $agent = "ForeignAddressPort"
        $Title = "Network Connections without Ports 0,80, and 443"
        $NP1 = "80"
        $NP2 = "443"
        $NP3 = "0"
            25_netstat_noweb
        }
        # Option 13
        if($subMenu3 -eq 13){
        $agent = "ForeignAddressIP"
        $Title = "Network Connections without Ports 0,80, and 443"
        $NP1 = "$LocalSubnet"
        $NP2 = "0.0.0.0"
        $NP3 = "127.0.0.1"
            25_netstat_noweb
        }
        # Option 14
        if($subMenu3 -eq 14){
        $agent = "ForeignAddressIP"
        $value = read-host -Prompt "Please enter the remote IP you want to search for"
        $Title = "Network connections with $value as the remote IP"
            24_Agent_Query_AllTime
        }
        # Option 15
        if($subMenu3 -eq 15){
            4_By_System_Latest
        }
        # Option 15
        if($subMenu3 -eq 16){
            5_By_System_AllTime
        }
    }
}



#****************************************************************************************
#                                  Functions
#****************************************************************************************
<#
 Function 1 - New Days.  
 This function will query the files for the number of days you specify, and compare them to all of the older files.
 The output will be all new items found in the new files that are not in the old files.
 #>
function 1_New_Days{
#prompt user for the number of days to query
$Days = read-host -Prompt "Please enter the number of days you would like to look for new $Type"

#Identify CSV files created in the last day and combine them
$New_Files = Get-ChildItem -Recurse -path "$Results\*\*\*\_Summary\Summary_$Type.csv" | Sort-object CreationTime -Descending | select -First "$Days" |
foreach-object {Import-Csv -path $PSItem.fullname } | 
Group-Object -Property PSComputerName,$P1,$P2,$P3 |
Select-Object @{Name='PSComputerName'; Expression={$_.Values[0]}},
                   @{Name="$P1"; Expression={$_.Values[1]}},
                   @{Name="$P2"; Expression={$_.Values[2]}},
                   @{Name="$P3"; Expression={$_.Values[3]}}

#Identify CSV documents over a day old
$Old_Files = Get-ChildItem -Recurse -path "$Results\*\*\*\_Summary\Summary_$Type.csv" | Sort-object CreationTime -Descending | select -skip "$Days" |
foreach-object {Import-Csv -path $PSItem.fullname } | 
Group-Object -Property PSComputerName,$P1,$P2,$P3 |
Select-Object @{Name='PSComputerName'; Expression={$_.Values[0]}},
                   @{Name="$P1"; Expression={$_.Values[1]}},
                   @{Name="$P2"; Expression={$_.Values[2]}},
                   @{Name="$P3"; Expression={$_.Values[3]}}

#Set the header names
$headers = 'PSComputername',"$P1","$P2","$P3"

#Create Filter to only show new Objects in compare objects
filter rightside{
param(
        [Parameter(Position=0, Mandatory=$true,ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject]
        $obj
    )

    $obj|?{$_.sideindicator -eq '=>'}

}

#Compare the New_Files to Old_Files and show the items only listed in New_Files
Compare-Object -ReferenceObject @($Old_Files | Select-Object) -DifferenceObject @($New_Files | Select-Object) -Property $headers -PassThru | rightside | Select-Object -Property PSComputerName,$P1,$P2,$P3 | out-GridView -title "New $Print discovered in the last $Days days"
}

<#
Function 2 - Summary by Days
This function will query the files for the number of days you specify and show a report of everything discovered
It is designed to give you a summary of what items are in your environment
#>
function 2_Summary_Days{
#Promt the user for the number of days they want to query
$Days = read-host -Prompt "Please enter the number of days you would like to query for"
# Identify the files created during this time frame and import them
Get-ChildItem -Recurse -Path "$Results\*\*\*\_Summary\Summary_$Type.csv" | Sort-object CreationTime -Descending | select -First "$Days" | # Get each CSV File
     ForEach-Object -Process { 
        Import-csv -path $PSItem.fullname # Import CSV Data
     }  | Sort-Object -property PSComputerName,$P1,$P2,$P3 -Unique |
     Group-Object $P1,$P2,$P3 |
     #select the necessary properties and display in a gridview
     Select-Object Count, @{Name="$P1"; Expression={$_.Values[0]}},
                          @{Name="$P2"; Expression={$_.Values[1]}},
                          @{Name="$P3"; Expression={$_.Values[2]}} | Sort-Object count -descending | Out-GridView -title "$Print discovered during the last $days days"
}

<#
Function 3 - Summary by Date
This function will query the files for the date or date range you specify and show a report of everything discovered.
This can query by Year, month, or day, depending on how you enter the date.
Examples:  
All records for the year 2020 = 2020. 
All Records for March 2020 = 2020-03 
All records for March of every year = *-03
All Records for March 13th 2020 = 2020-03-13
All Records = *
#>
function 3_Summary_Date{
#Prompt user for the date they want to query
 $Date = read-host -Prompt 'Please Enter the date you want to summarize as YYYY-MM-DD.  
Use * to do use a wildcard, or leave the section blank.  
Examples:  
All records for the year 2020 = 2020. 
All Records for March 2020 = 2020-03 
All records for March of every year = *-03
All Records for March 13th 2020 = 2020-03-13
All Records = *
'
$Year,$month,$day = $Date.split('-')

# Pull CSV files from the selected date
Get-ChildItem -Recurse -Path "$Results\$Year\$month\$day\*\Summary_$Type.csv" | # Get each CSV File
     ForEach-Object -Process { 
        Import-csv -path $PSItem.fullname # Import CSV Data
     } | Sort-Object -property PSComputerName,$P1,$P2,$P3 -Unique |
     Group-Object $P1,$P2,$P3 |
     Select-Object Count, @{Name="$P1"; Expression={$_.Values[0]}},
                          @{Name="$P2"; Expression={$_.Values[1]}},
                          @{Name="$P3"; Expression={$_.Values[2]}} | sort-object count -descending | Out-GridView -Title "New $Print discovered in the last in/on $Year-$month-$day"
}

<#
Function 4 - Query the latest results by system name
This function will query the latest results (Yesterdays) and display the items that are on the hostname specified
#>
function 4_By_System_Latest{
#Prompt user for the hostname they want to query for
$hostname = read-host -Prompt "Please Enter the Hostname you wish to search for"

#Pull CSV files created yesterday and filter results based on hostname
$List = Get-ChildItem -Recurse -Path "$Results\*\*\*\_Summary\Summary_$Type.csv" | sort-object CreationTime -Descending | select -First 1 |
     ForEach-Object -Process { 
        Import-Csv -path $PSItem.fullname | where-Object {($_.PSComputerName -match "$Hostname")}
 } 
 #Display results in gridview      
$List | Sort PSComputerName,"$P1","$P2","$P3" -Unique | Out-Gridview -Title "$print on $hostname - Latest"
}

<#
Function 5 - Query all results by system name
This functin will query all results and display the items that have ever been on the hostname specified
#>
function 5_By_System_AllTime{
#Prompt user for the hostname to seach for
$hostname = read-host -Prompt "Please Enter the Hostname you wish to search for"

#Query all CSV files and filter results based on the hostname
$List = Get-ChildItem -Recurse -Path "$Results\*\*\*\_Summary\Summary_$Type.csv" |
     ForEach-Object -Process { 
        Import-Csv -path $PSItem.fullname | where-Object {($_.PSComputerName -match "$Hostname")}
 }
 #Display results in a gridview       
$List | Sort PSComputerName,"$P1","$P2","$P3" -Unique | Out-Gridview -Title "$print on $hostname - All Time"
}

<#
Function 6 - Query for system that have the specified item
This function will query the latest results and identify systems which have the item specified by the user
For example, a specific administrator account, or piece of software installed
#>
function 6_Item_On_System_Latest{
#Prompt user for the item they want to search for
$Item = read-host -Prompt "Please Enter the $Type you wish to search for"

#Query the latest CSV files for the item
$List = Get-ChildItem -Recurse -Path "$Results\*\*\*\_Summary\Summary_$Type.csv" | sort-object CreationTime -Descending | select -First 1 |
     ForEach-Object -Process { 
        Import-Csv -path $PSItem.fullname | where-Object {($_.$P1 -like "*$Item*")  -or ($_.$P2 -like "*$Item*") -or ($_.$P3 -like "*$Item*")}
 } 
# display the results in a gridview      
$List | Sort PSComputerName,"$P1","$P2","$P3" -Unique | Out-Gridview -Title "Workstations with $print"
}

function 8_Item_On_System_alltime{
#Prompt user for the item they want to search for
$Item = read-host -Prompt "Please Enter the $Type you wish to search for"

#Query the latest CSV files for the item
$List = Get-ChildItem -Recurse -Path "$Results\*\*\*\_Summary\Summary_$Type.csv" |
     ForEach-Object -Process { 
        Import-Csv -path $PSItem.fullname | where-Object {($_.$P1 -like "*$Item*")  -or ($_.$P2 -like "*$Item*") -or ($_.$P3 -like "*$Item*")}
 } 
# display the results in a gridview      
$List | Sort PSComputerName,"$P1","$P2","$P3" -Unique | Out-Gridview -Title "Workstations with $print"
}



<#
Function 7 - Query for systems without a specific item
This function will query the latest results for a specific item.  It will then compare the results to the latest master list,
and display the systems that do not have the item you are looking for.
For example, a specific KB installed.  All systems with the KB will be compared to the master list, and those systems without 
it showing as installed  will be displayed
#>
function 7_Item_Not_On_System_Latest{
#Prompt user for the item you are searching for
$Item = read-host -Prompt "Please Enter the $Type you wish to search for"
#Query the latest CSV files for the item, and export the results
$List = Get-ChildItem -Recurse -Path "$Results\*\*\*\_Summary\Summary_$Type.csv" | sort-object CreationTime -Descending | select -First 1 |
     ForEach-Object -Process { 
        Import-Csv -path $PSItem.fullname | where-Object {($_.$P1 -like "*$Item*")  -or ($_.$P2 -like "*$Item*") -or ($_.$P3 -like "*$Item*")}
 } | Sort PSComputerName,"$P1","$P2","$P3" -Unique       

 #Import the latest Master CSV file
$Master = Import-Csv -Path "$Results\*\*\*\_Summary\Summary_master.csv" | sort-object CreationTime -Descending | select -First 1 |

#Create a filter to only show the right side of the output
filter rightside{
param(
        [Parameter(Position=0, Mandatory=$true,ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject]
        $obj
    )

    $obj|?{$_.sideindicator -eq '=>'}

}
#Compare the results of the query to the master list, and output those systems that are on the master list, but not in the query.  
Compare-Object -ReferenceObject $List -DifferenceObject $Master  -Property PSComputerName -PassThru | rightside | Select-Object -Property PSComputerName | out-GridView -title "Computers without $Item as of today"

}

<#
Function 21 - Master list data
This function imports the results of the Master list for the number of days specified
#>
function 21_Master_List_date{
#Prompt user for the number of days to query
$Days = read-host -Prompt "Please enter the number of days you would like to query for."
#Import the CSV files, and sort by Computer Name
$files = Get-ChildItem -Recurse -Path "$Results\*\*\*\_Summary\Summary_$Type.csv" | Sort-object CreationTime -Descending | select -First "$Days" | # Get each CSV File
     ForEach-Object -Process { 
        Import-csv -path $_ } 

        
  # Output the list in a gridview       
  $files | Out-Gridview -Title "$Print discovered during the last $days days"
  }

<#
Function 23 - Agent Query
This function searches the latest results for the clients with or without the agent you are searching for for the master list.  Agents include SCCM, McAfee, and on the domain.
It is also used for Netstat queries for ports, protocols, state, PID, EXE queries
#>
function 23_Agents_Latest{
$list = Get-ChildItem -Recurse -Path "$Results\*\*\*\_Summary\Summary_$Type.csv" | sort-object CreationTime -Descending | select -First 1 |
     ForEach-Object -Process { 
        Import-csv -path $_ | where-object {($_.$Agent -like "*$value*")} 
 }       
         
  $list | Out-Gridview -Title "$Title"
  }

  function 24_Agent_Query_AllTime{
  $list = Get-ChildItem -Recurse -Path "$Results\*\*\*\_Summary\Summary_$Type.csv" |
     ForEach-Object -Process { 
        Import-csv -path $_ | where-object {($_.$Agent -like "*$value*")} 
 }       
         
  $list | Out-Gridview -Title "$Title"

  }



<#
Function 25 - Netstat query with filtered results
option 11 - prompts user for three custom properties to filter out
option 12 - removes ports 80, 443, and 0
option 13 - removes local IP subnet, 0.0.0.0, and 127.0.0.1
#>
function 25_netstat_noweb{
  $list = Get-ChildItem -Recurse -Path "$Results\*\*\*\_Summary\Summary_$Type.csv" | sort-object CreationTime -Descending | select -First 1 | # Get each CSV File
     ForEach-Object -Process { 
        Import-csv -path $_ | where-object {($_.$Agent -notlike "$NP1") -and ($_.$Agent -notlike "*$NP2*") -and ($_.$Agent -notlike "*$NP3*")} 
 }       
         
  $list | Out-Gridview -Title "$Title"
  }

mainMenu

<#
Summary of Changes

27 APR 2020
    Added DNS and sessions queries.  Fixed function 1 to work with NULL values
20 May 2020
    Added the variabes.txt for changing variables
#>