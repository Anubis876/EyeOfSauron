<#
Created by Timothy Hoffman, timothy.hoffman.83@gmail.com
Requires export-excel module found at https://devblogs.microsoft.com/scripting/introducing-the-powershell-excel-module-2/

This script is designed to work with the Collector and eye scripts.

This script is used to summarize the results of the collection script so they can more easily be quiered by the eye.

best practice is to run this script daily at 11:00 PM.  This gives it time to summarize all results from the day, and provide them to be used by the Eye.

Once sumarized, it will compare the results from today to the results from yesterday.  Any new items will be added to the summary xlsx in teh Summary
folder for that day.  Each type will be added to a different tab in the worksheet.


It also includes options to cleanup the results in order to reduce disk space.
there are three options for the cleanup.  The first will remove all of the individual system files after they are summarized every day.
The second option is to set the $Days variable below.  This will remove all individual system files that are older than the number of days you specify.
The third option is to set the $Days_Summary variable below.  This will remove the summary files that are older than the days you specify.
#>

#import-module ".\ImportExcel-master\ImportExcel.psm1"

#SET GLOBAL ERROR HANDLING
$ErrorActionPreference = “silentlycontinue”

#****************************************************************************************
#                         Pull the variables from variables.txt
#****************************************************************************************

#Pull variables from variables.txt
Get-Content "$PSScriptRoot\Variables.txt" | ForEach-Object{
    $var = $_.Split('=')
    New-Variable -Name $var[0] -Value $var[1]
}


# Change these variables to set the number of days to maintain files
# Alternatively you can uncomment the section below which will remove the individually
# collected files daily after they are summarized

#set this to the number of days to keep the individual files collected by the collector script
$Days = 3
#set this to the number of days to keep the summary files
$Days_Summary = 365

# Variables for daily email alerts
$To_Email = "me@work.com"
$From_Email = "Eye@work.com"
$SMTPServer = "smtp.server.work.me"
$Subject = "Daily report from Eye of Sauron"



#****************************************************************************************
#                  These variables do not need to be adjusted
#****************************************************************************************
$DATE_DAY = Get-Date -format "dd"
$DATE_MONTH = Get-Date -format "MM"
$DATE_YEAR = Get-Date -format "yyyy"
$Yesterday_Day = (get-date).date.adddays(-1).ToString("dd")
$Yesterday_Month = (get-date).date.adddays(-1).ToString("MM")
$Yesterday_year = (get-date).date.adddays(-1).ToString("yyyy")
$DATE = Get-Date -format "yyyy-MM-dd"
$yestderday = (get-date).date.adddays(-1).ToString("yyyy-MM-dd")
$folder = "$Results\*\*\*"
$types = "Admins","LocalAccounts","Master","NetStat","NewEXE","NewFile","Printers","Processes","Products","Services","Shares","Startup","Updates","DNS","OutSessions","Tasks"


#****************************************************************************************
#                              Summarizes Function.
#****************************************************************************************

function Summarize{
New-Item -Path "$folder" -name _Summary -ItemType Directory -errorAction SilentlyContinue | Out-Null
Get-ChildItem -Path "$dir\*\*_$type.csv" -Exclude "*Summary*" | Select-Object -ExpandProperty Fullname | Import-Csv | Export-Csv "$dir\_Summary\Summary_$type.csv" -NoTypeInformation -Append
}

#****************************************************************************************
#                       Filter to only show right side of results.
#****************************************************************************************

filter rightside{
param(
        [Parameter(Position=0, Mandatory=$true,ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject]
        $obj
    )

    $obj|?{$_.sideindicator -eq '=>'}

}


#****************************************************************************************
#                  Run Summarize against un-summarized directories
#****************************************************************************************

# Check the directories for each day, and summarize the results into CSVs for each type 
# Skips directories that have already been summarized.  If a single summarized file has 
# been deleted, will re-summarize that type.                                            

foreach ( $dir in (get-item -Path "$folder" | ?{$_.PSIsContainer})){
foreach ($type in $types){
    IF (!(Test-Path -Path "$dir\_Summary\Summary_$type.csv")){
         Summarize
         }
         }
  }

#****************************************************************************************
#                              Compare Results
#****************************************************************************************
# Compares the summary from today to the one from yesterday.  
# Compiles the results into one .xlsx document with each type on an individual tab
# 


$New_Master = Import-csv -path "$Results\$DATE_YEAR\$DATE_MONTH\$DATE_DAY\_Summary\Summary_Master.csv"
$Old_Master = Import-csv -path "$Results\$Yesterday_year\$Yesterday_Month\$Yesterday_Day\_Summary\Summary_Master.csv"
$New_Comps = Compare-Object -ReferenceObject @($Old_Master | select-object) -DifferenceObject @($New_Master | select-object) -PassThru | rightside

if ($New_Comps) { $New_Comps | Export-Excel -workSheetName "Master" -excludeProperty SideIndicator -path "$Results\$DATE_YEAR\$DATE_MONTH\$DATE_DAY\_Summary\Summary.xlsx"}



foreach ($type in $Types | Where-Object {$type -ne "Master"}){

#  Pulls the summary file from today

$New_Files = Get-ChildItem -Recurse -path "$Results\$DATE_YEAR\$DATE_MONTH\$DATE_DAY\_Summary\Summary_$Type.csv" |  
foreach-object {Import-Csv -path $PSItem.fullname | Where-Object {$_.PSComputerName -ne $New_Comps.PSComputerName}}
 


#  Pulls the summary file from yesterday

$Old_Files = Get-ChildItem -Recurse -path "$Results\$Yesterday_year\$Yesterday_Month\$Yesterday_Day\_Summary\Summary_$Type.csv" | 
foreach-object {Import-Csv -path $PSItem.fullname}



# Compares the new files to the old files to look for differences

$compare = Compare-Object -ReferenceObject @($Old_Files | Select-Object) -DifferenceObject @($New_Files | Select-object) -PassThru  | rightside

if ($compare) {$compare | Export-Excel -workSheetName "$Type" -excludeProperty SideIndicator,date -path "$Results\$DATE_YEAR\$DATE_MONTH\$DATE_DAY\_Summary\Summary.xlsx"}
 }

#****************************************************************************************
#                              Email Results
#****************************************************************************************

#Send-MailMessage -From $From_Email -To $To_Email -SmtpServer $SMTPServer -Subject $Subject -Body "Here is the daily report for $date" -Attachments "$Results\$DATE_YEAR\$DATE_MONTH\$DATE_DAY\_Summary\Summary.xlsx"

#****************************************************************************************
#                             Clean-up Options
#****************************************************************************************

# Optional process to delete results in order to maintain disk space
# Could result in lost data if the summarized results are lost.
# un-comment the cleanup option you want to use


# delete the days results with the exception of the summary folder.  This will remove all individual results daily
<#
Get-ChildItem -path $folder -Recurse | 
Select -ExpandProperty FullName |
Where {$_ -notlike "*Summary*"} |
sort length -Descending |
Remove-Item -force
#>
#****************************************************************************************


# Deletes the individually collected files that are older than the $Days variable 
# set at the beginning of the script

Get-ChildItem -path $folder -Recurse -exclude *Summary* | Where-Object {$_.CreationTime  -le (get-Date).Date.AddDays(-$SUMDays)} |
Select -ExpandProperty FullName |
Where {$_ -notlike "*Summary*"} |
sort length -Descending |
Remove-Item -force

#****************************************************************************************


# Deletes all files to include summary files that are older than the $Days_Summary variable 
# set at the beginning of the script

Get-ChildItem -path $folder -Recurse -Include *Summary* | Where-Object {$_.CreationTime  -le (get-Date).Date.AddDays(-$SUMDays_Summary)} |
Select -ExpandProperty FullName |
 sort length -Descending |
Remove-Item -force

<#
Summary of Changes

28-APR-2020
    Adjusted Summary spreadsheet to exclude items from new computers, except for in the Master tab.
    Edited Summary output to only create tabs that contain content.
#>