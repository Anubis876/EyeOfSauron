# EyeOfSauron

The Eye of Sauron is a tool created by Adam Clark, David Betteridge, and myself, consisting of three PowerShell scripts designed to collect and analyze data from Windows systems.  There are two primary ways of using the tool.  The first approach is to have it run daily, creating a record to compare recent findings to previous results to search for anomalies by identifying new activity.  The second option is to deploy it in a one-time capacity to collect data from across an enterprise to aid in containing and eradicating a specific incident by searching for IOCs and using data stacking to identify anomalies.  This research will attempt to identify changes by comparing previous results, as well as data stacking, to identify one-offs in the environment.

The data sets collected by the tool fall into the classes in the below list.  These classes are each saved in individual CSV files, and later summarized for enhanced querying.  The capabilities of PowerShell enable the queries to be adjusted as necessary to meet the needs of the organization and collect only relevant data.  Not all categories are designed for threat hunting and are instead intended more for compliance checks, such as installed Windows updates.  
 
•	Members of the Local Admin Group
•	Local Accounts on system
•	DNS cache
•	Netstat details
•	New Executables in the last 24hrs
•	New Files in the previous 24hrs
•	Current out Bound sessions
•	Printers
•	Running processes
•	Installed applications
•	Services
•	Available Shares
•	Startup entries in the registry
•	Scheduled tasks
•	Installed Windows updates
•	Master 


Collection Script
This script runs on each endpoint to collect the data points mentioned above. It uses windows management instrumentation (WMI) and registry queries to gather the majority of data and saves it to a specified share.  Ideally, this script runs daily using a scheduled task or other means of automation, to provide a history of results for use in finding new additions. The Variables.txt file shares variables between all three scripts, preventing the need to edit them individually and ensuring consistency.  

Summarization Script
The summarization script is run after all of the systems have run the collection script.  This script has three functions; first, it summarizes the results gathered by the collection script and combines them into Summary CSV files.  The second function is to compare the most recent results with the most recent previous results, exporting all new findings to an excel spreadsheet for easy analysis.  The third function is to conduct maintenance, which deletes the individual system data and the summarized data according to the specified timeframes in the variables.txt file.
The longer the summary files are maintained, the better the capability to search for past findings and to find previously missed indicators.  This history can also aid in identifying normal behavior, such as running processes, or established network connections.  The Eye can combine results from multiple days to identify unusual activity, such as showing all processes that have run in the last seven days, or new local accounts detected during the previous 30 days.

User Interface Script 
The user interface script is The Eye and is used to query the collected data for further analysis using a series of menus and pre-defined queries.  The menu and query method allows people with little to no knowledge of PowerShell scripting to use the tool effectively. In contrast, those with PowerShell scripting knowledge can easily add additional queries to get their desired results.  
