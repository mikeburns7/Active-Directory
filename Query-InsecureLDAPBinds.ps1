<#-----------------------------------------------------------------------------
Author: Mike Burns
Forked from Russell Tomkin - Microsoft Premier Field Engineer
Name:           Query-InsecureLDAPBinds.ps1
Description:    Exports a CSV from the specified domain controller containing 
                all Unsgined and Clear-text LDAP binds made to the DC by
                extracting Event 2889 from the "Directory Services" event log.
                This extract can be used to identifiy applications and hosts
                performing weak and insecure LDAP binds.
                
                The events extracted by the script are only generated when
                LDAP diagnostics are enabled as per below. 
                https://technet.microsoft.com/en-us/library/dd941829(v=ws.10).aspx
                
Usage:          .\Query-InsecureLDAPBinds.ps1 [-ComputerName <DomainController>]
                     [-Hours <Hours>]
                Execute the script against the DomainController which has had
                the diagnostic logging enabled. By default, the script will 
                return the past 24 hours worth of events. You can increase or 
                decrease this value as required
Date:           1.0 - 27-01-2016 Russell Tomkins - Initial Release
                1.1 - 27-01-2016 Russell Tomkins - Removed Type Info from CSV  
		1.2 - 23-01-2019 Mike Burns - Added Multi DC and Registry Key Checking

-----------------------------------------------------------------------------#>
# -----------------------------------------------------------------------------
# Begin Main Script
# -----------------------------------------------------------------------------
# Prepare Variables
Param (
        [parameter(Mandatory=$false,Position=0)][String]$ComputerName = "localhost",
        [parameter(Mandatory=$false,Position=1)][Int]$Hours = 24)

$allDCs = (Get-ADForest).Domains | %{ Get-ADDomainController -Filter * -Server $_ }

# Create an Array to hold our returnedvValues
[System.Collections.ArrayList]$InsecureLDAPBinds = @()


ForEach($dc in $allDCs){

	$ComputerName = $dc.HostName 
	$locamachine = ([System.Net.Dns]::GetHostByName(($env:computerName))).Hostname
#function to check if registry key exists and or the proper value for LDAP Interface Logging
<##
	#Run function on remote machine
	If ($localmachine -ne $comptuername)
	{
	Invoke-Command -ComputerName $ComputerName -ScriptBlock ${Function:CheckLDAPRegistry}
	}
	#Run funcation locally
	Else{
		CheckLDAPRegistry
	}
	
##>

	# Grab the appropriate event entries
	try{
	$Events = Get-WinEvent -ComputerName $ComputerName -FilterHashtable @{Logname='Directory Service';Id=2889; StartTime=(get-date).AddHours("-$Hours")} -ErrorAction Stop

	}
	catch [Exception] {
		if ($_.Exception -match "No events were found that match the specified selection criteria") {
		$Events = $null
			 }
	    }
	# Loop through each event and output the 
	ForEach ($Event in $Events) { 
		$eventXML = [xml]$Event.ToXml()

		# Build Our Values
	    $Server = $ComputerName
		$Client = ($eventXML.event.EventData.Data[0])
		$IPAddress = $Client.SubString(0,$Client.LastIndexOf(":")) #Accomodates for IPV6 Addresses
		$Port = $Client.SubString($Client.LastIndexOf(":")+1) #Accomodates for IPV6 Addresses
		$User = $eventXML.event.EventData.Data[1]
		Switch ($eventXML.event.EventData.Data[2])
			{
			0 {$BindType = "Unsigned"}
			1 {$BindType = "Simple"}
			}

		# Add Them To a Row in our Array
		$Row = "" | select Server,IPAddress,Port,User,BindType
		$Row.Server = $Server
	    $Row.IPAddress = $IPAddress
		$Row.Port = $Port
		$Row.User = $User
		$Row.BindType = $BindType

		# Add the row to our Array
		$InsecureLDAPBinds += $Row


	}
	
	# Dump it all out to a CSV.
	Write-Host $InsecureLDAPBinds.Count "records saved to .\InsecureLDAPBinds.csv for Domain Controller" $ComputerName
	$InsecureLDAPBinds | Export-CSV -NoTypeInformation .\InsecureLDAPBinds.csv -append

	#clear array
	for ($i=0; $i -lt $InsecureLDAPBinds.count; $i++) {
		$InsecureLDAPBinds.removeat($i)
		$i--
	}


}
# -----------------------------------------------------------------------------
# End of Main Script
# -------------------
Function CheckLDAPRegistry() {
$KeyCheck = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics' 

	if (-not $KeyCheck)
	{
	Write-Host -f red "Registry Key Not Found. Please Check for Updates"
	 Quit
	}

	$value = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics' -Name '16 LDAP Interface Events').'16 LDAP Interface Events'
	  $value

	If ($value -lt 2){

	 Write-host -f red "Registry Key Updated To Enable LDAP Interface Logging. Please Run Again in 24 Hours to Analayze Results"
	 Set-Itemproperty -path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics' -Name '16 LDAP Interface Events' -value '2'

}
