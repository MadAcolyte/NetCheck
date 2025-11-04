# PowerShell Script for Checking Network Connections

## Purpose
This script was created as a university project to explore PowerShell scripting and basic network analysis.  
It checks active network connections and uses **AbuseIPDB** to identify potentially suspicious remote hosts.

## Key Functions
- Lists active TCP connections on the local IPv4 interface  
- Ignores trusted private networks and common service ports  
- Queries the **AbuseIPDB API** for information about external IPs  
- Shows confidence scores with color-coded output  
- Includes an interactive menu to review multiple connections

## Technical Details
- Uses PowerShell cmdlets: `Get-NetTCPConnection`, `Invoke-WebRequest`, and `Get-Process`  
- Parses JSON responses from a REST API using `ConvertFrom-Json`  
- Demonstrates basic use of parameters, validation, and formatted output  

## Usage
```powershell
.\NetCheck.ps1
