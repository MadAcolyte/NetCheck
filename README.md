#PowerShell script for checking network connections

#Purpose
Automates inspection of network connections and integrates with AbuseIPDB to identify potentially malicious hosts. Demonstrates PowerShell proficiency, API integration, and network analysis.

#Key Functions

-Enumerates established TCP connections bound to the active IPv4 interface.

-Filters out trusted private networks and common service ports.

-Queries AbuseIPDB API for threat intelligence on remote IPs.

-Displays confidence scores with color-coded feedback.

-Interactive menu to inspect multiple connections sequentially.

#Technical Highlights

-Implements parameter validation, structured output, and optional color highlighting.

-Uses PowerShell cmdlets: Get-NetTCPConnection, Invoke-WebRequest, Get-Process.

-Applies REST API interaction and JSON parsing via ConvertFrom-Json.
