#užrašome API raktą
$API = Get-Content -path "C:/users/edwin/Documents/key.txt"

# užrašome savo IP
$IP = (Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object { $_.InterfaceAlias -match "Wi|Wireless" -and $_.IPAddress -notlike "169.*" -and $_.IPAddress -ne "127.0.0.1" } |
        Select-Object -First 1 -ExpandProperty IPAddress)

[int[]]$portsToCheck = (22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3389, 5985, 5986, 1433, 1521, 3306, 5432, 5900, 6379, 8080, 8443, 9200, 27017)

    $menu=@"
    1 Check connection
    2 Next connection
    3 Quit
"@

<#
.SYNOPSIS
Checks your network for suspicious connections.
.DESCRIPTION
This function checks active network connections and identifies suspicious ones.
.PARAMETER ports
Specifies which ports to check.
.PARAMETER IPv4
Specifies the local IPv4 address.
.PARAMETER Color
Highlights safe and not safe connections
.INPUTS
[int[]], [string], [switch]
.OUTPUTS
[List of suspicious connections]
#>
function Check-Suspicious-Connections{
    
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "Medium")]
    param(
       [Parameter(Mandatory = $true, HelpMessage = "Range of ports to check")]
       [ValidateRange(1,65535)][int[]]$ports,
       [Parameter(Mandatory = $true, HelpMessage = "Your local IPv4 address")]
       [ValidatePattern ("^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")][string]$IPv4,
       [Parameter(HelpMessage = "Block found connections")][switch]$Color
    )
    
    $tcpConnections = Get-NetTCPConnection | Where-Object { $_.State -eq "Established" -and $_.LocalAddress -eq $IPv4 }

    $connections = $tcpConnections | Where-Object {
        ($ports -notcontains $_.LocalPort) -or
        ($_.RemoteAddress -notlike "10.*" -and $_.RemoteAddress -notlike "192.168.*" -and $_.RemoteAddress -notlike "172.16.*" -and $_.RemoteAddress -ne "127.0.0.1")
    } | ForEach-Object {
        $procName = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name
        [PSCustomObject]@{
            Protocol       = "TCP"
            LocalAddress   = $_.LocalAddress
            LocalPort      = $_.LocalPort
            RemoteAddress  = $_.RemoteAddress
            RemotePort     = $_.RemotePort
            State          = $_.State
            ProcessId      = $_.OwningProcess
            ProcessName    = $procName
        }
    }
  
    if ($connections.Count -eq 0) {
        Write-Host "No suspicious connections found." -ForegroundColor Green
        return $connections
    }
 
    for ($i = 0; $i -lt $connections.Count; $i++) {
      
        $connectionColor = if ($Color) { "Cyan" } else { "White" }
        Write-Host ($connections[$i] | Format-List | Out-String) -ForegroundColor $connectionColor
        Write-Host $menu
      
        do {
            [int]$in = Read-Host "Please, choose [1-3]"
            $validInput = $true
            switch($in) {
                1 {
                    $ip = $connections[$i].RemoteAddress
                    $uri = "https://api.abuseipdb.com/api/v2/check?ipAddress=$ip&maxAgeInDays=90&verbose"
                    $response = Invoke-WebRequest -Uri $uri -Method GET `
                        -Headers @{
                            "Key" = $API
                            "Accept" = "application/json"
                        }
                    $data = $response.Content | ConvertFrom-Json

                    $ipDetails = [PSCustomObject]@{
                        IPAddress = $data.data.ipAddress
                        AbuseConfidenceScore = $data.data.abuseConfidenceScore
                        CountryCode = $data.data.countryCode
                        UsageType = $data.data.usageType
                        ISP = $data.data.isp
                        Domain = $data.data.domain
                        IsTor = $data.data.isTor
                        TotalReports = $data.data.totalReports
                        LastReportedAt = $data.data.lastReportedAt
                    }


                    $score = $data.data.abuseConfidenceScore
                    $scoreColor = if ($score -gt 10) { "Red" } elseif ($score -eq 0) { "Green" } else { "Yellow" }
                    Write-Host "Abuse Confidence Score for " $ip ": $score" -ForegroundColor $scoreColor
                    if ($data.data.totalReports -gt 0) {
                        Write-Host "Reports: $($data.data.totalReports)"
                        $ipDetails | Format-List | Out-Host

                    } else {
                        Write-Host "No reports found."
                    }
                }
                2 { continue }
                3 { return $connections }
                default {
                    Write-Host -ForegroundColor Red "Invalid entry"
                    $validInput = $false
                }
            }
        } while (-not $validInput)
    }
}


Check-Suspicious-Connections -ports $portsToCheck -IPv4 $IP -Color
