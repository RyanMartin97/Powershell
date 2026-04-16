#Requires -Modules Az.Accounts, Az.Network
<#
.SYNOPSIS
    Exports all Network Security Group (NSG) rules from an Azure subscription.

.DESCRIPTION
    Connects to Azure, iterates every NSG in the target subscription, and exports
    both inbound and outbound security rules (including default rules) to:
      - NSG_Rules_<timestamp>.csv   (flat, easy to open in Excel)
      - NSG_Rules_<timestamp>.json  (full fidelity, one entry per NSG)

.PARAMETER SubscriptionId
    The Azure Subscription ID to target. If omitted the script uses the currently
    active subscription (or prompts you to select one).

.PARAMETER OutputDir
    Directory to write output files. Defaults to the current directory.

.PARAMETER IncludeDefaultRules
    Switch. When set, Azure's built-in default rules are included in the export.
    By default only custom rules are exported.

.EXAMPLE
    .\Export-AzureNSGRules.ps1

.EXAMPLE
    .\Export-AzureNSGRules.ps1 -SubscriptionId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -IncludeDefaultRules

.EXAMPLE
    .\Export-AzureNSGRules.ps1 -OutputDir "C:\Reports" -IncludeDefaultRules
#>

[CmdletBinding()]
param (
    [Parameter()]
    [string]$SubscriptionId,

    [Parameter()]
    [string]$OutputDir = (Get-Location).Path,

    [Parameter()]
    [switch]$IncludeDefaultRules
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Helper: ensure output directory exists
# ---------------------------------------------------------------------------
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

$timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
$csvPath    = Join-Path $OutputDir "NSG_Rules_$timestamp.csv"
$jsonPath   = Join-Path $OutputDir "NSG_Rules_$timestamp.json"

# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------
Write-Host "`n[1/4] Checking Azure authentication..." -ForegroundColor Cyan

$context = Get-AzContext -ErrorAction SilentlyContinue
if (-not $context) {
    Write-Host "     No active session found – launching Connect-AzAccount..." -ForegroundColor Yellow
    Connect-AzAccount | Out-Null
    $context = Get-AzContext
}

# ---------------------------------------------------------------------------
# Subscription selection
# ---------------------------------------------------------------------------
Write-Host "[2/4] Selecting subscription..." -ForegroundColor Cyan

if ($SubscriptionId) {
    Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
    $context = Get-AzContext
} else {
    $subs = Get-AzSubscription | Where-Object { $_.State -eq "Enabled" }
    if ($subs.Count -eq 0) {
        Write-Error "No enabled subscriptions found for this account."
        exit 1
    }
    if ($subs.Count -gt 1) {
        Write-Host "`n     Available subscriptions:" -ForegroundColor White
        for ($i = 0; $i -lt $subs.Count; $i++) {
            Write-Host ("     [{0}]  {1}  ({2})" -f $i, $subs[$i].Name, $subs[$i].Id)
        }
        $choice = Read-Host "`n     Enter number to select subscription"
        Set-AzContext -SubscriptionId $subs[$choice].Id | Out-Null
        $context = Get-AzContext
    }
}

Write-Host ("     Using: {0}  ({1})" -f $context.Subscription.Name, $context.Subscription.Id) -ForegroundColor Green

# ---------------------------------------------------------------------------
# Fetch NSGs
# ---------------------------------------------------------------------------
Write-Host "[3/4] Fetching NSGs..." -ForegroundColor Cyan

$allNSGs = Get-AzNetworkSecurityGroup
if ($allNSGs.Count -eq 0) {
    Write-Warning "No NSGs found in subscription '$($context.Subscription.Name)'."
    exit 0
}
Write-Host ("     Found {0} NSG(s)." -f $allNSGs.Count) -ForegroundColor Green

# ---------------------------------------------------------------------------
# Build rule objects
# ---------------------------------------------------------------------------
Write-Host "[4/4] Processing rules..." -ForegroundColor Cyan

$csvRows    = [System.Collections.Generic.List[PSCustomObject]]::new()
$jsonOutput = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($nsg in $allNSGs) {
    $associatedSubnets = ($nsg.Subnets | ForEach-Object { $_.Id.Split("/")[-1] }) -join "; "
    $associatedNics    = ($nsg.NetworkInterfaces | ForEach-Object { $_.Id.Split("/")[-1] }) -join "; "

    # Choose which rule collections to include
    $ruleSets = @()
    $ruleSets += $nsg.SecurityRules   # custom rules

    if ($IncludeDefaultRules) {
        $ruleSets += $nsg.DefaultSecurityRules
    }

    $nsgRuleList = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($rule in $ruleSets) {
        $isDefault = $nsg.DefaultSecurityRules.Name -contains $rule.Name

        # Safely resolve a property that may be a plural list, a singular scalar, or absent.
        # Returns a comma-separated string, or an empty string if nothing is set.
        function Resolve-RuleField {
            param($Rule, [string]$PluralProp, [string]$SingularProp)
            $pluralVal = $null
            if ($Rule.PSObject.Properties[$PluralProp]) {
                $pluralVal = $Rule.$PluralProp
            }
            if ($pluralVal -and $pluralVal.Count -gt 0) {
                return ($pluralVal -join ", ")
            }
            $singularVal = $null
            if ($Rule.PSObject.Properties[$SingularProp]) {
                $singularVal = $Rule.$SingularProp
            }
            if ($singularVal) { return $singularVal }
            return ""
        }

        $ruleObj = [PSCustomObject]@{
            # NSG context
            SubscriptionId      = $context.Subscription.Id
            SubscriptionName    = $context.Subscription.Name
            ResourceGroup       = $nsg.ResourceGroupName
            NSGName             = $nsg.Name
            NSGLocation         = $nsg.Location
            AssociatedSubnets   = $associatedSubnets
            AssociatedNICs      = $associatedNics
            # Rule identity
            RuleName            = $rule.Name
            IsDefaultRule       = $isDefault
            Priority            = $rule.Priority
            Direction           = $rule.Direction
            Access              = $rule.Access          # Allow / Deny
            Protocol            = $rule.Protocol        # TCP / UDP / ICMP / * etc.
            # Source
            SourceAddressPrefix  = Resolve-RuleField $rule "SourceAddressPrefixes"    "SourceAddressPrefix"
            SourcePortRange      = Resolve-RuleField $rule "SourcePortRanges"         "SourcePortRange"
            # Destination
            DestinationAddressPrefix = Resolve-RuleField $rule "DestinationAddressPrefixes" "DestinationAddressPrefix"
            DestinationPortRange     = Resolve-RuleField $rule "DestinationPortRanges"      "DestinationPortRange"
            # Application Security Groups
                SourceASGs          = ($(if ($rule.PSObject.Properties["SourceApplicationSecurityGroups"]) `
                                        { $rule.SourceApplicationSecurityGroups } else { @() }) `
                                        | ForEach-Object { $_.Id.Split("/")[-1] }) -join "; "
            DestinationASGs     = ($(if ($rule.PSObject.Properties["DestinationApplicationSecurityGroups"]) `
                                        { $rule.DestinationApplicationSecurityGroups } else { @() }) `
                                        | ForEach-Object { $_.Id.Split("/")[-1] }) -join "; "
            ProvisioningState   = if ($rule.PSObject.Properties["ProvisioningState"]) { $rule.ProvisioningState } else { "" }
            Description         = if ($rule.PSObject.Properties["Description"])       { $rule.Description }       else { "" }
        }

        $nsgRuleList.Add($ruleObj)
        $csvRows.Add($ruleObj)
    }

    $jsonOutput.Add([PSCustomObject]@{
        NSGName           = $nsg.Name
        ResourceGroup     = $nsg.ResourceGroupName
        Location          = $nsg.Location
        AssociatedSubnets = $associatedSubnets
        AssociatedNICs    = $associatedNics
        Rules             = $nsgRuleList
    })

    $customCount  = ($nsgRuleList | Where-Object { -not $_.IsDefaultRule }).Count
    $defaultCount = ($nsgRuleList | Where-Object { $_.IsDefaultRule }).Count
    Write-Host ("     {0,-40}  custom: {1,3}  default: {2,3}" -f $nsg.Name, $customCount, $defaultCount)
}

# ---------------------------------------------------------------------------
# Export CSV
# ---------------------------------------------------------------------------
$csvRows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
Write-Host "`nCSV  saved → $csvPath" -ForegroundColor Green

# ---------------------------------------------------------------------------
# Export JSON
# ---------------------------------------------------------------------------
$jsonOutput | ConvertTo-Json -Depth 6 | Out-File -FilePath $jsonPath -Encoding UTF8
Write-Host "JSON saved → $jsonPath" -ForegroundColor Green

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
$totalCustom  = ($csvRows | Where-Object { -not $_.IsDefaultRule }).Count
$totalDefault = ($csvRows | Where-Object { $_.IsDefaultRule }).Count

Write-Host "`n--- Summary ---" -ForegroundColor Cyan
Write-Host ("  Subscription : {0}" -f $context.Subscription.Name)
Write-Host ("  NSGs         : {0}" -f $allNSGs.Count)
Write-Host ("  Custom rules : {0}" -f $totalCustom)
if ($IncludeDefaultRules) {
    Write-Host ("  Default rules: {0}" -f $totalDefault)
}
Write-Host ""
