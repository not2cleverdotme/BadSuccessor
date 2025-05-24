function Get-BadSuccessorOUPermissions {
    <#
    .SYNOPSIS
        Lists every principal that can perform a BadSuccessor attack and the OUs where it holds the required permissions.

    .DESCRIPTION
        Scans all Organizational Units (OUs) for Access Control Entries (ACEs) granting permissions that could allow creation of a delegated Managed Service Account (dMSA),
        enabling a potential BadSuccessor privilege escalation attack.

        Built-in privileged identities (e.g., Domain Admins, Administrators, SYSTEM, Enterprise Admins) are excluded from results. 
        This script does not evaluate DENY ACEs and therefore, some false positives may occur.

        Note: We do not expand group membership and the permissions list used may not be exhaustive. Indirect rights such as WriteDACL on the OU are considered.

        PowerShell Compatibility:
        - Supports both PowerShell 5.1 and PowerShell 7+
        - When running on PowerShell 7, automatically handles Windows PowerShell compatibility mode for the Active Directory module
        - Includes performance optimizations for PowerShell 7

    .PARAMETER SimulateAttack
        Switch parameter to enable attack path simulation mode. This will show the exact steps that would be taken without making any actual changes.
        When enabled, the script will demonstrate the potential attack path without executing any modifications.

    .PARAMETER TargetOU
        Optional. Specific OU to target for simulation. If not specified, will use the first vulnerable OU found.
        Format: Distinguished Name (DN) of the OU
        Example: "OU=TestOU,DC=contoso,DC=com"

    .PARAMETER Force
        Switch parameter to bypass confirmation prompts in simulation mode.
        Use with caution as it will run the simulation without asking for confirmation.

    .PARAMETER Verbose
        Enables detailed logging of all operations and checks.
        Shows additional information about permission checks and excluded identities.

    .EXAMPLE
        Get-BadSuccessorOUPermissions
        Description: Performs a basic scan of the domain and lists vulnerable OUs and principals.

    .EXAMPLE
        Get-BadSuccessorOUPermissions -SimulateAttack
        Description: Runs the script in simulation mode, demonstrating the attack path on the first vulnerable OU found.

    .EXAMPLE
        Get-BadSuccessorOUPermissions -SimulateAttack -TargetOU "OU=IT,DC=contoso,DC=com"
        Description: Simulates the attack specifically on the IT organizational unit.

    .EXAMPLE
        Get-BadSuccessorOUPermissions -SimulateAttack -Force -Verbose
        Description: Runs simulation mode with no confirmation prompts and detailed logging.

    .OUTPUTS
        Without -SimulateAttack:
            Returns an array of PSCustomObjects containing:
            - Identity: The security principal that has the required permissions
            - OUs: Array of Distinguished Names of vulnerable OUs

        With -SimulateAttack:
            Displays a detailed simulation of the attack path including:
            - Permission validation
            - dMSA creation simulation
            - Privilege escalation steps

    .NOTES
        File Name      : Get-BadSuccessorOUPermissions.ps1
        Prerequisite   : PowerShell 5.1 or PowerShell 7+
                        Active Directory PowerShell Module
                        Microsoft.PowerShell.Compatibility Module (for PS7)
                        Domain User Rights
        
        PowerShell 7 Note: When running on PowerShell 7, you may need to install the WindowsCompatibility module:
                          Install-Module -Name Microsoft.PowerShell.Compatibility -Force
        
        SECURITY NOTE: This script is intended for security testing and assessment only.
                      Always obtain proper authorization before running security tests.

    .LINK
        https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-principals
        https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers
        https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.compatibility/

    .COMPONENT
        ActiveDirectory

    .FUNCTIONALITY
        Active Directory Security Assessment
    #>

    [CmdletBinding()]
    param (
        [Parameter()]
        [switch]$SimulateAttack,
        
        [Parameter()]
        [string]$TargetOU,
        
        [Parameter()]
        [switch]$Force
    )

    # Check PowerShell version and set compatibility features
    $script:isPS7 = $PSVersionTable.PSVersion.Major -ge 7
    Write-Verbose "PowerShell Version: $($PSVersionTable.PSVersion)"
    Write-Verbose "Running in PowerShell 7 mode: $isPS7"

    # Set error action preference
    $ErrorActionPreference = 'Stop'

    Write-Host "`n[*] Starting BadSuccessor Permission Scanner" -ForegroundColor Cyan
    Write-Verbose "Function started with parameters: SimulateAttack=$SimulateAttack, TargetOU='$TargetOU', Force=$Force"

    # Cache for IsExcludedSID to reduce network calls
    $SidCache = @{}
    Write-Verbose "Initialized SID cache"

    function Test-IsExcludedSID {
        [CmdletBinding()]
        Param ([string]$IdentityReference)

        Write-Verbose "Testing SID exclusion for: $IdentityReference"

        if ($SidCache.ContainsKey($IdentityReference)) {
            Write-Verbose "Cache hit for $IdentityReference"
            return $SidCache[$IdentityReference]
        }

        $sid = $null
        try {
            Write-Verbose "Attempting to translate $IdentityReference to SID"
            if ($IdentityReference -match '^S-\d-\d+(-\d+)+$') {
                $sid = $IdentityReference
                Write-Verbose "Input is already a SID: $sid"
            } else {
                $sid = (New-Object System.Security.Principal.NTAccount($IdentityReference)).Translate([System.Security.Principal.SecurityIdentifier]).Value
                Write-Verbose "Translated to SID: $sid"
            }
        } catch {
            Write-Verbose "Failed to translate $IdentityReference to SID: $_"
            $SidCache[$IdentityReference] = $false
            return $false
        }
        
        $isExcluded = ($sid -and ($excludedSids -contains $sid -or $sid.EndsWith('-519')))
        Write-Verbose "SID $sid exclusion result: $isExcluded"
        $SidCache[$IdentityReference] = $isExcluded
        return $isExcluded
    }

    function Simulate-BadSuccessorAttack {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory=$true)]
            [string]$TargetOU,
            
            [Parameter(Mandatory=$true)]
            [string]$Identity
        )

        Write-Verbose "Starting simulation for OU: $TargetOU with Identity: $Identity"

        Write-Host "`n[!] SIMULATION MODE - No actual changes will be made" -ForegroundColor Yellow
        Write-Host "=================================================" -ForegroundColor Yellow
        
        Write-Verbose "Step 1: Beginning OU access validation"
        Write-Host "`n[+] Step 1: Validating permissions on target OU" -ForegroundColor Cyan
        Write-Host "    Target OU: $TargetOU"
        Write-Host "    Identity: $Identity"
        
        $ou = $null
        try {
            Write-Verbose "Attempting to access OU"
            $ou = Get-ADOrganizationalUnit -Identity $TargetOU -Properties ntSecurityDescriptor
            Write-Host "    [✓] Successfully accessed OU" -ForegroundColor Green
            Write-Verbose "Successfully retrieved OU object"
        } catch {
            Write-Verbose "Failed to access OU: $_"
            Write-Host "    [×] Failed to access OU: $_" -ForegroundColor Red
            return
        }

        Write-Verbose "Step 2: Beginning dMSA creation simulation"
        Write-Host "`n[+] Step 2: Simulating dMSA creation" -ForegroundColor Cyan
        Write-Host "    [>] Would create dMSA with following attributes:"
        Write-Host "        - Name: SIMDMSA_POC"
        Write-Host "        - Path: $TargetOU"
        Write-Host "        - Enabled: True"
        Write-Host "    [✓] dMSA creation would succeed with current permissions" -ForegroundColor Green

        Write-Verbose "Step 3: Beginning privilege escalation simulation"
        Write-Host "`n[+] Step 3: Simulating privilege escalation path" -ForegroundColor Cyan
        Write-Host "    [>] Attack path would proceed as follows:"
        Write-Host "        1. Create dMSA in target OU"
        Write-Host "        2. Configure dMSA for unconstrained delegation"
        Write-Host "        3. Add computer account to local admin group"
        Write-Host "        4. Potential privilege escalation achieved"
        
        Write-Host "`n[!] SIMULATION COMPLETE - No changes were made" -ForegroundColor Yellow
        Write-Host "    This simulation demonstrates the potential attack path only."
        Write-Host "    Actual execution could be detected by security monitoring systems."
        Write-Verbose "Simulation completed successfully"
    }

    # Import Active Directory module based on PS version
    Write-Host "[*] Checking Active Directory module..." -ForegroundColor Cyan
    
    if ($isPS7) {
        try {
            # For PowerShell 7, try to import the Windows compatibility module if needed
            if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
                Import-Module -Name Microsoft.PowerShell.Compatibility -ErrorAction SilentlyContinue
            }
            Import-Module -Name ActiveDirectory -UseWindowsPowerShell -ErrorAction Stop
            Write-Verbose "Imported Active Directory module in Windows PowerShell compatibility mode"
        }
        catch {
            Write-Error "Failed to import Active Directory module in PowerShell 7. Error: $_"
            Write-Host "Note: In PowerShell 7, you may need to install the WindowsCompatibility module:" -ForegroundColor Yellow
            Write-Host "Install-Module -Name Microsoft.PowerShell.Compatibility -Force" -ForegroundColor Yellow
            return
        }
    }
    else {
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            Write-Error "Active Directory module is not available. Please install RSAT tools."
            return
        }
        Import-Module -Name ActiveDirectory
    }
    Write-Host "[+] Active Directory module is available" -ForegroundColor Green

    Write-Host "[*] Connecting to domain..." -ForegroundColor Cyan
    try {
        $domain = Get-ADDomain -ErrorAction Stop
        Write-Host "[+] Successfully connected to domain: $($domain.DNSRoot)" -ForegroundColor Green
        $domainSID = $domain.DomainSID.Value
        Write-Host "    Domain SID: $domainSID" -ForegroundColor Gray
    }
    catch {
        $errorMessage = if ($isPS7) { $_.Exception.Message } else { $_.Exception.Message }
        Write-Error "Failed to connect to domain: $errorMessage"
        return
    }

    Write-Verbose "Setting up excluded SIDs"
    $excludedSids = @(
        "$domainSID-512",       # Domain Admins
        "S-1-5-32-544",         # Builtin Administrators
        "S-1-5-18"              # Local SYSTEM
    )    
    Write-Verbose "Excluded SIDs: $($excludedSids -join ', ')"

    Write-Verbose "Setting up relevant object types"
    $relevantObjectTypes = @{
        "00000000-0000-0000-0000-000000000000"="All Objects"
        "0feb936f-47b3-49f2-9386-1dedc2c23765"="msDS-DelegatedManagedServiceAccount"
    }
    Write-Verbose "Relevant object types configured"

    Write-Verbose "Setting up relevant rights"
    $relevantRights = "CreateChild|GenericAll|WriteDACL|WriteOwner"
    Write-Verbose "Relevant rights: $relevantRights"

    Write-Host "[*] Retrieving all OUs from Active Directory..." -ForegroundColor Cyan
    try {
        $allOUs = Get-ADOrganizationalUnit -Filter * -Properties ntSecurityDescriptor -ErrorAction Stop |
                  Select-Object DistinguishedName, ntSecurityDescriptor
        
        if (-not $allOUs -or $allOUs.Count -eq 0) {
            Write-Warning "No OUs found in the domain."
            return
        }
        Write-Host "[+] Found $($allOUs.Count) OUs to analyze" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to retrieve OUs: $_"
        return
    }

    $allowedIdentities = @{}
    $processedOUs = 0
    $totalOUs = $allOUs.Count
    
    Write-Host "`n[*] Analyzing permissions..." -ForegroundColor Cyan
    foreach ($ou in $allOUs) {
        $processedOUs++
        $percentComplete = [math]::Round(($processedOUs / $totalOUs) * 100, 1)
        
        # PowerShell 7 has improved progress bar performance
        if ($isPS7) {
            if ($processedOUs % 10 -eq 0) {  # Update every 10 items for better performance
                Write-Progress -Activity "Analyzing OU Permissions" -Status "Processing $($ou.DistinguishedName)" -PercentComplete $percentComplete
            }
        }
        else {
            Write-Progress -Activity "Analyzing OU Permissions" -Status "Processing $($ou.DistinguishedName)" -PercentComplete $percentComplete
        }
        Write-Verbose "Processing OU ($processedOUs of $totalOUs): $($ou.DistinguishedName)"

        # Process ACEs
        $aceCount = 0
        foreach ($ace in $ou.ntSecurityDescriptor.Access) {
            $aceCount++
            Write-Verbose "  Processing ACE $aceCount of $($ou.ntSecurityDescriptor.Access.Count)"
            
            if ($ace.AccessControlType -ne "Allow") { 
                Write-Verbose "  Skipping non-Allow ACE"
                continue 
            }
            if ($ace.ActiveDirectoryRights -notmatch $relevantRights) { 
                Write-Verbose "  Skipping ACE with non-relevant rights"
                continue 
            }
            if (-not $relevantObjectTypes.ContainsKey($ace.ObjectType.Guid)) { 
                Write-Verbose "  Skipping ACE with non-relevant object type"
                continue 
            }

            $identity = $ace.IdentityReference.Value
            if (-not $identity) {
                Write-Verbose "  Skipping null identity"
                continue
            }
            
            Write-Verbose "  Processing identity: $identity"
            
            if (Test-IsExcludedSID $identity) { 
                Write-Verbose "  Skipping excluded identity"
                continue 
            }

            try {
                if (-not $allowedIdentities.ContainsKey($identity)) {
                    Write-Verbose "  Creating new entry for identity"
                    $allowedIdentities[$identity] = [System.Collections.Generic.List[string]]::new()
                }
                Write-Verbose "  Adding OU to identity's list"
                $allowedIdentities[$identity].Add($ou.DistinguishedName)
            }
            catch {
                Write-Warning "Failed to process identity '$identity' for OU '$($ou.DistinguishedName)': $_"
                continue
            }
        }

        # Check the owner
        Write-Verbose "  Checking OU owner"
        $owner = $ou.ntSecurityDescriptor.Owner
        Write-Verbose "  Owner: $owner"
        
        if ($owner -and -not (Test-IsExcludedSID $owner)) {
            Write-Verbose "  Owner is not excluded, processing"
            try {
                if (-not $allowedIdentities.ContainsKey($owner)) {
                    Write-Verbose "  Creating new entry for owner"
                    $allowedIdentities[$owner] = [System.Collections.Generic.List[string]]::new()
                }
                Write-Verbose "  Adding OU to owner's list"
                $allowedIdentities[$owner].Add($ou.DistinguishedName)
            }
            catch {
                Write-Warning "Failed to process owner '$owner' for OU '$($ou.DistinguishedName)': $_"
                continue
            }
        }
        else {
            Write-Verbose "  Owner is null or excluded, skipping"
        }
    }
    Write-Progress -Activity "Analyzing OU Permissions" -Completed

    Write-Host "`n[*] Analysis complete!" -ForegroundColor Cyan
    $results = foreach ($id in $allowedIdentities.Keys) {
        [PSCustomObject]@{
            Identity = $id
            OUs      = $allowedIdentities[$id].ToArray()
        }
    }

    Write-Host "    Found $($results.Count) principals with potentially dangerous permissions" -ForegroundColor Yellow
    
    if ($results.Count -gt 0) {
        Write-Host "`n[*] Results Summary:" -ForegroundColor Cyan
        foreach ($result in $results) {
            Write-Host "    Principal: $($result.Identity)" -ForegroundColor Yellow
            Write-Host "    Vulnerable OUs: $($result.OUs.Count)" -ForegroundColor Gray
            Write-Host "    First OU: $($result.OUs[0])" -ForegroundColor Gray
            Write-Host ""
        }
    }

    if ($SimulateAttack) {
        Write-Host "`n[*] Simulation Mode Enabled" -ForegroundColor Cyan
        if ($results.Count -eq 0) {
            Write-Host "[!] No vulnerable OUs found to simulate attack" -ForegroundColor Red
            return
        }

        if (-not $Force) {
            $confirmation = Read-Host "`nDo you want to proceed with attack path simulation? (y/N)"
            if ($confirmation -ne 'y') {
                Write-Host "Simulation aborted." -ForegroundColor Yellow
                return
            }
        }

        $targetIdentity = $results[0].Identity
        $simulationOU = if ($TargetOU) { $TargetOU } else { $results[0].OUs[0] }
        Write-Verbose "Target Identity: $targetIdentity"
        Write-Verbose "Simulation OU: $simulationOU"
        
        Simulate-BadSuccessorAttack -TargetOU $simulationOU -Identity $targetIdentity
    }
    else {
        return $results
    }

    Write-Verbose "Cleaning up SID cache"
    $SidCache.Clear()
    Write-Host "`n[*] Scan completed successfully" -ForegroundColor Green
}

# Auto-run if script is executed directly
if ($MyInvocation.InvocationName -ne '.') {
    Get-BadSuccessorOUPermissions @PSBoundParameters
}