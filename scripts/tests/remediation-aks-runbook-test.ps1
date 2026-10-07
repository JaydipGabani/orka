[CmdletBinding()]
param([string] $Runbook)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. $Runbook -LibraryOnly
$script:Passed = 0

function Check([bool] $Condition, [string] $Message) {
    if (-not $Condition) { throw $Message }
}

function Throws([scriptblock] $Code, [string] $Expected) {
    try { & $Code; throw 'expected-rejection' }
    catch { Check ($_.Exception.Message -eq $Expected) ('wrong-error:' + $_.Exception.Message) }
}

function Reset-Fixture {
    $script:Now = [DateTimeOffset]::Parse('2026-01-01T23:00:00Z')
    $script:InputManifest = @{
        version = 2
        authorizationModel = 'builtin-group-cleanup-v1'
        subscriptionId = '11111111-1111-1111-1111-111111111111'
        tenantId = '22222222-2222-2222-2222-222222222222'
        principalId = '33333333-3333-3333-3333-333333333333'
        suffix = 'sample01'
        owner = 'fixture-owner'
        cleanupReceipt = '44444444-4444-4444-4444-444444444444'
        controlVnetId = '/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/control/providers/Microsoft.Network/virtualNetworks/control'
        budgetStartUtc = '2026-01-01T00:00:00Z'
        expiresAtUtc = '2026-01-02T00:00:00Z'
        requireNodeScope = $true
        requirePeeringScope = $true
    }
    $script:Fixture = Read-CleanupManifest ($script:InputManifest | ConvertTo-Json -Compress)
    $tags = @{
        'orka-purpose' = 'isolated-remediation-verification'
        'orka-owner' = $script:Fixture.owner
        'orka-deployment' = $script:Fixture.prefix
        'orka-cleanup-receipt' = $script:Fixture.cleanupReceipt
        'orka-budget-start-utc' = $script:Fixture.budgetStartUtc
        'orka-expires-at-utc' = $script:Fixture.expiresAtUtc
    }
    $script:Objects = @{
        group = @{ id = $script:Fixture.ids.group; tags = $tags.Clone() }
        aks = @{ id = $script:Fixture.ids.aks; tags = $tags.Clone(); properties = @{
            nodeResourceGroup = $script:Fixture.ids.nodeGroup.Split('/')[-1]
        } }
        vm = @{ id = $script:Fixture.ids.vm; tags = $tags.Clone() }
        nodeGroup = @{ id = $script:Fixture.ids.nodeGroup; managedBy = $script:Fixture.ids.aks }
        peer = @{ id = $script:Fixture.ids.peer; properties = @{
            remoteVirtualNetwork = @{ id = $script:Fixture.ids.vnet }
        } }
        permissions = @{ value = @(@{
            actions = @(
                '*/read',
                'Microsoft.Resources/subscriptions/resourceGroups/read',
                'Microsoft.Resources/subscriptions/resourceGroups/write',
                'Microsoft.Resources/subscriptions/resourceGroups/delete'
            )
            notActions = @(); dataActions = @(); notDataActions = @()
        }) }
    }
    $script:Deletes = [Collections.Generic.List[string]]::new()
    $script:Forbidden = ''
    $script:ForbiddenAbsent = @()
    $script:AutoRemoveNodesWithAKS = $false
    $script:Stuck = ''
    $script:PendingMainReads = 0
    $script:RejectChildrenAfterMainDelete = $false
    $script:ChildReadsAfterMainDelete = 0
    $script:PermissionReplies = @()
    $script:PermissionReads = 0
}

function Get-CleanupTime { return $script:Now }
function Start-Sleep { param([double] $Seconds); $script:Now = $script:Now.AddSeconds($Seconds) }
function Get-CleanupResource {
    param([string] $Kind)
    if ($Kind -eq 'permissions') {
        $script:PermissionReads++
        if ($script:PermissionReplies.Count -gt 0) {
            $reply = $script:PermissionReplies[0]
            $script:PermissionReplies = @($script:PermissionReplies | Select-Object -Skip 1)
            return $reply
        }
    }
    if ($script:RejectChildrenAfterMainDelete -and $script:Deletes.Contains('group') -and $Kind -in @('aks', 'vm')) {
        $script:ChildReadsAfterMainDelete++
        throw 'arm-forbidden'
    }
    if ($Kind -eq 'group' -and $script:Deletes.Contains('group') -and $script:PendingMainReads -gt 0) {
        $script:PendingMainReads--
        if ($script:PendingMainReads -eq 0) { $script:Objects.Remove('group') }
    }
    if ($Kind -eq $script:Forbidden) { throw 'arm-forbidden' }
    if ($script:Objects.ContainsKey($Kind)) { return $script:Objects[$Kind] }
    if ($Kind -in $script:ForbiddenAbsent) { throw 'arm-forbidden' }
    return $null
}
function Remove-CleanupResource {
    param([string] $Kind)
    Check ($Kind -in @('group', 'nodeGroup', 'peer')) 'unapproved-individual-resource-delete'
    $script:Deletes.Add($Kind)
    if ($Kind -eq 'group' -and $script:PendingMainReads -gt 0) {
        $script:Objects.group['properties'] = @{ provisioningState = 'Deleting' }
    } elseif ($Kind -ne $script:Stuck) { $script:Objects.Remove($Kind) }
    if ($Kind -eq 'group' -and $script:AutoRemoveNodesWithAKS) { $script:Objects.Remove('nodeGroup') }
    return @{ accepted = $true; completed = $false }
}

Reset-Fixture
$script:Objects.Remove('nodeGroup')
$script:Objects.Remove('peer')
$result = Invoke-FoundationCleanup ($script:InputManifest | ConvertTo-Json -Compress) 'Preflight'
Check ($result.outcome -eq 'preflight-succeeded' -and $script:Deletes.Count -eq 0) 'preflight-mutated'
Check ($result.postDeleteGroupRead -and $result.postDeletePeeringRead) 'preflight-missing-metadata-read-proof'
$script:Passed++

Reset-Fixture
$result = Invoke-FoundationCleanup ($script:InputManifest | ConvertTo-Json -Compress) 'Cleanup'
Check ($result.outcome -eq 'cleanup-succeeded') 'cleanup-did-not-complete'
Check (($script:Deletes -join ',') -eq 'group,nodeGroup,peer') 'unsafe-delete-order'
$script:Passed++

Reset-Fixture
$script:Objects.group.tags['orka-owner'] = 'foreign'
Throws { Invoke-FoundationCleanup ($script:InputManifest | ConvertTo-Json -Compress) 'Cleanup' } 'main-group-ownership-not-confirmed'
Check ($script:Deletes.Count -eq 0) 'deleted-foreign-group'
$script:Passed++

Reset-Fixture
$script:Objects.aks.properties.nodeResourceGroup = 'foreign'
Throws { Invoke-FoundationCleanup ($script:InputManifest | ConvertTo-Json -Compress) 'Cleanup' } 'main-cleanup-verification-required'
Check ($script:Deletes.Count -eq 0) 'deleted-foreign-aks'
$script:Passed++

Reset-Fixture
$script:Objects.nodeGroup.managedBy = '/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/foreign'
Throws { Invoke-FoundationCleanup ($script:InputManifest | ConvertTo-Json -Compress) 'Cleanup' } 'cleanup-residual-verification-required'
Check (-not $script:Deletes.Contains('nodeGroup') -and $script:Deletes.Contains('group')) 'foreign-node-blocked-owned-main-cleanup'
$script:Passed++

Reset-Fixture
$script:Objects.peer.properties.remoteVirtualNetwork.id = '/foreign'
Throws { Invoke-FoundationCleanup ($script:InputManifest | ConvertTo-Json -Compress) 'Cleanup' } 'cleanup-residual-verification-required'
Check (-not $script:Deletes.Contains('peer') -and $script:Deletes.Contains('group')) 'foreign-peer-blocked-owned-main-cleanup'
$script:Passed++

Reset-Fixture
$script:Forbidden = 'group'
Throws { Invoke-FoundationCleanup ($script:InputManifest | ConvertTo-Json -Compress) 'Cleanup' } 'cleanup-residual-verification-required'
Check ($script:Deletes.Count -eq 0) 'forbidden-treated-as-absent'
$script:Passed++

Reset-Fixture
$script:Now = [DateTimeOffset]::Parse('2026-01-01T21:59:59Z')
Throws { Invoke-FoundationCleanup ($script:InputManifest | ConvertTo-Json -Compress) 'Cleanup' } 'cleanup-not-due'
Check ($script:Deletes.Count -eq 0) 'early-deletion'
$script:Passed++

Reset-Fixture
$script:InputManifest.expiresAtUtc = '2026-01-03T00:00:00Z'
Throws { Invoke-FoundationCleanup ($script:InputManifest | ConvertTo-Json -Compress) 'Cleanup' } 'lifetime-not-24-hours'
$script:Passed++

Reset-Fixture
$script:Objects.permissions.value[0].actions += 'Microsoft.Compute/virtualMachines/write'
Throws { Invoke-FoundationCleanup ($script:InputManifest | ConvertTo-Json -Compress) 'Preflight' } 'unexpected-extra-cleanup-authority'
$script:Passed++

Reset-Fixture
$script:Stuck = 'group'
Throws { Invoke-FoundationCleanup ($script:InputManifest | ConvertTo-Json -Compress) 'Cleanup' } 'cleanup-deadline-reached'
Check (@($script:Deletes | Where-Object { $_ -eq 'group' }).Count -eq 1) 'unbounded-delete-replay'
Check (-not $script:Deletes.Contains('nodeGroup')) 'node-group-deleted-before-main-group-settled'
$script:Passed++

Reset-Fixture
$script:Now = [DateTimeOffset]::Parse('2026-01-02T01:00:00Z')
$result = Invoke-FoundationCleanup ($script:InputManifest | ConvertTo-Json -Compress) 'Cleanup'
Check ($result.outcome -eq 'cleanup-succeeded' -and $result.late) 'late-cleanup-leaked-resources'
$script:Passed++

Reset-Fixture
$script:PendingMainReads = 3
$script:RejectChildrenAfterMainDelete = $true
$result = Invoke-FoundationCleanup ($script:InputManifest | ConvertTo-Json -Compress) 'Cleanup'
Check ($result.outcome -eq 'cleanup-succeeded') 'deleting-main-group-did-not-settle'
Check ($script:ChildReadsAfterMainDelete -eq 0) 're-read-children-after-main-delete-accepted'
Check (@($script:Deletes | Where-Object { $_ -eq 'group' }).Count -eq 1) 'replayed-main-delete'
$script:Passed++

Reset-Fixture
$script:Forbidden = 'nodeGroup'
Throws { Invoke-FoundationCleanup ($script:InputManifest | ConvertTo-Json -Compress) 'Cleanup' } 'cleanup-residual-verification-required'
Check ($script:Deletes.Contains('group')) 'partial-A-retained-main-group'
Check ($script:CleanupEvidence.nodeGroup.state -eq 'Unverified') 'partial-A-falsely-claimed-absence'
$script:Passed++

Reset-Fixture
$script:Forbidden = 'peer'
Throws { Invoke-FoundationCleanup ($script:InputManifest | ConvertTo-Json -Compress) 'Cleanup' } 'cleanup-residual-verification-required'
Check ($script:Deletes.Contains('group') -and $script:Deletes.Contains('nodeGroup')) 'partial-B-retained-owned-resources'
Check ($script:CleanupEvidence.peer.state -eq 'Unverified') 'partial-B-falsely-claimed-absence'
$script:Passed++

Reset-Fixture
$script:AutoRemoveNodesWithAKS = $true
$script:ForbiddenAbsent = @('nodeGroup')
Throws { Invoke-FoundationCleanup ($script:InputManifest | ConvertTo-Json -Compress) 'Cleanup' } 'cleanup-residual-verification-required'
Check (($script:Deletes -join ',') -eq 'group,peer') 'partial-C-did-not-delete-main-group'
Check ($script:CleanupEvidence.group.state -eq 'Absent') 'partial-C-missing-main-proof'
$script:Passed++

Reset-Fixture
foreach ($kind in @('group', 'aks', 'vm')) { $script:Objects.Remove($kind) }
$result = Invoke-FoundationCleanup ($script:InputManifest | ConvertTo-Json -Compress) 'Cleanup'
Check ($result.outcome -eq 'cleanup-succeeded' -and
    ($script:Deletes -join ',') -eq 'nodeGroup,peer') 'catchup-refused-owned-residuals-after-main-delete'
$script:Passed++

Reset-Fixture
foreach ($kind in @('group', 'aks', 'vm', 'nodeGroup', 'peer')) { $script:Objects.Remove($kind) }
$script:ForbiddenAbsent = @('group', 'nodeGroup', 'peer')
Throws { Invoke-FoundationCleanup ($script:InputManifest | ConvertTo-Json -Compress) 'Cleanup' } 'cleanup-residual-verification-required'
Check ($script:Deletes.Count -eq 0 -and $script:CleanupEvidence.group.state -eq 'Unverified') 'catchup-forbidden-was-success'
$script:Passed++

Add-Type -TypeDefinition @'
using System;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
public sealed class CleanupHttpFixture {
    public int Calls;
    public int ForbiddenCount;
    public CleanupHttpFixture(int forbiddenCount) { ForbiddenCount = forbiddenCount; }
    public Task<HttpResponseMessage> SendAsync(HttpRequestMessage request) {
        Calls++;
        var status = Calls <= ForbiddenCount ? HttpStatusCode.Forbidden : HttpStatusCode.OK;
        var response = new HttpResponseMessage(status);
        response.Content = new StringContent("{\"fixture\":\"ok\"}");
        return Task.FromResult(response);
    }
}
'@
function Get-IdentityToken { param($Manifest); $script:Token = 'SYNTHETIC_OFFLINE_TOKEN' }

Reset-Fixture
$script:Manifest = $script:Fixture
$script:PreflightOnly = $true
$script:RunDeadline = $script:Now.AddMinutes(10)
$script:Http = [CleanupHttpFixture]::new(2)
$value = Invoke-CleanupArm 'GET' $script:Fixture.ids.group '2024-03-01'
Check ($value.fixture -eq 'ok' -and $script:Http.Calls -eq 3) 'preflight-did-not-retry-propagating-403'
$script:Passed++

Reset-Fixture
$script:Manifest = $script:Fixture
$script:PreflightOnly = $false
$script:RunDeadline = $script:Now.AddMinutes(60)
$script:Http = [CleanupHttpFixture]::new(2)
Throws { Invoke-CleanupArm 'GET' $script:Fixture.ids.group '2024-03-01' } 'arm-forbidden'
Check ($script:Http.Calls -eq 1) 'cleanup-silently-retried-403'
$script:Passed++

Reset-Fixture
$script:Manifest = $script:Fixture
$script:PreflightOnly = $true
$script:RunDeadline = $script:Now.AddMinutes(10)
$start = $script:Now
$script:Http = [CleanupHttpFixture]::new(99999)
Throws { Invoke-CleanupArm 'GET' $script:Fixture.ids.group '2024-03-01' } 'retry-exceeds-deadline'
Check (($script:Now - $start).TotalMinutes -lt 10 -and $script:Http.Calls -gt 2) 'unbounded-preflight-retry'
$script:Passed++

Reset-Fixture
$script:InputManifest.version = 1
Throws { Read-CleanupManifest ($script:InputManifest | ConvertTo-Json -Compress) } 'unsupported-manifest-version'
$script:Passed++

Reset-Fixture
$script:Objects.permissions.value[0].actions = @('*')
Throws { Invoke-FoundationCleanup ($script:InputManifest | ConvertTo-Json -Compress) 'Preflight' } 'unexpected-extra-cleanup-authority'
$script:Passed++

Reset-Fixture
$script:Manifest = $script:Fixture
Throws { Invoke-CleanupArm 'DELETE' $script:Fixture.ids.vm '2024-11-01' } 'arm-delete-outside-scope'
Throws { Invoke-CleanupArm 'DELETE' $script:Fixture.ids.aks '2025-07-01' } 'arm-delete-outside-scope'
$script:Passed++

foreach ($visible in @('group', 'reader')) {
    Reset-Fixture
    $script:Objects.Remove('nodeGroup')
    $script:Objects.Remove('peer')
    $partial = if ($visible -eq 'reader') { @('*/read') } else {
        @('Microsoft.Resources/subscriptions/resourceGroups/read',
          'Microsoft.Resources/subscriptions/resourceGroups/write',
          'Microsoft.Resources/subscriptions/resourceGroups/delete')
    }
    $script:PermissionReplies = @(@{ value = @(@{
        actions = $partial; notActions = @(); dataActions = @(); notDataActions = @()
    }) })
    $result = Invoke-FoundationCleanup ($script:InputManifest | ConvertTo-Json -Compress) 'Preflight'
    Check ($result.outcome -eq 'preflight-succeeded' -and $script:PermissionReads -eq 2) 'partial-grant-not-retried'
    Check ($script:Deletes.Count -eq 0) 'propagation-check-mutated'
    $script:Passed++
}

Reset-Fixture
$script:Objects.permissions.value[0].actions = @('*/read')
$start = $script:Now
Throws { Invoke-FoundationCleanup ($script:InputManifest | ConvertTo-Json -Compress) 'Preflight' } 'missing-cleanup-authority'
Check ($script:PermissionReads -gt 1 -and ($script:Now - $start).TotalMinutes -lt 10) 'partial-grant-wait-unbounded'
$script:Passed++

Reset-Fixture
$script:Objects.permissions.value[0].actions += '*'
Throws { Invoke-FoundationCleanup ($script:InputManifest | ConvertTo-Json -Compress) 'Preflight' } 'unexpected-extra-cleanup-authority'
Check ($script:PermissionReads -eq 1) 'extra-authority-was-retried'
$script:Passed++

Reset-Fixture
$script:Manifest = $script:Fixture
$script:PreflightOnly = $false
$script:RunDeadline = $script:Now.AddMinutes(60)
$script:Objects.permissions.value[0].actions = @('*/read')
Throws { Assert-CleanupAuthority } 'missing-cleanup-authority'
Check ($script:PermissionReads -eq 1) 'nonpreflight-partial-authority-was-retried'
$script:Passed++

Write-Output ("Runbook offline contracts passed: " + $script:Passed)
