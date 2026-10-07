[CmdletBinding()]
param(
    [string] $ManifestJson = '',
    [ValidateSet('Preflight', 'Cleanup')] [string] $Mode = 'Preflight',
    [switch] $LibraryOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-Cleanup {
    param([bool] $Condition, [string] $Code)
    if (-not $Condition) { throw [InvalidOperationException]::new($Code) }
}

function Get-CleanupTime { [DateTimeOffset]::UtcNow }

function Convert-CleanupJsonElement {
    param([System.Text.Json.JsonElement] $Element)
    switch ([string]$Element.ValueKind) {
        'Object' {
            $value = @{}
            foreach ($property in $Element.EnumerateObject()) {
                Assert-Cleanup (-not $value.ContainsKey($property.Name)) 'duplicate-json-key'
                $value[$property.Name] = Convert-CleanupJsonElement $property.Value
            }
            return $value
        }
        'Array' {
            $value = @()
            foreach ($item in $Element.EnumerateArray()) { $value += ,(Convert-CleanupJsonElement $item) }
            return ,$value
        }
        'String' { return $Element.GetString() }
        'Number' { return $Element.GetDouble() }
        'True' { return $true }
        'False' { return $false }
        'Null' { return $null }
        default { throw 'unsupported-json-value' }
    }
}

function ConvertFrom-CleanupJson {
    param([string] $Json)
    $document = [System.Text.Json.JsonDocument]::Parse($Json)
    try { return Convert-CleanupJsonElement $document.RootElement }
    finally { $document.Dispose() }
}

function Read-CleanupManifest {
    param([string] $Json)
    Assert-Cleanup ($Json.Length -le 32768) 'manifest-too-large'
    try { $m = ConvertFrom-CleanupJson $Json }
    catch { throw 'invalid-manifest-json' }
    $keys = @('version', 'subscriptionId', 'tenantId', 'principalId', 'suffix', 'owner',
        'cleanupReceipt', 'controlVnetId', 'budgetStartUtc', 'expiresAtUtc',
        'requireNodeScope', 'requirePeeringScope')
    Assert-Cleanup (($m -is [hashtable]) -and ($m.Count -eq $keys.Count)) 'invalid-manifest-shape'
    foreach ($key in $keys) { Assert-Cleanup ($m.ContainsKey($key)) 'missing-manifest-field' }
    Assert-Cleanup ($m.version -eq 1) 'unsupported-manifest-version'
    $uuid = '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$'
    foreach ($key in @('subscriptionId', 'tenantId', 'principalId', 'cleanupReceipt')) {
        Assert-Cleanup (($m[$key] -is [string]) -and ($m[$key] -cmatch $uuid)) 'invalid-manifest-uuid'
    }
    Assert-Cleanup (($m.suffix -is [string]) -and ($m.suffix -cmatch '^[a-z0-9]{6,12}$')) 'invalid-suffix'
    Assert-Cleanup (($m.owner -is [string]) -and $m.owner.Length -ge 1 -and $m.owner.Length -le 64) 'invalid-owner'
    Assert-Cleanup (($m.requireNodeScope -is [bool]) -and ($m.requirePeeringScope -is [bool])) 'invalid-scope-requirements'
    $vnetPattern = '^/subscriptions/' + [regex]::Escape($m.subscriptionId) +
        '/resourceGroups/[A-Za-z0-9_.-]+/providers/Microsoft.Network/virtualNetworks/[A-Za-z0-9_.-]+$'
    Assert-Cleanup (($m.controlVnetId -is [string]) -and ($m.controlVnetId -cmatch $vnetPattern)) 'foreign-control-vnet'
    $prefix = 'orka-verify-' + $m.suffix
    $group = '/subscriptions/' + $m.subscriptionId + '/resourceGroups/rg-' + $prefix
    $ids = @{
        group = $group
        nodeGroup = $group + '-nodes'
        aks = $group + '/providers/Microsoft.ContainerService/managedClusters/' + $prefix + '-aks'
        vm = $group + '/providers/Microsoft.Compute/virtualMachines/' + $prefix + '-builder'
        vnet = $group + '/providers/Microsoft.Network/virtualNetworks/' + $prefix + '-vnet'
        peer = $m.controlVnetId + '/virtualNetworkPeerings/to-' + $prefix
        permissions = $group + '/providers/Microsoft.Authorization/permissions'
    }
    $m['prefix'] = $prefix
    $m['ids'] = $ids
    $pending = ($m.budgetStartUtc -eq '') -and ($m.expiresAtUtc -eq '')
    if (-not $pending) {
        foreach ($key in @('budgetStartUtc', 'expiresAtUtc')) {
            Assert-Cleanup (($m[$key] -is [string]) -and
                ($m[$key] -cmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$')) 'invalid-utc-clock'
        }
        try {
            $start = [DateTimeOffset]::Parse($m.budgetStartUtc)
            $end = [DateTimeOffset]::Parse($m.expiresAtUtc)
        } catch { throw 'invalid-utc-clock' }
        Assert-Cleanup ($end -eq $start.AddHours(24)) 'lifetime-not-24-hours'
    }
    $m['pendingClock'] = $pending
    return $m
}

function Assert-ResourceIdentity {
    param($Resource, [string] $ExpectedId)
    Assert-Cleanup (($null -ne $Resource) -and $Resource.Contains('id') -and
        [string]::Equals($Resource.id, $ExpectedId, [StringComparison]::OrdinalIgnoreCase)) 'resource-id-mismatch'
}

function Assert-Ownership {
    param($Resource, $Manifest, [string] $ExpectedId)
    Assert-ResourceIdentity $Resource $ExpectedId
    Assert-Cleanup ($Resource.Contains('tags') -and ($Resource.tags -is [hashtable])) 'missing-ownership-tags'
    $tags = $Resource.tags
    $expected = @{
        'orka-purpose' = 'isolated-remediation-verification'
        'orka-owner' = $Manifest.owner
        'orka-deployment' = $Manifest.prefix
        'orka-cleanup-receipt' = $Manifest.cleanupReceipt
    }
    foreach ($key in $expected.Keys) {
        Assert-Cleanup ($tags.ContainsKey($key) -and ($tags[$key] -ceq $expected[$key])) 'ownership-mismatch'
    }
    foreach ($key in @('orka-budget-start-utc', 'orka-expires-at-utc')) {
        Assert-Cleanup ($tags.ContainsKey($key)) 'missing-budget-tag'
    }
    $prepared = ($tags['orka-budget-start-utc'] -eq 'pending') -and ($tags['orka-expires-at-utc'] -eq 'pending')
    if (-not $prepared) {
        Assert-Cleanup (-not $Manifest.pendingClock) 'unexpected-active-lifetime'
        Assert-Cleanup (($tags['orka-budget-start-utc'] -ceq $Manifest.budgetStartUtc) -and
            ($tags['orka-expires-at-utc'] -ceq $Manifest.expiresAtUtc)) 'budget-tag-mismatch'
    }
}

function Get-IdentityToken {
    param($Manifest)
    if ($script:Token -and ($script:TokenExpires -gt (Get-CleanupTime).AddMinutes(5))) { return }
    Assert-Cleanup ($env:IDENTITY_ENDPOINT -and $env:IDENTITY_HEADER) 'automation-identity-unavailable'
    try { $endpoint = [Uri]$env:IDENTITY_ENDPOINT } catch { throw 'invalid-identity-endpoint' }
    Assert-Cleanup (($endpoint.Scheme -eq 'http') -and $endpoint.IsLoopback -and
        (-not $endpoint.UserInfo) -and (-not $endpoint.Fragment)) 'untrusted-identity-endpoint'
    $separator = if ($endpoint.Query) { '&' } else { '?' }
    $uri = $endpoint.AbsoluteUri + $separator + 'resource=https%3A%2F%2Fmanagement.azure.com%2F'
    try {
        $response = Invoke-RestMethod -Method Get -Uri $uri -TimeoutSec 30 -MaximumRedirection 0 -NoProxy `
            -Headers @{ 'X-IDENTITY-HEADER' = $env:IDENTITY_HEADER; 'Metadata' = 'True' }
        $token = [string]$response.access_token
        $parts = $token.Split('.')
        Assert-Cleanup ($parts.Length -eq 3) 'invalid-identity-token'
        $payload = $parts[1].Replace('-', '+').Replace('_', '/')
        $payload = $payload.PadRight($payload.Length + ((4 - $payload.Length % 4) % 4), '=')
        $claims = ConvertFrom-CleanupJson ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload)))
        Assert-Cleanup (($claims.oid -ceq $Manifest.principalId) -and
            ($claims.tid -ceq $Manifest.tenantId) -and
            ($claims.aud -in @('https://management.azure.com/', 'https://management.core.windows.net/'))) 'identity-claims-mismatch'
        $expiry = [DateTimeOffset]::FromUnixTimeSeconds([long]$claims.exp)
        Assert-Cleanup ($expiry -gt (Get-CleanupTime).AddMinutes(2)) 'identity-token-expired'
        $script:Token = $token
        $script:TokenExpires = $expiry
    } catch { throw 'managed-identity-authentication-failed' }
}

function Invoke-CleanupArm {
    param([ValidateSet('GET', 'DELETE')] [string] $Method, [string] $Id, [string] $ApiVersion)
    $m = $script:Manifest
    $readIds = @($m.ids.group, $m.ids.nodeGroup, $m.ids.aks, $m.ids.vm, $m.ids.peer, $m.ids.permissions)
    $deleteIds = @($m.ids.group, $m.ids.nodeGroup, $m.ids.aks, $m.ids.vm, $m.ids.peer)
    Assert-Cleanup ($Id -cin $readIds) 'arm-read-outside-scope'
    if ($Method -eq 'DELETE') { Assert-Cleanup ($Id -cin $deleteIds) 'arm-delete-outside-scope' }
    Assert-Cleanup ($ApiVersion -cmatch '^\d{4}-\d{2}-\d{2}$') 'invalid-api-version'
    $retry = 0
    while ((Get-CleanupTime) -lt $script:RunDeadline) {
        Get-IdentityToken $m
        $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::new($Method),
            'https://management.azure.com' + $Id + '?api-version=' + $ApiVersion)
        $request.Headers.Authorization = [Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $script:Token)
        try { $response = $script:Http.SendAsync($request).GetAwaiter().GetResult() }
        catch {
            $request.Dispose()
            $retry++
            $delay = [Math]::Min(30, [Math]::Pow(2, [Math]::Min($retry, 5)))
            Assert-Cleanup ((Get-CleanupTime).AddSeconds($delay) -lt $script:RunDeadline) 'arm-transport-deadline'
            Start-Sleep -Seconds $delay
            continue
        }
        try {
            $status = [int]$response.StatusCode
            if ($status -eq 404) { return $null }
            if ($status -eq 403 -and -not $script:PreflightOnly) { throw 'arm-forbidden' }
            if ($status -eq 401) { throw 'arm-unauthorized' }
            if (($status -eq 403 -and $script:PreflightOnly) -or
                $status -in @(408, 429, 500, 502, 503, 504) -or ($Method -eq 'DELETE' -and $status -eq 409)) {
                $retry++
                $delay = [Math]::Min(30, [Math]::Pow(2, [Math]::Min($retry, 5)))
                if ($response.Headers.RetryAfter) {
                    $after = $response.Headers.RetryAfter
                    if ($null -ne $after.Delta) { $delay = [Math]::Max($delay, ([TimeSpan]$after.Delta).TotalSeconds) }
                    elseif ($null -ne $after.Date) {
                        $delay = [Math]::Max($delay, (([DateTimeOffset]$after.Date) - (Get-CleanupTime)).TotalSeconds)
                    }
                }
                Assert-Cleanup ((Get-CleanupTime).AddSeconds($delay) -lt $script:RunDeadline) 'retry-exceeds-deadline'
                Start-Sleep -Seconds $delay
                continue
            }
            Assert-Cleanup ($status -in @(200, 201, 202, 204)) 'arm-request-rejected'
            if ($Method -eq 'DELETE' -or $status -eq 204) {
                return @{ accepted = $true; completed = ($status -eq 204) }
            }
            $body = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            Assert-Cleanup ($body.Length -le 2097152) 'arm-response-too-large'
            try { return ConvertFrom-CleanupJson $body }
            catch { throw 'invalid-arm-json' }
        } finally { $request.Dispose(); $response.Dispose() }
    }
    throw 'cleanup-deadline-reached'
}

function Get-CleanupResource {
    param([string] $Kind)
    $versions = @{ group = '2024-03-01'; nodeGroup = '2024-03-01'; aks = '2025-07-01';
        vm = '2024-11-01'; peer = '2024-05-01'; permissions = '2022-04-01' }
    Assert-Cleanup ($versions.ContainsKey($Kind)) 'unknown-resource-kind'
    return Invoke-CleanupArm 'GET' $script:Manifest.ids[$Kind] $versions[$Kind]
}

function Remove-CleanupResource {
    param([string] $Kind)
    $versions = @{ group = '2024-03-01'; nodeGroup = '2024-03-01'; aks = '2025-07-01';
        vm = '2024-11-01'; peer = '2024-05-01' }
    Assert-Cleanup ($versions.ContainsKey($Kind)) 'unknown-delete-kind'
    return Invoke-CleanupArm 'DELETE' $script:Manifest.ids[$Kind] $versions[$Kind]
}

function Observe-CleanupResource {
    param([string] $Kind)
    if ($script:CleanupEvidence[$Kind].state -eq 'Absent' -and
        $script:CleanupEvidence[$Kind].proof -eq 'delete-terminal') {
        return @{ state = 'Absent'; resource = $null }
    }
    try {
        $resource = Get-CleanupResource $Kind
        if ($null -eq $resource) {
            $script:CleanupEvidence[$Kind] = @{ state = 'Absent'; proof = 'get-404' }
            return @{ state = 'Absent'; resource = $null }
        }
        $script:CleanupEvidence[$Kind] = @{ state = 'Present'; proof = 'get-200' }
        return @{ state = 'Present'; resource = $resource }
    } catch {
        $script:CleanupEvidence[$Kind] = @{ state = 'Unverified'; proof = 'read-not-authoritative' }
        return @{ state = 'Unverified'; resource = $null }
    }
}

function Request-CleanupDeletion {
    param([string] $Kind, [hashtable] $Requested)
    if ($Requested.ContainsKey($Kind)) { return }
    try {
        $result = Remove-CleanupResource $Kind
        $Requested[$Kind] = $true
        if ($null -eq $result -or $result.completed) {
            $script:CleanupEvidence[$Kind] = @{ state = 'Absent'; proof = 'delete-terminal' }
        } else {
            $script:CleanupEvidence[$Kind] = @{ state = 'Pending'; proof = 'delete-accepted-not-completed' }
        }
    } catch {
        $script:CleanupEvidence[$Kind] = @{ state = 'Unverified'; proof = 'delete-not-confirmed' }
    }
}

function Set-CleanupRefused {
    param([string] $Kind)
    $script:CleanupEvidence[$Kind] = @{ state = 'Refused'; proof = 'ownership-not-confirmed' }
}

function Assert-CleanupAuthority {
    $permissions = Get-CleanupResource 'permissions'
    Assert-Cleanup (($null -ne $permissions) -and $permissions.Contains('value')) 'permissions-unavailable'
    $actions = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $permissions.value) {
        foreach ($action in $entry.actions) {
            Assert-Cleanup (-not $action.Contains('*')) 'wildcard-cleanup-authority'
            $null = $actions.Add($action)
        }
        Assert-Cleanup (($entry.notActions.Count -eq 0) -and
            ($entry.dataActions.Count -eq 0) -and ($entry.notDataActions.Count -eq 0)) 'unexpected-cleanup-permissions'
    }
    $expected = @('Microsoft.Resources/subscriptions/resourceGroups/read',
            'Microsoft.Resources/subscriptions/resourceGroups/delete',
            'Microsoft.Resources/subscriptions/resourceGroups/resources/read',
            'Microsoft.Resources/deployments/read', 'Microsoft.Resources/deployments/operations/read',
            'Microsoft.ContainerService/managedClusters/read', 'Microsoft.ContainerService/managedClusters/delete',
            'Microsoft.Compute/virtualMachines/read', 'Microsoft.Compute/virtualMachines/instanceView/read',
            'Microsoft.Compute/virtualMachines/delete', 'Microsoft.Authorization/permissions/read')
    Assert-Cleanup ($actions.Count -eq $expected.Count) 'unexpected-extra-cleanup-authority'
    foreach ($action in $expected) {
        Assert-Cleanup ($actions.Contains($action)) 'missing-cleanup-authority'
    }
}

function Invoke-FoundationCleanup {
    param([string] $Json, [string] $Operation)
    $script:Manifest = Read-CleanupManifest $Json
    $script:PreflightOnly = ($Operation -eq 'Preflight')
    $m = $script:Manifest
    $script:RunDeadline = (Get-CleanupTime).AddMinutes($(if ($Operation -eq 'Preflight') { 10 } else { 60 }))
    if ($Operation -eq 'Cleanup') {
        Assert-Cleanup (-not $m.pendingClock) 'cleanup-clock-unarmed'
        Assert-Cleanup ((Get-CleanupTime) -ge ([DateTimeOffset]::Parse($m.budgetStartUtc)).AddHours(22)) 'cleanup-not-due'
    }
    if ($Operation -eq 'Preflight') {
        $group = Get-CleanupResource 'group'
        Assert-Cleanup ($null -ne $group) 'preflight-group-absent'
        Assert-Ownership $group $m $m.ids.group
        Assert-CleanupAuthority
        Assert-Cleanup ($null -eq (Get-CleanupResource 'nodeGroup')) 'preflight-node-group-already-present'
        Assert-Cleanup ($null -eq (Get-CleanupResource 'peer')) 'preflight-peering-already-present'
        return @{ outcome = 'preflight-succeeded'; principalMatched = $true; coreDeleteAuthority = $true;
            postDeleteGroupRead = $true; postDeletePeeringRead = $true }
    }

    # Never reuse these names while the cleanup identity/schedules remain live.
    # ARM group DELETE has no atomic ownership-tag precondition.
    $requested = @{}
    $script:CleanupRequested = $requested
    $script:CleanupEvidence = @{}
    foreach ($kind in @('group', 'aks', 'vm', 'nodeGroup', 'peer')) {
        $script:CleanupEvidence[$kind] = @{ state = 'Unverified'; proof = 'not-observed' }
    }
    while ((Get-CleanupTime) -lt $script:RunDeadline) {
        $main = Observe-CleanupResource 'group'
        $mainOwned = $false
        $coreAbsent = ($main.state -eq 'Absent')
        if ($main.state -eq 'Present') {
            try { Assert-Ownership $main.resource $m $m.ids.group; $mainOwned = $true }
            catch { Set-CleanupRefused 'group'; throw 'main-group-ownership-not-confirmed' }
            $coreAbsent = $true
            $ownedCore = @()
            # Group-level authorization can disappear while the containing
            # group is still Deleting. Its children were settled before DELETE.
            $coreKinds = if ($requested.ContainsKey('group')) { @() } else { @('aks', 'vm') }
            foreach ($kind in $coreKinds) {
                $observed = Observe-CleanupResource $kind
                if ($observed.state -eq 'Absent') { continue }
                $coreAbsent = $false
                if ($observed.state -ne 'Present') { continue }
                try {
                    Assert-Ownership $observed.resource $m $m.ids[$kind]
                    if ($kind -eq 'aks') {
                        Assert-Cleanup ($observed.resource.properties.nodeResourceGroup -ceq
                            $m.ids.nodeGroup.Split('/')[-1]) 'aks-node-group-mismatch'
                    }
                    $ownedCore += $kind
                } catch { Set-CleanupRefused $kind }
            }
            Assert-Cleanup (@(@('aks', 'vm') | Where-Object {
                $script:CleanupEvidence[$_].state -eq 'Refused'
            }).Count -eq 0) 'main-cleanup-verification-required'
            foreach ($kind in $ownedCore) { Request-CleanupDeletion $kind $requested }
        }
        if ($main.state -eq 'Absent') {
            # A resource cannot outlive its deleted containing group.
            foreach ($kind in @('aks', 'vm')) {
                $script:CleanupEvidence[$kind] = @{ state = 'Absent'; proof = 'containing-group-absent' }
            }
        }

        # Request owned main cleanup before any independent residual call can
        # deny access, stall, or consume the remaining execution deadline.
        if ($mainOwned -and $coreAbsent) {
            $fresh = Get-CleanupResource 'group'
            if ($null -ne $fresh) {
                Assert-Ownership $fresh $m $m.ids.group
                Request-CleanupDeletion 'group' $requested
            } else {
                $script:CleanupEvidence.group = @{ state = 'Absent'; proof = 'get-404' }
            }
        }
        if ($coreAbsent -and $m.requireNodeScope) {
            $node = Observe-CleanupResource 'nodeGroup'
            if ($node.state -eq 'Present') {
                try {
                    Assert-ResourceIdentity $node.resource $m.ids.nodeGroup
                    Assert-Cleanup ([string]::Equals($node.resource.managedBy, $m.ids.aks,
                        [StringComparison]::OrdinalIgnoreCase)) 'node-group-owner-mismatch'
                    Request-CleanupDeletion 'nodeGroup' $requested
                } catch { Set-CleanupRefused 'nodeGroup' }
            }
        }
        if ($coreAbsent -and $m.requirePeeringScope) {
            $peer = Observe-CleanupResource 'peer'
            if ($peer.state -eq 'Present') {
                try {
                    Assert-ResourceIdentity $peer.resource $m.ids.peer
                    Assert-Cleanup ([string]::Equals($peer.resource.properties.remoteVirtualNetwork.id,
                        $m.ids.vnet, [StringComparison]::OrdinalIgnoreCase)) 'peering-remote-mismatch'
                    Request-CleanupDeletion 'peer' $requested
                } catch { Set-CleanupRefused 'peer' }
            }
        }

        $required = @('group')
        if ($m.requireNodeScope) { $required += 'nodeGroup' }
        if ($m.requirePeeringScope) { $required += 'peer' }
        if (@($required | Where-Object { $script:CleanupEvidence[$_].state -ne 'Absent' }).Count -eq 0) {
            return @{ outcome = 'cleanup-succeeded'; evidence = $script:CleanupEvidence;
                deleteRequests = @($requested.Keys);
                late = ((Get-CleanupTime) -gt [DateTimeOffset]::Parse($m.expiresAtUtc)) }
        }
        $uncertain = @($required | Where-Object { $script:CleanupEvidence[$_].state -in @('Unverified', 'Refused') })
        $pending = @($required | Where-Object { $script:CleanupEvidence[$_].state -in @('Present', 'Pending') })
        if ($uncertain.Count -gt 0 -and $pending.Count -eq 0) {
            throw 'cleanup-residual-verification-required'
        }
        if (-not $coreAbsent) {
            foreach ($kind in @('group', 'aks', 'vm')) {
                if ($script:CleanupEvidence[$kind].state -in @('Unverified', 'Refused')) {
                    throw 'main-cleanup-verification-required'
                }
            }
        }
        Start-Sleep -Seconds 15
    }
    throw 'cleanup-deadline-reached'
}

if (-not $LibraryOnly) {
    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $script:Http = [Net.Http.HttpClient]::new($handler)
    $script:Http.Timeout = [TimeSpan]::FromSeconds(30)
    $script:Token = ''
    $script:TokenExpires = [DateTimeOffset]::MinValue
    $script:CleanupEvidence = @{}
    $script:CleanupRequested = @{}
    try {
        Invoke-FoundationCleanup $ManifestJson $Mode | ConvertTo-Json -Compress -Depth 4 | Write-Output
    } catch {
        # Never serialize HTTP exceptions, token responses, headers or full manifests.
        @{ outcome = 'cleanup-failed'; detail = 'inspect-safe-operator-receipt';
            evidence = $script:CleanupEvidence; deleteRequests = @($script:CleanupRequested.Keys)
        } | ConvertTo-Json -Compress -Depth 5 | Write-Output
        throw 'bounded-foundation-cleanup-failed'
    } finally {
        $script:Token = ''
        $script:Http.Dispose()
        $handler.Dispose()
    }
}
