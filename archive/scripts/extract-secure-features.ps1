# ============================================================
# Secure Kubernetes Feature Extraction
# Cluster: kind-ml-secure-cluster
# Namespace: security-lab
# ============================================================

# Get deployments from the secure cluster
$deployments = kubectl --context kind-ml-secure-cluster `
    get deployments -n security-lab -o json |
    ConvertFrom-Json

# Get NetworkPolicies from the secure cluster
$networkPolicies = kubectl --context kind-ml-secure-cluster `
    get networkpolicies -n security-lab -o json |
    ConvertFrom-Json

$rows = foreach ($d in $deployments.items) {

    $p = $d.spec.template.spec
    $containers = @($p.containers)

    # --------------------------------------------------------
    # Privileged containers
    # --------------------------------------------------------
    $privilegedCount = @(
        $containers | Where-Object {
            $_.securityContext.privileged -eq $true
        }
    ).Count

    # --------------------------------------------------------
    # Explicitly configured root containers
    # Checks container-level first, then Pod-level
    # --------------------------------------------------------
    $rootCount = @(
        $containers | Where-Object {

            if ($null -ne $_.securityContext.runAsUser) {
                $_.securityContext.runAsUser -eq 0
            }
            else {
                $p.securityContext.runAsUser -eq 0
            }
        }
    ).Count

    # --------------------------------------------------------
    # Containers configured to run as non-root
    # Checks container-level first, then Pod-level
    # --------------------------------------------------------
    $nonRootCount = @(
        $containers | Where-Object {

            if ($null -ne $_.securityContext.runAsNonRoot) {
                $_.securityContext.runAsNonRoot -eq $true
            }
            else {
                $p.securityContext.runAsNonRoot -eq $true
            }
        }
    ).Count

    # --------------------------------------------------------
    # Privilege escalation
    # Counts containers where it is NOT explicitly disabled
    # --------------------------------------------------------
    $privEscCount = @(
        $containers | Where-Object {
            $_.securityContext.allowPrivilegeEscalation -ne $false
        }
    ).Count

    # --------------------------------------------------------
    # Read-only root filesystem
    # --------------------------------------------------------
    $readOnlyCount = @(
        $containers | Where-Object {
            $_.securityContext.readOnlyRootFilesystem -eq $true
        }
    ).Count

    # --------------------------------------------------------
    # Added Linux capabilities
    # --------------------------------------------------------
    $capAddedCount = 0

    foreach ($c in $containers) {

        if ($null -ne $c.securityContext.capabilities.add) {

            $capAddedCount += @(
                $c.securityContext.capabilities.add
            ).Count
        }
    }

    # --------------------------------------------------------
    # Drop ALL capabilities
    # --------------------------------------------------------
    $capDropAllCount = @(
        $containers | Where-Object {
            $_.securityContext.capabilities.drop -contains "ALL"
        }
    ).Count

    # --------------------------------------------------------
    # Host ports
    # --------------------------------------------------------
    $hostPortCount = @(
        $containers | ForEach-Object {

            @($_.ports) | Where-Object {
                $_.hostPort
            }
        }
    ).Count

    # --------------------------------------------------------
    # Missing CPU limits
    # --------------------------------------------------------
    $cpuMissingCount = @(
        $containers | Where-Object {
            -not $_.resources.limits.cpu
        }
    ).Count

    # --------------------------------------------------------
    # Missing memory limits
    # --------------------------------------------------------
    $memoryMissingCount = @(
        $containers | Where-Object {
            -not $_.resources.limits.memory
        }
    ).Count

    # --------------------------------------------------------
    # RuntimeDefault seccomp
    # Checks Pod-level first and container-level settings
    # --------------------------------------------------------
    $seccompDefault = (

        ($p.securityContext.seccompProfile.type -eq "RuntimeDefault") -or

        (
            @(
                $containers | Where-Object {
                    $_.securityContext.seccompProfile.type -eq "RuntimeDefault"
                }
            ).Count -gt 0
        )
    )

    # --------------------------------------------------------
    # Service account token
    # TRUE when Kubernetes will automatically mount the token
    # --------------------------------------------------------
    $serviceAccountToken = (

        $null -eq $p.automountServiceAccountToken -or
        $p.automountServiceAccountToken -eq $true
    )

    # --------------------------------------------------------
    # Application label
    # Used to locate the running Pod and NetworkPolicy
    # --------------------------------------------------------
    $appLabel = $d.spec.template.metadata.labels.app

    # --------------------------------------------------------
    # Effective runtime root count
    #
    # This checks the ACTUAL UID inside each running container.
    # UID 0 = root.
    # --------------------------------------------------------
    $effectiveRootCount = 0

    if ($appLabel) {

        $podName = kubectl --context kind-ml-secure-cluster `
            -n security-lab `
            get pods `
            -l "app=$appLabel" `
            -o jsonpath='{.items[0].metadata.name}' `
            2>$null

        if ($podName) {

            $podInfo = kubectl --context kind-ml-secure-cluster `
                -n security-lab `
                get pod $podName `
                -o json |
                ConvertFrom-Json

            foreach ($container in @($podInfo.spec.containers)) {

                $uidText = kubectl --context kind-ml-secure-cluster `
                    -n security-lab `
                    exec $podName `
                    -c $container.name `
                    -- id -u `
                    2>$null

                $uid = ($uidText | Out-String).Trim()

                if ($uid -eq "0") {
                    $effectiveRootCount++
                }
            }
        }
    }

    # --------------------------------------------------------
    # NetworkPolicy
    # Matches the workload's app label
    # --------------------------------------------------------
    $networkPolicyPresent = @(
        $networkPolicies.items | Where-Object {

            $_.spec.podSelector.matchLabels.app -eq $appLabel
        }
    ).Count -gt 0

    # --------------------------------------------------------
    # Create feature row
    # --------------------------------------------------------
    [PSCustomObject]@{

        namespace                    = $d.metadata.namespace
        deployment                   = $d.metadata.name

        # Target label
        # 1 = secure
        label                        = 1

        # Container/security features
        container_count              = $containers.Count
        privileged_count             = $privilegedCount
        run_as_root_count            = $rootCount

        # NEW: actual runtime UID=0 count
        effective_root_count         = $effectiveRootCount

        run_as_nonroot_count         = $nonRootCount
        allow_priv_esc_count         = $privEscCount
        readonly_rootfs_count        = $readOnlyCount
        capabilities_added_count     = [int]$capAddedCount
        capabilities_drop_all_count  = $capDropAllCount

        # Host-level configuration
        host_network                 = [int][bool]$p.hostNetwork
        host_pid                     = [int][bool]$p.hostPID
        host_ipc                     = [int][bool]$p.hostIPC
        hostport_count               = $hostPortCount

        # Resource limits
        cpu_limit_missing            = $cpuMissingCount
        memory_limit_missing         = $memoryMissingCount

        # Service account token
        service_account_token        = [int]$serviceAccountToken

        # HostPath volumes
        hostpath_count               = @(
            $p.volumes | Where-Object {
                $_.hostPath
            }
        ).Count

        # Seccomp
        seccomp_runtime_default      = [int]$seccompDefault

        # runAsGroup
        # Missing only when neither container nor Pod defines it
        run_as_group_missing         = @(
            $containers | Where-Object {

                if ($null -ne $_.securityContext.runAsGroup) {
                    $false
                }
                else {
                    $null -eq $p.securityContext.runAsGroup
                }
            }
        ).Count

        # NetworkPolicy
        network_policy_present       = [int]$networkPolicyPresent
    }
}

# ============================================================
# Export dataset
# ============================================================

$rows | Export-Csv `
    "reports\baseline\secure-config-features.csv" `
    -NoTypeInformation `
    -Encoding UTF8

Write-Host "Secure feature extraction complete."
Write-Host "Rows extracted: $($rows.Count)"
Write-Host "Output: reports\baseline\secure-config-features.csv"