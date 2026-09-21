# ============================================================
# Controlled Kubernetes Variant Feature Extraction
# Cluster: kind-ml-secure-cluster
# Namespace: ml-variants
# ============================================================

$context = "kind-ml-secure-cluster"
$namespace = "ml-variants"

$planPath = "D:\MINI PROJECT\KUBERNATES SECURITY\data\dataset\variant_plan.csv"
$outputPath = "D:\MINI PROJECT\KUBERNATES SECURITY\reports\variants\variant-config-features.csv"

# Create output directory if it does not exist
$outputDir = Split-Path $outputPath -Parent

if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}


# ------------------------------------------------------------
# Read variant plan
# ------------------------------------------------------------
$variantPlan = Import-Csv $planPath


# ------------------------------------------------------------
# Get all Deployments in the variant namespace
# ------------------------------------------------------------
$deployments = kubectl `
    --context $context `
    get deployments `
    -n $namespace `
    -o json |
    ConvertFrom-Json


# ------------------------------------------------------------
# Get all NetworkPolicies
# ------------------------------------------------------------
$networkPolicies = kubectl `
    --context $context `
    get networkpolicies `
    -n $namespace `
    -o json |
    ConvertFrom-Json


$rows = foreach ($d in $deployments.items) {

    # Only process our variant deployments
    if ($d.metadata.name -notmatch "^variant-v\d+$") {
        continue
    }


    # --------------------------------------------------------
    # Deployment information
    # --------------------------------------------------------
    $deploymentName = $d.metadata.name

    $variantNumber = (
        $deploymentName -replace "^variant-v", ""
    )

    $variantName = "V" + $variantNumber.PadLeft(2, "0")


    # --------------------------------------------------------
    # Get label from variant_plan.csv
    # --------------------------------------------------------
    $planEntry = @(
        $variantPlan | Where-Object {
            $_.variant -eq $variantName
        }
    ) | Select-Object -First 1


    if ($null -eq $planEntry) {
        Write-Warning "No plan entry found for $variantName. Skipping."
        continue
    }


    $label = [int]$planEntry.label


    # --------------------------------------------------------
    # Pod specification
    # --------------------------------------------------------
    $p = $d.spec.template.spec

    $containers = @($p.containers)


    # ========================================================
    # 1. Privileged containers
    # ========================================================
    $privilegedCount = @(
        $containers | Where-Object {
            $_.securityContext.privileged -eq $true
        }
    ).Count


    # ========================================================
    # 2. Explicit YAML root configuration
    # ========================================================
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


    # ========================================================
    # 3. Configured non-root containers
    # ========================================================
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


    # ========================================================
    # 4. Privilege escalation
    # ========================================================
    $privEscCount = @(
        $containers | Where-Object {

            $_.securityContext.allowPrivilegeEscalation -ne $false
        }
    ).Count


    # ========================================================
    # 5. Read-only root filesystem
    # ========================================================
    $readOnlyCount = @(
        $containers | Where-Object {

            $_.securityContext.readOnlyRootFilesystem -eq $true
        }
    ).Count


    # ========================================================
    # 6. Drop ALL capabilities
    # ========================================================
    $capDropAllCount = @(
        $containers | Where-Object {

            $_.securityContext.capabilities.drop -contains "ALL"
        }
    ).Count


    # ========================================================
    # 7. Host PID
    # ========================================================
    $hostPid = [int][bool]$p.hostPID


    # ========================================================
    # 8. Host IPC
    # ========================================================
    $hostIpc = [int][bool]$p.hostIPC


    # ========================================================
    # 9. Missing CPU limits
    # ========================================================
    $cpuMissingCount = @(
        $containers | Where-Object {

            -not $_.resources.limits.cpu
        }
    ).Count


    # ========================================================
    # 10. Missing memory limits
    # ========================================================
    $memoryMissingCount = @(
        $containers | Where-Object {

            -not $_.resources.limits.memory
        }
    ).Count


    # ========================================================
    # 11. Service account token
    # ========================================================
    $serviceAccountToken = (

        $null -eq $p.automountServiceAccountToken -or
        $p.automountServiceAccountToken -eq $true
    )


    # ========================================================
    # 12. HostPath count
    # ========================================================
    $hostPathCount = @(
        $p.volumes | Where-Object {

            $_.hostPath
        }
    ).Count


    # ========================================================
    # 13. RuntimeDefault seccomp
    # ========================================================
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


    # ========================================================
    # 14. runAsGroup missing
    # ========================================================
    $runAsGroupMissing = @(
        $containers | Where-Object {

            if ($null -ne $_.securityContext.runAsGroup) {

                $false
            }
            else {

                $null -eq $p.securityContext.runAsGroup
            }
        }
    ).Count


    # ========================================================
    # 15. Application label
    # ========================================================
    $appLabel = $d.spec.template.metadata.labels.app


    # ========================================================
    # 16. NetworkPolicy
    # ========================================================
    $networkPolicyPresent = $false

    if ($appLabel) {

        $networkPolicyPresent = @(
            $networkPolicies.items | Where-Object {

                $_.spec.podSelector.matchLabels.app -eq $appLabel
            }
        ).Count -gt 0
    }


    # ========================================================
    # 17. Find running Pod using Deployment selector
    # ========================================================
    $selectorParts = @()

    foreach (
        $prop in $d.spec.selector.matchLabels.PSObject.Properties
    ) {

        $selectorParts += (
            $prop.Name + "=" + $prop.Value
        )
    }

    $selectorString = $selectorParts -join ","


    $podName = ""

    if ($selectorString) {

        $podName = kubectl `
            --context $context `
            -n $namespace `
            get pods `
            -l $selectorString `
            -o jsonpath='{.items[0].metadata.name}' `
            2>$null
    }


    # ========================================================
    # 18. Effective runtime root count
    #
    # UID 0 = root
    # ========================================================
    $effectiveRootCount = 0

    if ($podName) {

        foreach ($container in $containers) {

            $uidText = kubectl `
                --context $context `
                -n $namespace `
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


    # ========================================================
    # Create feature row
    # ========================================================
    [PSCustomObject]@{

        variant                      = $variantName

        deployment                   = $deploymentName

        container_count              = $containers.Count

        privileged_count             = $privilegedCount

        run_as_root_count            = $rootCount

        effective_root_count         = $effectiveRootCount

        run_as_nonroot_count         = $nonRootCount

        allow_priv_esc_count         = $privEscCount

        readonly_rootfs_count        = $readOnlyCount

        capabilities_drop_all_count  = $capDropAllCount

        host_pid                     = $hostPid

        host_ipc                     = $hostIpc

        cpu_limit_missing            = $cpuMissingCount

        memory_limit_missing         = $memoryMissingCount

        service_account_token        = [int]$serviceAccountToken

        hostpath_count               = $hostPathCount

        seccomp_runtime_default      = [int]$seccompDefault

        run_as_group_missing         = $runAsGroupMissing

        network_policy_present       = [int]$networkPolicyPresent

        label                        = $label
    }
}


# ============================================================
# Sort variants numerically
# ============================================================
$rows = @(
    $rows |
    Sort-Object {
        [int]($_.variant -replace "^V", "")
    }
)


# ============================================================
# Export dataset
# ============================================================
$rows | Export-Csv `
    $outputPath `
    -NoTypeInformation `
    -Encoding UTF8


# ============================================================
# Summary
# ============================================================
Write-Host "Variant feature extraction complete."
Write-Host ("Rows extracted: " + $rows.Count)
Write-Host ("Output: " + $outputPath)

Write-Host ""
Write-Host "Label distribution:"

$rows |
    Group-Object label |
    Select-Object Name, Count |
    Format-Table -AutoSize