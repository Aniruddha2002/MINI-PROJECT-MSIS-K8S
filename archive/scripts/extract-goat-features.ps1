# ============================================================
# Insecure Kubernetes Goat Feature Extraction
# Cluster: kind-ml-insecure-cluster
# ============================================================

$kubeconfig = "tools\kubeconfig-ml-insecure.yaml"

# ------------------------------------------------------------
# Get all deployments
# ------------------------------------------------------------
$deployments = kubectl --kubeconfig $kubeconfig `
    get deployments -A -o json |
    ConvertFrom-Json

# ------------------------------------------------------------
# Get all NetworkPolicies
# ------------------------------------------------------------
$networkPolicies = kubectl --kubeconfig $kubeconfig `
    get networkpolicies -A -o json |
    ConvertFrom-Json


$rows = foreach ($d in $deployments.items) {

    # --------------------------------------------------------
    # Only process Kubernetes Goat application namespaces
    # --------------------------------------------------------
    if ($d.metadata.namespace -in @(
        "default",
        "big-monolith",
        "secure-middleware"
    )) {

        $namespace = $d.metadata.namespace

        $p = $d.spec.template.spec

        $containers = @($p.containers)


        # ====================================================
        # 1. Privileged containers
        # ====================================================
        $privilegedCount = @(
            $containers | Where-Object {
                $_.securityContext.privileged -eq $true
            }
        ).Count


        # ====================================================
        # 2. Explicitly configured root containers
        #
        # Check container-level first.
        # If absent, check Pod-level.
        # ====================================================
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


        # ====================================================
        # 3. Containers configured as non-root
        #
        # Check container-level first.
        # If absent, check Pod-level.
        # ====================================================
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


        # ====================================================
        # 4. Privilege escalation
        #
        # Count containers where the setting is not explicitly
        # disabled.
        # ====================================================
        $privEscCount = @(
            $containers | Where-Object {

                $_.securityContext.allowPrivilegeEscalation -ne $false
            }
        ).Count


        # ====================================================
        # 5. Read-only root filesystem
        # ====================================================
        $readOnlyCount = @(
            $containers | Where-Object {

                $_.securityContext.readOnlyRootFilesystem -eq $true
            }
        ).Count


        # ====================================================
        # 6. Added Linux capabilities
        # ====================================================
        $capAddedCount = 0

        foreach ($c in $containers) {

            if ($null -ne $c.securityContext.capabilities.add) {

                $capAddedCount += @(
                    $c.securityContext.capabilities.add
                ).Count
            }
        }


        # ====================================================
        # 7. Containers dropping ALL capabilities
        # ====================================================
        $capDropAllCount = @(
            $containers | Where-Object {

                $_.securityContext.capabilities.drop -contains "ALL"
            }
        ).Count


        # ====================================================
        # 8. Host ports
        # ====================================================
        $hostPortCount = @(
            $containers | ForEach-Object {

                @($_.ports) | Where-Object {
                    $_.hostPort
                }
            }
        ).Count


        # ====================================================
        # 9. Missing CPU limits
        # ====================================================
        $cpuMissingCount = @(
            $containers | Where-Object {

                -not $_.resources.limits.cpu
            }
        ).Count


        # ====================================================
        # 10. Missing memory limits
        # ====================================================
        $memoryMissingCount = @(
            $containers | Where-Object {

                -not $_.resources.limits.memory
            }
        ).Count


        # ====================================================
        # 11. RuntimeDefault seccomp
        #
        # Check Pod-level and container-level settings.
        # ====================================================
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


        # ====================================================
        # 12. Service account token
        #
        # Kubernetes automatically mounts the token unless
        # automountServiceAccountToken is explicitly false.
        # ====================================================
        $serviceAccountToken = (

            $null -eq $p.automountServiceAccountToken -or
            $p.automountServiceAccountToken -eq $true
        )


        # ====================================================
        # 13. Application label
        # ====================================================
        $appLabel = $d.spec.template.metadata.labels.app


        # ====================================================
        # 14. Find the corresponding running Pod
        #
        # Build the selector directly from the Deployment's
        # selector.matchLabels.
        #
        # This also works for metadata-db, whose selector is:
        #
        # app.kubernetes.io/instance=metadata-db
        # app.kubernetes.io/name=metadata-db
        # ====================================================
        $selectorParts = @()

        foreach ($prop in $d.spec.selector.matchLabels.PSObject.Properties) {

            $selectorParts += ($prop.Name + "=" + $prop.Value)
        }

        $selectorString = $selectorParts -join ","


        $podName = ""

        if ($selectorString) {

            $podName = kubectl `
                --kubeconfig $kubeconfig `
                -n $namespace `
                get pods `
                -l $selectorString `
                -o jsonpath='{.items[0].metadata.name}' `
                2>$null
        }


        # ====================================================
        # 15. Effective runtime root count
        #
        # UID 0 = root
        #
        # This is different from run_as_root_count:
        #
        # run_as_root_count
        #     = explicitly configured runAsUser: 0
        #
        # effective_root_count
        #     = actual UID observed inside the running
        #       container
        # ====================================================
        $effectiveRootCount = 0

        if ($podName) {

            foreach ($container in $containers) {

                $uidText = kubectl `
                    --kubeconfig $kubeconfig `
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


        # ====================================================
        # 16. NetworkPolicy
        #
        # Check whether a NetworkPolicy selects this
        # workload's Pod.
        # ====================================================
        $networkPolicyPresent = $false

        if ($appLabel) {

            $networkPolicyPresent = @(
                $networkPolicies.items | Where-Object {

                    $_.metadata.namespace -eq $namespace -and

                    $_.spec.podSelector.matchLabels.app -eq $appLabel
                }
            ).Count -gt 0
        }


        # ====================================================
        # 17. Create the feature row
        # ====================================================
        [PSCustomObject]@{

            namespace                    = $namespace

            deployment                   = $d.metadata.name

            # 0 = insecure
            label                        = 0


            # ------------------------------------------------
            # Container security
            # ------------------------------------------------
            container_count              = $containers.Count

            privileged_count             = $privilegedCount

            # Explicit YAML root configuration
            run_as_root_count            = $rootCount

            # Actual runtime UID 0
            effective_root_count         = $effectiveRootCount

            run_as_nonroot_count         = $nonRootCount

            allow_priv_esc_count         = $privEscCount

            readonly_rootfs_count        = $readOnlyCount


            # ------------------------------------------------
            # Linux capabilities
            # ------------------------------------------------
            capabilities_added_count    = [int]$capAddedCount

            capabilities_drop_all_count = $capDropAllCount


            # ------------------------------------------------
            # Host-level settings
            # ------------------------------------------------
            host_network                 = [int][bool]$p.hostNetwork

            host_pid                     = [int][bool]$p.hostPID

            host_ipc                     = [int][bool]$p.hostIPC

            hostport_count               = $hostPortCount


            # ------------------------------------------------
            # Resource limits
            # ------------------------------------------------
            cpu_limit_missing            = $cpuMissingCount

            memory_limit_missing         = $memoryMissingCount


            # ------------------------------------------------
            # Service account
            # ------------------------------------------------
            service_account_token        = [int]$serviceAccountToken


            # ------------------------------------------------
            # HostPath
            # ------------------------------------------------
            hostpath_count               = @(
                $p.volumes | Where-Object {

                    $_.hostPath
                }
            ).Count


            # ------------------------------------------------
            # Seccomp
            # ------------------------------------------------
            seccomp_runtime_default      = [int]$seccompDefault


            # ------------------------------------------------
            # runAsGroup
            #
            # Missing only if neither the container nor
            # Pod securityContext defines it.
            # ------------------------------------------------
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


            # ------------------------------------------------
            # NetworkPolicy
            # ------------------------------------------------
            network_policy_present       = [int]$networkPolicyPresent
        }
    }
}


# ============================================================
# Export dataset
# ============================================================

$rows | Export-Csv `
    "reports\insecure\goat-config-features.csv" `
    -NoTypeInformation `
    -Encoding UTF8


# ============================================================
# Output summary
# ============================================================

Write-Host "Insecure feature extraction complete."
Write-Host "Rows extracted: $($rows.Count)"
Write-Host "Output: reports\insecure\goat-config-features.csv"