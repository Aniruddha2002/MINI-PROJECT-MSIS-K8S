$deployments = kubectl --kubeconfig "tools\kubeconfig-ml-insecure.yaml" get deployments -A -o json | ConvertFrom-Json

$rows = foreach ($d in $deployments.items) {

    if ($d.metadata.namespace -in @("default", "big-monolith", "secure-middleware")) {

        $p = $d.spec.template.spec
        $containers = @($p.containers)

        $privilegedCount = @(
            $containers | Where-Object {
                $_.securityContext.privileged -eq $true
            }
        ).Count

        $rootCount = @(
            $containers | Where-Object {
                $_.securityContext.runAsUser -eq 0
            }
        ).Count

        $nonRootCount = @(
            $containers | Where-Object {
                $_.securityContext.runAsNonRoot -eq $true
            }
        ).Count

        $privEscCount = @(
            $containers | Where-Object {
                $_.securityContext.allowPrivilegeEscalation -ne $false
            }
        ).Count

        $readOnlyCount = @(
            $containers | Where-Object {
                $_.securityContext.readOnlyRootFilesystem -eq $true
            }
        ).Count

        $capAddedCount = (
            $containers | ForEach-Object {
                @($_.securityContext.capabilities.add).Count
            } | Measure-Object -Sum
        ).Sum

        $capDropAllCount = @(
            $containers | Where-Object {
                $_.securityContext.capabilities.drop -contains "ALL"
            }
        ).Count

        $hostPortCount = @(
            $containers | ForEach-Object {
                @($_.ports) | Where-Object { $_.hostPort }
            }
        ).Count

        $cpuMissingCount = @(
            $containers | Where-Object {
                -not $_.resources.limits.cpu
            }
        ).Count

        $memoryMissingCount = @(
            $containers | Where-Object {
                -not $_.resources.limits.memory
            }
        ).Count

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

        $serviceAccountToken = (
            $null -eq $p.automountServiceAccountToken -or
            $p.automountServiceAccountToken -eq $true
        )

        [PSCustomObject]@{
            namespace                    = $d.metadata.namespace
            deployment                   = $d.metadata.name
            label                        = 0
            container_count              = $containers.Count
            privileged_count             = $privilegedCount
            run_as_root_count            = $rootCount
            run_as_nonroot_count         = $nonRootCount
            allow_priv_esc_count         = $privEscCount
            readonly_rootfs_count        = $readOnlyCount
            capabilities_added_count     = [int]$capAddedCount
            capabilities_drop_all_count  = $capDropAllCount
            host_network                 = [int][bool]$p.hostNetwork
            host_pid                     = [int][bool]$p.hostPID
            host_ipc                     = [int][bool]$p.hostIPC
            hostport_count               = $hostPortCount
            cpu_limit_missing            = $cpuMissingCount
            memory_limit_missing         = $memoryMissingCount
            service_account_token        = [int]$serviceAccountToken
            hostpath_count               = @(
                $p.volumes | Where-Object { $_.hostPath }
            ).Count
            seccomp_runtime_default      = [int]$seccompDefault
            run_as_group_missing         = @(
                $containers | Where-Object {
                    -not $_.securityContext.runAsGroup
                }
            ).Count
        }
    }
}

$rows | Export-Csv `
    "reports\insecure\goat-config-features.csv" `
    -NoTypeInformation `
    -Encoding UTF8

Write-Host "Feature extraction complete."
Write-Host "Rows extracted: $($rows.Count)"
Write-Host "Output: reports\insecure\goat-config-features.csv"