
import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

import joblib
import pandas as pd


MODEL_PATH = Path(__file__).resolve().with_name("final_security_model.joblib")

FEATURES = [
    "container_count",
    "privileged_count",
    "effective_root_count",
    "run_as_nonroot_count",
    "allow_priv_esc_count",
    "readonly_rootfs_count",
    "capabilities_drop_all_count",
    "host_pid",
    "host_ipc",
    "cpu_limit_missing",
    "memory_limit_missing",
    "service_account_token",
    "hostpath_count",
    "seccomp_runtime_default",
    "run_as_group_missing",
    "network_policy_present",
]


def run_kubectl(context, *args):
    command = ["kubectl", "--context", context, *args]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    if result.returncode != 0:
        raise RuntimeError(
            "kubectl command failed:\n"
            + " ".join(command)
            + "\n\n"
            + result.stderr.strip()
        )

    return result.stdout


def kubectl_json(context, *args):
    output = run_kubectl(context, *args, "-o", "json")
    try:
        return json.loads(output)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"kubectl returned invalid JSON for: {' '.join(args)}"
        ) from exc


def safe_filename(value):
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value)


def container_security_context(container):
    return container.get("securityContext") or {}


def pod_security_context(pod_spec):
    return pod_spec.get("securityContext") or {}


'''
def get_effective_root_count(context, namespace, pod_name, pod_containers):
    root_count = 0

    for container in pod_containers:
        container_name = container.get("name", "")

        result = subprocess.run(
            [
                "kubectl",
                "--context",
                context,
                "-n",
                namespace,
                "exec",
                pod_name,
                "-c",
                container_name,
                "--",
                "id",
                "-u",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

        if result.returncode != 0:
            raise RuntimeError(
                f"Could not determine runtime UID for container "
                f"'{container_name}' in pod '{pod_name}'.\n"
                f"kubectl error:\n{result.stderr.strip()}"
            )

        uid = result.stdout.strip()

        if uid == "0":
            root_count += 1

    return root_count
'''
def get_effective_root_count(pod):
    """
    Determine the actual runtime UID from Kubernetes PodStatus.

    Kubernetes exposes the runtime user under:
    status.containerStatuses[].user.linux.uid

    UID 0 means root.
    """

    root_count = 0

    container_statuses = (
        pod.get("status", {})
        .get("containerStatuses", [])
        or []
    )

    for container_status in container_statuses:
        linux_user = (
            container_status
            .get("user", {})
            .get("linux", {})
            or {}
        )

        uid = linux_user.get("uid")

        if uid == 0:
            root_count += 1

    return root_count


def deployment_selector(deployment):
    selector = (
        deployment.get("spec", {})
        .get("selector", {})
        .get("matchLabels", {})
    )

    if selector:
        return ",".join(
            f"{key}={value}"
            for key, value in selector.items()
        )

    template_labels = (
        deployment.get("spec", {})
        .get("template", {})
        .get("metadata", {})
        .get("labels", {})
    )

    if template_labels.get("app"):
        return f"app={template_labels['app']}"

    return None


def find_running_pod(
    context,
    namespace,
    deployment,
):
    selector = deployment_selector(deployment)

    if not selector:
        return None

    pods = kubectl_json(
        context,
        "get",
        "pods",
        "-n",
        namespace,
        "-l",
        selector,
    )

    for pod in pods.get("items", []):
        phase = (
            pod.get("status", {})
            .get("phase")
        )

        if phase == "Running":
            return pod

    return None


def policy_selects_labels(policy, pod_labels):
    selector = policy.get("spec", {}).get("podSelector") or {}

    if not selector:
        return True

    match_labels = selector.get("matchLabels") or {}

    for key, value in match_labels.items():
        if pod_labels.get(key) != value:
            return False

    expressions = selector.get("matchExpressions") or []

    for expression in expressions:
        key = expression.get("key")
        operator = expression.get("operator")
        values = expression.get("values") or []
        present = key in pod_labels
        actual = pod_labels.get(key)

        if operator == "In":
            if not present or actual not in values:
                return False

        elif operator == "NotIn":
            if present and actual in values:
                return False

        elif operator == "Exists":
            if not present:
                return False

        elif operator == "DoesNotExist":
            if present:
                return False

    return True


def network_policy_present(network_policies, namespace, pod_labels):
    namespace_policies = [
        policy
        for policy in network_policies
        if policy.get("metadata", {}).get("namespace") == namespace
    ]

    return any(
        policy_selects_labels(policy, pod_labels)
        for policy in namespace_policies
    )


def extract_features(context, namespace=None):
    if namespace:
        deployments_data = kubectl_json(
            context,
            "get",
            "deployments",
            "-n",
            namespace,
        )

        networkpolicy_data = kubectl_json(
            context,
            "get",
            "networkpolicies",
            "-n",
            namespace,
        )
    else:
        deployments_data = kubectl_json(
            context,
            "get",
            "deployments",
            "-A",
        )

        networkpolicy_data = kubectl_json(
            context,
            "get",
            "networkpolicies",
            "-A",
        )

    deployments = deployments_data.get("items", [])
    network_policies = networkpolicy_data.get("items", [])

    if not deployments:
        raise RuntimeError(
            "No Deployments were found in the selected scope."
        )

    rows = []

    for deployment in deployments:
        metadata = deployment.get("metadata", {})
        spec = deployment.get("spec", {})
        template = spec.get("template", {})
        pod_spec = template.get("spec", {}) or {}

        deployment_name = metadata.get("name", "unknown")
        deployment_namespace = metadata.get(
            "namespace",
            namespace or "default",
        )

        containers = pod_spec.get("containers") or []

        if not containers:
            continue

        template_labels = (
            template.get("metadata", {})
            .get("labels", {})
            or {}
        )

        pod_security = pod_security_context(pod_spec)

        privileged_count = 0
        root_count = 0
        non_root_count = 0
        privilege_escalation_count = 0
        readonly_count = 0
        capabilities_added_count = 0
        capabilities_drop_all_count = 0
        hostport_count = 0
        cpu_missing_count = 0
        memory_missing_count = 0
        hostpath_count = 0
        run_as_group_missing_count = 0

        for container in containers:
            container_sc = container_security_context(container)

            if container_sc.get("privileged") is True:
                privileged_count += 1

            if "runAsUser" in container_sc and container_sc["runAsUser"] is not None:
                if container_sc["runAsUser"] == 0:
                    root_count += 1
            elif pod_security.get("runAsUser") == 0:
                root_count += 1

            if "runAsNonRoot" in container_sc and container_sc["runAsNonRoot"] is not None:
                if container_sc["runAsNonRoot"] is True:
                    non_root_count += 1
            elif pod_security.get("runAsNonRoot") is True:
                non_root_count += 1

            if container_sc.get("allowPrivilegeEscalation") is not False:
                privilege_escalation_count += 1

            if container_sc.get("readOnlyRootFilesystem") is True:
                readonly_count += 1

            capabilities = container_sc.get("capabilities") or {}

            added = capabilities.get("add") or []
            capabilities_added_count += len(added)

            dropped = capabilities.get("drop") or []
            if "ALL" in dropped:
                capabilities_drop_all_count += 1

            for port in container.get("ports") or []:
                if port.get("hostPort"):
                    hostport_count += 1

            limits = (
                container.get("resources", {})
                .get("limits", {})
                or {}
            )

            if not limits.get("cpu"):
                cpu_missing_count += 1

            if not limits.get("memory"):
                memory_missing_count += 1

            if "runAsGroup" not in container_sc or container_sc.get("runAsGroup") is None:
                if pod_security.get("runAsGroup") is None:
                    run_as_group_missing_count += 1

            for volume in pod_spec.get("volumes") or []:
                if volume.get("hostPath"):
                    hostpath_count += 1

        service_account_token = (
            pod_spec.get("automountServiceAccountToken") is None
            or pod_spec.get("automountServiceAccountToken") is True
        )

        pod_seccomp = (
            pod_security.get("seccompProfile") or {}
        )

        seccomp_runtime_default = (
            pod_seccomp.get("type") == "RuntimeDefault"
        )

        if not seccomp_runtime_default:
            for container in containers:
                container_seccomp = (
                    container_security_context(container)
                    .get("seccompProfile")
                    or {}
                )

                if container_seccomp.get("type") == "RuntimeDefault":
                    seccomp_runtime_default = True
                    break

        host_network = int(bool(pod_spec.get("hostNetwork", False)))
        host_pid = int(bool(pod_spec.get("hostPID", False)))
        host_ipc = int(bool(pod_spec.get("hostIPC", False)))

        pod = find_running_pod(
            context,
            deployment_namespace,
            deployment,
        )

        if pod is None:
            raise RuntimeError(
                f"No Running pod found for deployment "
                f"'{deployment_name}' in namespace "
                f"'{deployment_namespace}'."
            )

        pod_name = pod["metadata"]["name"]
        runtime_containers = pod.get("spec", {}).get("containers", [])
	

        '''effective_root_count = get_effective_root_count(
            context,
            deployment_namespace,
            pod_name,
            runtime_containers,
        )'''
        effective_root_count = get_effective_root_count(pod)
        policy_present = network_policy_present(
            network_policies,
            deployment_namespace,
            template_labels,
        )

        rows.append(
            {
                "namespace": deployment_namespace,
                "deployment": deployment_name,
                "container_count": len(containers),
                "privileged_count": privileged_count,
                "run_as_root_count": root_count,
                "effective_root_count": effective_root_count,
                "run_as_nonroot_count": non_root_count,
                "allow_priv_esc_count": privilege_escalation_count,
                "readonly_rootfs_count": readonly_count,
                "capabilities_added_count": capabilities_added_count,
                "capabilities_drop_all_count": capabilities_drop_all_count,
                "host_network": host_network,
                "host_pid": host_pid,
                "host_ipc": host_ipc,
                "hostport_count": hostport_count,
                "cpu_limit_missing": cpu_missing_count,
                "memory_limit_missing": memory_missing_count,
                "service_account_token": int(service_account_token),
                "hostpath_count": hostpath_count,
                "seccomp_runtime_default": int(seccomp_runtime_default),
                "run_as_group_missing": run_as_group_missing_count,
                "network_policy_present": int(policy_present),
            }
        )

    return pd.DataFrame(rows)


def assess_dataframe(df):
    if not MODEL_PATH.exists():
        raise RuntimeError(
            f"Model not found: {MODEL_PATH}"
        )

    artifact = joblib.load(MODEL_PATH)

    model = artifact["model"]
    model_features = artifact["features"]
    threshold = artifact["threshold"]

    missing = [
        feature
        for feature in model_features
        if feature not in df.columns
    ]

    if missing:
        raise RuntimeError(
            "Missing required model features:\n"
            + "\n".join(f"- {feature}" for feature in missing)
        )

    X = df[model_features]

    probabilities = model.predict_proba(X)[:, 1]
    predictions = (
        probabilities >= threshold
    ).astype(int)

    result = df.copy()

    result["security_probability"] = probabilities
    result["predicted_label"] = predictions
    result["predicted_status"] = result[
        "predicted_label"
    ].map(
        {
            1: "SECURE",
            0: "INSECURE",
        }
    )

    score = probabilities.mean() * 100

    if score >= 80:
        category = "HIGH"
    elif score >= 60:
        category = "MEDIUM"
    else:
        category = "LOW"

    overall_status = (
        "SECURE"
        if score >= threshold * 100
        else "INSECURE"
    )

    return (
        result,
        score,
        category,
        overall_status,
        threshold,
    )


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Automatically extract Kubernetes security features "
            "and assess the cluster with the trained ML model."
        )
    )

    parser.add_argument(
        "--context",
        help=(
            "Kubernetes context. If omitted, uses the current "
            "kubectl context."
        ),
    )

    parser.add_argument(
        "--namespace",
        help=(
            "Optional namespace. If omitted, all namespaces are scanned."
        ),
    )

    parser.add_argument(
        "--output-dir",
        default=r"reports\auto_assessment",
        help="Directory for generated CSV files.",
    )

    args = parser.parse_args()

    if args.context:
        context = args.context
    else:
        current_context = subprocess.run(
            ["kubectl", "config", "current-context"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

        if current_context.returncode != 0:
            print(
                "Could not determine current kubectl context.",
                file=sys.stderr,
            )
            sys.exit(1)

        context = current_context.stdout.strip()

        if not context:
            print(
                "No current kubectl context is configured.",
                file=sys.stderr,
            )
            sys.exit(1)

    try:
        print()
        print("AUTOMATIC KUBERNETES SECURITY ASSESSMENT")
        print("========================================")
        print("Context:", context)

        if args.namespace:
            print("Namespace:", args.namespace)
        else:
            print("Namespace: ALL")

        print()
        print("Step 1: Extracting Kubernetes security features...")

        df = extract_features(
            context,
            args.namespace,
        )

        print(
            f"Workloads extracted: {len(df)}"
        )

        output_dir = Path(args.output_dir)
        output_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        context_file = safe_filename(context)

        feature_csv = (
            output_dir
            / f"{context_file}_features.csv"
        )

        df.to_csv(
            feature_csv,
            index=False,
        )

        print(
            "Feature CSV:",
            feature_csv,
        )

        print()
        print("Step 2: Running trained ML model...")

        result, score, category, overall_status, threshold = (
            assess_dataframe(df)
        )

        assessment_csv = (
            output_dir
            / f"{context_file}_assessment.csv"
        )

        result.to_csv(
            assessment_csv,
            index=False,
        )

        print()
        print("FINAL ASSESSMENT")
        print("================")
        print("Workloads assessed:", len(result))
        print(
            "Predicted SECURE:",
            int((result["predicted_label"] == 1).sum()),
        )
        print(
            "Predicted INSECURE:",
            int((result["predicted_label"] == 0).sum()),
        )
        print(
            f"Security Score: {score:.2f}/100"
        )
        print(
            f"Category: {category}"
        )
        print(
            f"Overall Status: {overall_status}"
        )
        print(
            f"Decision Threshold: {threshold:.2f}"
        )

        print()
        print("WORKLOAD RESULTS")
        print("=================")

        for index, row in result.iterrows():
            name = row.get(
                "deployment",
                f"Row-{index + 1}",
            )

            print(
                f"{name}: "
                f"{row['security_probability']:.6f} -> "
                f"{row['predicted_status']}"
            )

        print()
        print("Assessment CSV:")
        print(assessment_csv)

    except Exception as exc:
        print()
        print("ASSESSMENT FAILED")
        print("=================")
        print(str(exc))
        sys.exit(1)


if __name__ == "__main__":
    main()
