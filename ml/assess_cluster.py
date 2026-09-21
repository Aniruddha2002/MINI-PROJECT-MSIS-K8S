import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

import joblib
import pandas as pd


# ============================================================
# MODEL
# ============================================================

MODEL_PATH = (
    Path(__file__).resolve().with_name("final_security_model.joblib")
)


# ============================================================
# STANDARD KUBERNETES / INFRASTRUCTURE NAMESPACES
# ============================================================
#
# These namespaces normally contain Kubernetes infrastructure
# rather than application workloads.
#
# They are skipped automatically when --namespace is NOT supplied.
#
# Use --include-system-namespaces when you explicitly want to
# include them.
# ============================================================

SYSTEM_NAMESPACES = {
    "kube-system",
    "kube-public",
    "kube-node-lease",
    "local-path-storage",
}


# ============================================================
# FEATURES USED BY THE FINAL ML MODEL
# ============================================================

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


# ============================================================
# KUBECTL HELPERS
# ============================================================

def run_kubectl(context, *args):
    """
    Run kubectl against the selected Kubernetes context.
    """

    command = [
        "kubectl",
        "--context",
        context,
        *args,
    ]

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
    """
    Run kubectl and parse the result as JSON.
    """

    output = run_kubectl(
        context,
        *args,
        "-o",
        "json",
    )

    try:
        return json.loads(output)

    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"kubectl returned invalid JSON for: "
            f"{' '.join(args)}"
        ) from exc


# ============================================================
# GENERAL HELPERS
# ============================================================

def safe_filename(value):
    """
    Convert a Kubernetes context name into a safe filename.
    """

    return re.sub(
        r"[^A-Za-z0-9._-]+",
        "_",
        value,
    )


def container_security_context(container):
    """
    Return container securityContext or an empty dictionary.
    """

    return container.get("securityContext") or {}


def pod_security_context(pod_spec):
    """
    Return Pod securityContext or an empty dictionary.
    """

    return pod_spec.get("securityContext") or {}


# ============================================================
# EFFECTIVE RUNTIME ROOT CHECK
# ============================================================

def get_effective_root_count(pod):
    """
    Determine how many running containers actually have UID 0.

    Kubernetes exposes this through:

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


# ============================================================
# DEPLOYMENT → POD MATCHING
# ============================================================

def deployment_selector(deployment):
    """
    Obtain the Deployment's selector.

    Normally spec.selector.matchLabels is sufficient.
    """

    selector = (
        deployment
        .get("spec", {})
        .get("selector", {})
        .get("matchLabels", {})
    )

    if selector:

        return ",".join(
            f"{key}={value}"
            for key, value in selector.items()
        )

    template_labels = (
        deployment
        .get("spec", {})
        .get("template", {})
        .get("metadata", {})
        .get("labels", {})
        or {}
    )

    if template_labels.get("app"):

        return f"app={template_labels['app']}"

    return None


def find_running_pod(
    context,
    namespace,
    deployment,
):
    """
    Find a Running Pod belonging to the Deployment.
    """

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
            pod
            .get("status", {})
            .get("phase")
        )

        if phase == "Running":
            return pod

    return None


# ============================================================
# NETWORK POLICY CHECK
# ============================================================

def policy_selects_labels(
    policy,
    pod_labels,
):
    """
    Determine whether a NetworkPolicy selects a workload.

    An empty podSelector {} selects all Pods in the namespace.
    """

    selector = (
        policy
        .get("spec", {})
        .get("podSelector")
        or {}
    )

    # Empty podSelector means all Pods in that namespace.
    if not selector:
        return True

    match_labels = (
        selector.get("matchLabels")
        or {}
    )

    for key, value in match_labels.items():

        if pod_labels.get(key) != value:
            return False

    expressions = (
        selector.get("matchExpressions")
        or []
    )

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


def network_policy_present(
    network_policies,
    namespace,
    pod_labels,
):
    """
    Return True if at least one NetworkPolicy selects
    this workload.
    """

    namespace_policies = [
        policy
        for policy in network_policies
        if policy
        .get("metadata", {})
        .get("namespace") == namespace
    ]

    return any(
        policy_selects_labels(
            policy,
            pod_labels,
        )
        for policy in namespace_policies
    )


# ============================================================
# FEATURE EXTRACTION
# ============================================================

def extract_features(
    context,
    namespace=None,
    include_system_namespaces=False,
):
    """
    Extract security features from Kubernetes Deployments.

    Behavior:

    --namespace <name>
        Assess only that namespace.

    No --namespace
        Assess all application namespaces while skipping
        standard Kubernetes/system namespaces.

    --include-system-namespaces
        Include the standard system namespaces.
    """

    # --------------------------------------------------------
    # Get Deployments and NetworkPolicies
    # --------------------------------------------------------

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

    deployments = (
        deployments_data.get("items", [])
    )

    network_policies = (
        networkpolicy_data.get("items", [])
    )

    if not deployments:

        raise RuntimeError(
            "No Deployments were found in the selected scope."
        )

    rows = []

    skipped_system = 0

    # ========================================================
    # PROCESS EACH DEPLOYMENT
    # ========================================================

    for deployment in deployments:

        metadata = (
            deployment.get("metadata", {})
        )

        spec = (
            deployment.get("spec", {})
        )

        template = (
            spec.get("template", {})
        )

        pod_spec = (
            template.get("spec", {})
            or {}
        )

        deployment_name = (
            metadata.get(
                "name",
                "unknown",
            )
        )

        deployment_namespace = (
            metadata.get(
                "namespace",
                namespace or "default",
            )
        )

        # ----------------------------------------------------
        # Automatically skip standard system namespaces when
        # operating in cluster-wide mode.
        # ----------------------------------------------------

        if (
            namespace is None
            and not include_system_namespaces
            and deployment_namespace
            in SYSTEM_NAMESPACES
        ):
            skipped_system += 1
            continue

        containers = (
            pod_spec.get("containers")
            or []
        )

        if not containers:
            continue

        template_labels = (
            template
            .get("metadata", {})
            .get("labels", {})
            or {}
        )

        pod_security = (
            pod_security_context(
                pod_spec
            )
        )

        # ----------------------------------------------------
        # Initialize counters
        # ----------------------------------------------------

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

        # ====================================================
        # CONTAINER-LEVEL FEATURES
        # ====================================================

        for container in containers:

            container_sc = (
                container_security_context(
                    container
                )
            )

            # ------------------------------------------------
            # Privileged
            # ------------------------------------------------

            if (
                container_sc.get(
                    "privileged"
                )
                is True
            ):
                privileged_count += 1

            # ------------------------------------------------
            # Explicitly configured root
            # Container-level first, Pod-level second
            # ------------------------------------------------

            if (
                "runAsUser" in container_sc
                and container_sc["runAsUser"] is not None
            ):

                if (
                    container_sc["runAsUser"]
                    == 0
                ):
                    root_count += 1

            elif (
                pod_security.get(
                    "runAsUser"
                )
                == 0
            ):
                root_count += 1

            # ------------------------------------------------
            # runAsNonRoot
            # ------------------------------------------------

            if (
                "runAsNonRoot" in container_sc
                and container_sc["runAsNonRoot"] is not None
            ):

                if (
                    container_sc["runAsNonRoot"]
                    is True
                ):
                    non_root_count += 1

            elif (
                pod_security.get(
                    "runAsNonRoot"
                )
                is True
            ):
                non_root_count += 1

            # ------------------------------------------------
            # allowPrivilegeEscalation
            #
            # Count as risky unless explicitly false.
            # ------------------------------------------------

            if (
                container_sc.get(
                    "allowPrivilegeEscalation"
                )
                is not False
            ):
                privilege_escalation_count += 1

            # ------------------------------------------------
            # Read-only root filesystem
            # ------------------------------------------------

            if (
                container_sc.get(
                    "readOnlyRootFilesystem"
                )
                is True
            ):
                readonly_count += 1

            # ------------------------------------------------
            # Added capabilities
            # ------------------------------------------------

            capabilities = (
                container_sc.get(
                    "capabilities"
                )
                or {}
            )

            added = (
                capabilities.get("add")
                or []
            )

            capabilities_added_count += len(
                added
            )

            # ------------------------------------------------
            # Drop ALL capabilities
            # ------------------------------------------------

            dropped = (
                capabilities.get("drop")
                or []
            )

            if "ALL" in dropped:
                capabilities_drop_all_count += 1

            # ------------------------------------------------
            # Host ports
            # ------------------------------------------------

            for port in (
                container.get("ports")
                or []
            ):

                if port.get("hostPort"):
                    hostport_count += 1

            # ------------------------------------------------
            # CPU / Memory limits
            # ------------------------------------------------

            limits = (
                container
                .get("resources", {})
                .get("limits", {})
                or {}
            )

            if not limits.get("cpu"):
                cpu_missing_count += 1

            if not limits.get("memory"):
                memory_missing_count += 1

            # ------------------------------------------------
            # runAsGroup
            # Container-level first, Pod-level second
            # ------------------------------------------------

            if (
                "runAsGroup" not in container_sc
                or container_sc.get(
                    "runAsGroup"
                ) is None
            ):

                if (
                    pod_security.get(
                        "runAsGroup"
                    )
                    is None
                ):
                    run_as_group_missing_count += 1

            # ------------------------------------------------
            # HostPath volumes
            # ------------------------------------------------

            for volume in (
                pod_spec.get("volumes")
                or []
            ):

                if volume.get("hostPath"):
                    hostpath_count += 1

        # ====================================================
        # POD-LEVEL FEATURES
        # ====================================================

        # ----------------------------------------------------
        # Service account token
        #
        # Kubernetes automatically mounts a token when this
        # setting is omitted or true.
        # ----------------------------------------------------

        service_account_token = (
            pod_spec.get(
                "automountServiceAccountToken"
            )
            is None
            or
            pod_spec.get(
                "automountServiceAccountToken"
            )
            is True
        )

        # ----------------------------------------------------
        # Seccomp RuntimeDefault
        #
        # Check Pod-level first and container-level second.
        # ----------------------------------------------------

        pod_seccomp = (
            pod_security.get(
                "seccompProfile"
            )
            or {}
        )

        seccomp_runtime_default = (
            pod_seccomp.get("type")
            == "RuntimeDefault"
        )

        if not seccomp_runtime_default:

            for container in containers:

                container_seccomp = (
                    container_security_context(
                        container
                    )
                    .get(
                        "seccompProfile"
                    )
                    or {}
                )

                if (
                    container_seccomp.get(
                        "type"
                    )
                    == "RuntimeDefault"
                ):

                    seccomp_runtime_default = True
                    break

        # ----------------------------------------------------
        # Host namespaces
        # ----------------------------------------------------

        host_network = int(
            bool(
                pod_spec.get(
                    "hostNetwork",
                    False,
                )
            )
        )

        host_pid = int(
            bool(
                pod_spec.get(
                    "hostPID",
                    False,
                )
            )
        )

        host_ipc = int(
            bool(
                pod_spec.get(
                    "hostIPC",
                    False,
                )
            )
        )

        # ====================================================
        # FIND RUNNING POD
        # ====================================================

        pod = find_running_pod(
            context,
            deployment_namespace,
            deployment,
        )

        if pod is None:

            print(
                f"WARNING: No Running pod found for "
                f"{deployment_namespace}/"
                f"{deployment_name}. Skipping workload.",
                file=sys.stderr,
            )

            continue

        # ====================================================
        # EFFECTIVE RUNTIME ROOT
        # ====================================================

        effective_root_count = (
            get_effective_root_count(
                pod
            )
        )

        # ====================================================
        # NETWORK POLICY
        # ====================================================

        policy_present = (
            network_policy_present(
                network_policies,
                deployment_namespace,
                template_labels,
            )
        )

        # ====================================================
        # CREATE FEATURE ROW
        # ====================================================

        rows.append(
            {
                "namespace":
                    deployment_namespace,

                "deployment":
                    deployment_name,

                "container_count":
                    len(containers),

                "privileged_count":
                    privileged_count,

                "run_as_root_count":
                    root_count,

                "effective_root_count":
                    effective_root_count,

                "run_as_nonroot_count":
                    non_root_count,

                "allow_priv_esc_count":
                    privilege_escalation_count,

                "readonly_rootfs_count":
                    readonly_count,

                "capabilities_added_count":
                    capabilities_added_count,

                "capabilities_drop_all_count":
                    capabilities_drop_all_count,

                "host_network":
                    host_network,

                "host_pid":
                    host_pid,

                "host_ipc":
                    host_ipc,

                "hostport_count":
                    hostport_count,

                "cpu_limit_missing":
                    cpu_missing_count,

                "memory_limit_missing":
                    memory_missing_count,

                "service_account_token":
                    int(service_account_token),

                "hostpath_count":
                    hostpath_count,

                "seccomp_runtime_default":
                    int(seccomp_runtime_default),

                "run_as_group_missing":
                    run_as_group_missing_count,

                "network_policy_present":
                    int(policy_present),
            }
        )

    # ========================================================
    # FINAL EXTRACTION CHECK
    # ========================================================

    if not rows:

        raise RuntimeError(
            "No assessable application workloads were found."
        )

    if skipped_system > 0:

        print(
            f"System/infrastructure workloads skipped: "
            f"{skipped_system}"
        )

    return pd.DataFrame(rows)


# ============================================================
# MACHINE LEARNING ASSESSMENT
# ============================================================

def assess_dataframe(df):
    """
    Load the trained model and assess the extracted features.
    """

    if not MODEL_PATH.exists():

        raise RuntimeError(
            f"Model not found: {MODEL_PATH}"
        )

    artifact = joblib.load(
        MODEL_PATH
    )

    model = artifact["model"]
    model_features = artifact["features"]
    threshold = artifact["threshold"]

    # --------------------------------------------------------
    # Verify required model features
    # --------------------------------------------------------

    missing = [
        feature
        for feature in model_features
        if feature not in df.columns
    ]

    if missing:

        raise RuntimeError(
            "Missing required model features:\n"
            + "\n".join(
                f"- {feature}"
                for feature in missing
            )
        )

    # --------------------------------------------------------
    # Prepare model input
    # --------------------------------------------------------

    X = df[model_features]

    # --------------------------------------------------------
    # Predict probability of SECURE
    # --------------------------------------------------------

    probabilities = (
        model.predict_proba(X)[:, 1]
    )

    # --------------------------------------------------------
    # Apply trained decision threshold
    # --------------------------------------------------------

    predictions = (
        probabilities >= threshold
    ).astype(int)

    # --------------------------------------------------------
    # Build result dataframe
    # --------------------------------------------------------

    result = df.copy()

    result[
        "security_probability"
    ] = probabilities

    result[
        "predicted_label"
    ] = predictions

    result[
        "predicted_status"
    ] = result[
        "predicted_label"
    ].map(
        {
            1: "SECURE",
            0: "INSECURE",
        }
    )

    # --------------------------------------------------------
    # Overall score
    # --------------------------------------------------------

    score = (
        probabilities.mean()
        * 100
    )

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


# ============================================================
# MAIN
# ============================================================

def main():

    parser = argparse.ArgumentParser(
        description=(
            "Automatically extract Kubernetes security "
            "features and assess workloads using the "
            "trained ML model."
        )
    )

    # --------------------------------------------------------
    # Kubernetes context
    # --------------------------------------------------------

    parser.add_argument(
        "--context",
        help=(
            "Kubernetes context. If omitted, "
            "the current kubectl context is used."
        ),
    )

    # --------------------------------------------------------
    # Optional namespace
    # --------------------------------------------------------

    parser.add_argument(
        "--namespace",
        help=(
            "Assess only this namespace. If omitted, "
            "all application namespaces are assessed."
        ),
    )

    # --------------------------------------------------------
    # Optional system namespace override
    # --------------------------------------------------------

    parser.add_argument(
        "--include-system-namespaces",
        action="store_true",
        help=(
            "Include standard Kubernetes/system namespaces "
            "when scanning cluster-wide."
        ),
    )

    # --------------------------------------------------------
    # Output directory
    # --------------------------------------------------------

    parser.add_argument(
        "--output-dir",
        default=r"reports\auto_assessment",
        help=(
            "Directory for generated assessment files."
        ),
    )

    args = parser.parse_args()

    # ========================================================
    # DETERMINE KUBERNETES CONTEXT
    # ========================================================

    if args.context:

        context = args.context

    else:

        current_context = subprocess.run(
            [
                "kubectl",
                "config",
                "current-context",
            ],
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

        context = (
            current_context.stdout
            .strip()
        )

        if not context:

            print(
                "No current kubectl context is configured.",
                file=sys.stderr,
            )

            sys.exit(1)

    # ========================================================
    # ASSESSMENT
    # ========================================================

    try:

        print()
        print(
            "AUTOMATIC KUBERNETES SECURITY ASSESSMENT"
        )
        print(
            "========================================"
        )

        print(
            "Context:",
            context,
        )

        if args.namespace:

            print(
                "Namespace:",
                args.namespace,
            )

        elif args.include_system_namespaces:

            print(
                "Namespace: ALL "
                "(including system namespaces)"
            )

        else:

            print(
                "Namespace: ALL APPLICATION NAMESPACES"
            )

        # ----------------------------------------------------
        # STEP 1
        # ----------------------------------------------------

        print()
        print(
            "Step 1: Extracting Kubernetes "
            "security features..."
        )

        df = extract_features(
            context=context,
            namespace=args.namespace,
            include_system_namespaces=(
                args.include_system_namespaces
            ),
        )

        print(
            f"Workloads extracted: {len(df)}"
        )

        # ----------------------------------------------------
        # OUTPUT DIRECTORY
        # ----------------------------------------------------

        output_dir = Path(
            args.output_dir
        )

        output_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        context_file = safe_filename(
            context
        )

        # ----------------------------------------------------
        # SAVE FEATURE CSV
        # ----------------------------------------------------

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

        # ----------------------------------------------------
        # STEP 2
        # ----------------------------------------------------

        print()
        print(
            "Step 2: Running trained ML model..."
        )

        (
            result,
            score,
            category,
            overall_status,
            threshold,
        ) = assess_dataframe(df)

        # ----------------------------------------------------
        # SAVE ASSESSMENT CSV
        # ----------------------------------------------------

        assessment_csv = (
            output_dir
            / f"{context_file}_assessment.csv"
        )

        result.to_csv(
            assessment_csv,
            index=False,
        )

        # ====================================================
        # FINAL RESULTS
        # ====================================================

        print()
        print(
            "FINAL ASSESSMENT"
        )
        print(
            "================"
        )

        print(
            "Workloads assessed:",
            len(result),
        )

        print(
            "Predicted SECURE:",
            int(
                (
                    result[
                        "predicted_label"
                    ]
                    == 1
                ).sum()
            ),
        )

        print(
            "Predicted INSECURE:",
            int(
                (
                    result[
                        "predicted_label"
                    ]
                    == 0
                ).sum()
            ),
        )

        print(
            f"Security Score: "
            f"{score:.2f}/100"
        )

        print(
            f"Category: {category}"
        )

        print(
            f"Overall Status: "
            f"{overall_status}"
        )

        print(
            f"Decision Threshold: "
            f"{threshold:.2f}"
        )

        # ====================================================
        # WORKLOAD RESULTS
        # ====================================================

        print()
        print(
            "WORKLOAD RESULTS"
        )
        print(
            "================="
        )

        for index, row in result.iterrows():

            name = row.get(
                "deployment",
                f"Row-{index + 1}",
            )

            print(
                f"{name}: "
                f"{row['security_probability']:.6f} "
                f"-> "
                f"{row['predicted_status']}"
            )

        # ====================================================
        # OUTPUT
        # ====================================================

        print()
        print(
            "Assessment CSV:"
        )
        print(
            assessment_csv
        )

    except Exception as exc:

        print()
        print(
            "ASSESSMENT FAILED"
        )
        print(
            "================="
        )
        print(
            str(exc)
        )

        sys.exit(1)


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()