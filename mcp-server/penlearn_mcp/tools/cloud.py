"""
Cloud, container, and infrastructure-as-code security tools.
Includes: prowler, trivy, scout-suite, cloudmapper, pacu, kube-hunter,
kube-bench, docker-bench, clair, falco, checkov, terrascan.
"""
import os
import shutil
import tempfile

from mcp.types import Tool

from .register_all import register
from ._helpers import _run_subprocess, _save_artifact, _record_execution


async def _persist(project_id, tool_name: str, args: dict, stdout: str, stderr: str, exit_code: int):
    if project_id:
        out_p, err_p, sha = await _save_artifact(int(project_id), tool_name, stdout, stderr)
        await _record_execution(int(project_id), tool_name, args, out_p, err_p, exit_code, sha)


# ---------------------------------------------------------------------------
# prowler  (AWS / Azure / GCP security assessment)
# ---------------------------------------------------------------------------

async def _prowler_scan(args: dict) -> str:
    provider = (args.get("provider") or "aws").strip()
    profile = (args.get("profile") or "").strip()
    region = (args.get("region") or "").strip()
    checks = (args.get("checks") or "").strip()
    output_format = (args.get("output_format") or "json").strip()
    extra = (args.get("additional_args") or "").strip()
    project_id = args.get("project_id")

    if not shutil.which("prowler"):
        return "Error: prowler not found in PATH. Install: pip install prowler"

    cmd = ["prowler", provider]
    if profile:
        cmd += ["--profile", profile]
    if region:
        cmd += ["--region", region]
    if checks:
        cmd += ["--checks", checks]
    cmd += ["--output-format", output_format]
    if extra:
        cmd += extra.split()

    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=600)
    await _persist(project_id, "prowler_scan", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return stdout or stderr or f"Prowler {provider} assessment completed with no output."


register(
    Tool(
        name="prowler_scan",
        description="Run Prowler cloud security assessment for AWS, Azure, or GCP. Checks for misconfigurations, compliance violations, and security best practices.",
        inputSchema={
            "type": "object",
            "properties": {
                "provider": {"type": "string", "description": "Cloud provider: aws, azure, gcp (default: aws)"},
                "profile": {"type": "string", "description": "AWS credential profile name"},
                "region": {"type": "string", "description": "Cloud region to scan"},
                "checks": {"type": "string", "description": "Specific checks to run (comma-separated)"},
                "output_format": {"type": "string", "description": "Output format: json, html, csv (default: json)"},
                "additional_args": {"type": "string", "description": "Extra CLI flags"},
                "project_id": {"type": "integer"},
            },
        },
    ),
    _prowler_scan,
)


# ---------------------------------------------------------------------------
# trivy  (container / filesystem / repo vulnerability scanning)
# ---------------------------------------------------------------------------

async def _trivy_scan(args: dict) -> str:
    scan_type = (args.get("scan_type") or "image").strip()
    target = (args.get("target") or "").strip()
    severity = (args.get("severity") or "").strip()
    output_format = (args.get("output_format") or "table").strip()
    extra = (args.get("additional_args") or "").strip()
    project_id = args.get("project_id")

    if not target:
        return "Error: target is required (image name, directory, or repo URL)."
    if not shutil.which("trivy"):
        return "Error: trivy not found in PATH. Install: apt install trivy"

    cmd = ["trivy", scan_type, "--format", output_format]
    if severity:
        cmd += ["--severity", severity]
    if extra:
        cmd += extra.split()
    cmd.append(target)

    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=300)
    await _persist(project_id, "trivy_scan", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return stdout or stderr or f"Trivy {scan_type} scan completed for {target} with no findings."


register(
    Tool(
        name="trivy_scan",
        description="Scan container images, filesystems, or repos for vulnerabilities using Trivy. Detects CVEs, misconfigurations, secrets, and SBOM.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Container image name, directory path, or repo URL"},
                "scan_type": {"type": "string", "description": "Scan type: image, fs, repo, config (default: image)"},
                "severity": {"type": "string", "description": "Filter by severity: CRITICAL,HIGH,MEDIUM,LOW"},
                "output_format": {"type": "string", "description": "Output format: table, json, sarif (default: table)"},
                "additional_args": {"type": "string", "description": "Extra CLI flags"},
                "project_id": {"type": "integer"},
            },
        },
    ),
    _trivy_scan,
)


# ---------------------------------------------------------------------------
# scout_suite  (multi-cloud security audit)
# ---------------------------------------------------------------------------

async def _scout_suite(args: dict) -> str:
    provider = (args.get("provider") or "aws").strip()
    profile = (args.get("profile") or "").strip()
    services = (args.get("services") or "").strip()
    report_dir = (args.get("report_dir") or "/tmp/scout-suite-report").strip()
    extra = (args.get("additional_args") or "").strip()
    project_id = args.get("project_id")

    if not shutil.which("scout"):
        return "Error: scout (ScoutSuite) not found in PATH. Install: pip install scoutsuite"

    cmd = ["scout", provider]
    if profile and provider == "aws":
        cmd += ["--profile", profile]
    if services:
        cmd += ["--services", services]
    cmd += ["--report-dir", report_dir]
    if extra:
        cmd += extra.split()

    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=600)
    await _persist(project_id, "scout_suite", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return (stdout or stderr or f"ScoutSuite {provider} assessment completed.") + f"\nReport: {report_dir}"


register(
    Tool(
        name="scout_suite",
        description="Multi-cloud security auditing with ScoutSuite. Supports AWS, Azure, GCP, Alibaba, and OCI. Generates HTML report with security findings.",
        inputSchema={
            "type": "object",
            "properties": {
                "provider": {"type": "string", "description": "Cloud provider: aws, azure, gcp, aliyun, oci (default: aws)"},
                "profile": {"type": "string", "description": "AWS credential profile"},
                "services": {"type": "string", "description": "Limit to specific services (comma-separated)"},
                "report_dir": {"type": "string", "description": "Report output directory (default: /tmp/scout-suite-report)"},
                "additional_args": {"type": "string", "description": "Extra CLI flags"},
                "project_id": {"type": "integer"},
            },
        },
    ),
    _scout_suite,
)


# ---------------------------------------------------------------------------
# cloudmapper  (AWS network visualization and security analysis)
# ---------------------------------------------------------------------------

async def _cloudmapper_analyze(args: dict) -> str:
    action = (args.get("action") or "collect").strip()
    account = (args.get("account") or "").strip()
    config = (args.get("config") or "config.json").strip()
    extra = (args.get("additional_args") or "").strip()
    project_id = args.get("project_id")

    if not account and action != "webserver":
        return "Error: account is required for most cloudmapper actions."
    if not shutil.which("cloudmapper"):
        return "Error: cloudmapper not found in PATH. Install: pip install cloudmapper"

    cmd = ["cloudmapper", action]
    if account:
        cmd += ["--account", account]
    if config:
        cmd += ["--config", config]
    if extra:
        cmd += extra.split()

    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=300)
    await _persist(project_id, "cloudmapper_analyze", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return stdout or stderr or f"CloudMapper {action} completed."


register(
    Tool(
        name="cloudmapper_analyze",
        description="AWS network visualization and security analysis with CloudMapper. Actions: collect (gather data), prepare (build graph), find_admins, report.",
        inputSchema={
            "type": "object",
            "properties": {
                "action": {"type": "string", "description": "Action: collect, prepare, find_admins, report, webserver (default: collect)"},
                "account": {"type": "string", "description": "AWS account name from config"},
                "config": {"type": "string", "description": "Config file path (default: config.json)"},
                "additional_args": {"type": "string", "description": "Extra CLI flags"},
                "project_id": {"type": "integer"},
            },
        },
    ),
    _cloudmapper_analyze,
)


# ---------------------------------------------------------------------------
# pacu  (AWS exploitation framework)
# ---------------------------------------------------------------------------

async def _pacu_exploit(args: dict) -> str:
    session_name = (args.get("session_name") or "penlearn_session").strip()
    modules = (args.get("modules") or "").strip()
    regions = (args.get("regions") or "").strip()
    project_id = args.get("project_id")

    if not modules:
        return "Error: modules is required. Example: 'iam__enum_permissions,s3__enum_buckets'"
    if not shutil.which("pacu"):
        return "Error: pacu not found in PATH. Install: pip install pacu"

    commands = [f"set_session {session_name}"]
    if regions:
        commands.append(f"set_regions {regions}")
    for mod in modules.split(","):
        mod = mod.strip()
        if mod:
            commands.append(f"run {mod}")
    commands.append("exit")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(commands))
        cmd_file = f.name

    try:
        cmd = ["bash", "-c", f"pacu < {cmd_file}"]
        stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=600)
        await _persist(project_id, "pacu_exploit", args, stdout, stderr, exit_code)
    finally:
        try:
            os.unlink(cmd_file)
        except OSError:
            pass

    if exit_code == -1:
        return stderr
    return stdout or stderr or "Pacu exploitation completed with no output."


register(
    Tool(
        name="pacu_exploit",
        description="AWS exploitation using Pacu framework. Run enumeration and exploitation modules against AWS environments. Requires configured AWS credentials.",
        inputSchema={
            "type": "object",
            "required": ["modules"],
            "properties": {
                "modules": {"type": "string", "description": "Comma-separated Pacu modules to run (e.g. 'iam__enum_permissions,s3__enum_buckets')"},
                "session_name": {"type": "string", "description": "Pacu session name (default: penlearn_session)"},
                "regions": {"type": "string", "description": "AWS regions to target (comma-separated)"},
                "project_id": {"type": "integer"},
            },
        },
    ),
    _pacu_exploit,
)


# ---------------------------------------------------------------------------
# kube_hunter  (Kubernetes penetration testing)
# ---------------------------------------------------------------------------

async def _kube_hunter(args: dict) -> str:
    target = (args.get("target") or "").strip()
    cidr = (args.get("cidr") or "").strip()
    active = bool(args.get("active", False))
    report_format = (args.get("report_format") or "json").strip()
    extra = (args.get("additional_args") or "").strip()
    project_id = args.get("project_id")

    if not shutil.which("kube-hunter"):
        return "Error: kube-hunter not found in PATH. Install: pip install kube-hunter"

    cmd = ["kube-hunter", "--report", report_format]
    if target:
        cmd += ["--remote", target]
    elif cidr:
        cmd += ["--cidr", cidr]
    else:
        cmd.append("--pod")

    if active:
        cmd.append("--active")
    if extra:
        cmd += extra.split()

    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=300)
    await _persist(project_id, "kube_hunter", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return stdout or stderr or "kube-hunter scan completed with no findings."


register(
    Tool(
        name="kube_hunter",
        description="Kubernetes penetration testing with kube-hunter. Discovers Kubernetes components and tests for known exploits. Use --active for active exploitation attempts.",
        inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Remote Kubernetes API server IP/hostname"},
                "cidr": {"type": "string", "description": "CIDR range to scan for Kubernetes clusters"},
                "active": {"type": "boolean", "description": "Enable active exploitation (default: false)"},
                "report_format": {"type": "string", "description": "Report format: json, yaml, plain (default: json)"},
                "additional_args": {"type": "string", "description": "Extra CLI flags"},
                "project_id": {"type": "integer"},
            },
        },
    ),
    _kube_hunter,
)


# ---------------------------------------------------------------------------
# kube_bench  (CIS Kubernetes benchmark)
# ---------------------------------------------------------------------------

async def _kube_bench(args: dict) -> str:
    targets = (args.get("targets") or "").strip()
    version = (args.get("version") or "").strip()
    extra = (args.get("additional_args") or "").strip()
    project_id = args.get("project_id")

    if not shutil.which("kube-bench"):
        return "Error: kube-bench not found in PATH. Install from https://github.com/aquasecurity/kube-bench"

    cmd = ["kube-bench", "--json"]
    if targets:
        cmd += ["--targets", targets]
    if version:
        cmd += ["--version", version]
    if extra:
        cmd += extra.split()

    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=300)
    await _persist(project_id, "kube_bench", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return stdout or stderr or "kube-bench CIS benchmark completed."


register(
    Tool(
        name="kube_bench",
        description="Run CIS Kubernetes Benchmark checks with kube-bench. Audits master nodes, worker nodes, etcd, and policies for security compliance.",
        inputSchema={
            "type": "object",
            "properties": {
                "targets": {"type": "string", "description": "Targets to check: master, node, etcd, policies (comma-separated)"},
                "version": {"type": "string", "description": "Kubernetes version to benchmark against"},
                "additional_args": {"type": "string", "description": "Extra CLI flags"},
                "project_id": {"type": "integer"},
            },
        },
    ),
    _kube_bench,
)


# ---------------------------------------------------------------------------
# docker_bench  (Docker security assessment)
# ---------------------------------------------------------------------------

async def _docker_bench(args: dict) -> str:
    checks = (args.get("checks") or "").strip()
    exclude = (args.get("exclude") or "").strip()
    extra = (args.get("additional_args") or "").strip()
    project_id = args.get("project_id")

    if not shutil.which("docker-bench-security"):
        return "Error: docker-bench-security not found in PATH. Clone from https://github.com/docker/docker-bench-security"

    cmd = ["docker-bench-security"]
    if checks:
        cmd += ["-c", checks]
    if exclude:
        cmd += ["-e", exclude]
    if extra:
        cmd += extra.split()

    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=120)
    await _persist(project_id, "docker_bench", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return stdout or stderr or "Docker Bench Security assessment completed."


register(
    Tool(
        name="docker_bench",
        description="Docker security assessment using Docker Bench for Security. Checks Docker daemon configuration, container runtime settings, and image security against CIS benchmarks.",
        inputSchema={
            "type": "object",
            "properties": {
                "checks": {"type": "string", "description": "Specific check IDs to run (e.g. '1,2,3')"},
                "exclude": {"type": "string", "description": "Check IDs to exclude"},
                "additional_args": {"type": "string", "description": "Extra CLI flags"},
                "project_id": {"type": "integer"},
            },
        },
    ),
    _docker_bench,
)


# ---------------------------------------------------------------------------
# clair_scan  (container vulnerability analysis)
# ---------------------------------------------------------------------------

async def _clair_scan(args: dict) -> str:
    image = (args.get("image") or "").strip()
    config = (args.get("config") or "").strip()
    output_format = (args.get("output_format") or "json").strip()
    extra = (args.get("additional_args") or "").strip()
    project_id = args.get("project_id")

    if not image:
        return "Error: image is required."
    if not shutil.which("clairctl"):
        return "Error: clairctl not found in PATH. Install from https://github.com/quay/clair"

    cmd = ["clairctl", "analyze", image, "--format", output_format]
    if config:
        cmd += ["--config", config]
    if extra:
        cmd += extra.split()

    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=300)
    await _persist(project_id, "clair_scan", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return stdout or stderr or f"Clair vulnerability scan completed for {image}."


register(
    Tool(
        name="clair_scan",
        description="Container vulnerability analysis using Clair (clairctl). Scans container images for known CVEs from multiple vulnerability databases.",
        inputSchema={
            "type": "object",
            "required": ["image"],
            "properties": {
                "image": {"type": "string", "description": "Container image to analyze (e.g. 'ubuntu:20.04')"},
                "config": {"type": "string", "description": "Clair config file path"},
                "output_format": {"type": "string", "description": "Output format: json, xml (default: json)"},
                "additional_args": {"type": "string", "description": "Extra CLI flags"},
                "project_id": {"type": "integer"},
            },
        },
    ),
    _clair_scan,
)


# ---------------------------------------------------------------------------
# falco_monitor  (runtime container security monitoring)
# ---------------------------------------------------------------------------

async def _falco_monitor(args: dict) -> str:
    config_file = (args.get("config_file") or "/etc/falco/falco.yaml").strip()
    rules_file = (args.get("rules_file") or "").strip()
    duration = int(args.get("duration", 60))
    extra = (args.get("additional_args") or "").strip()
    project_id = args.get("project_id")

    if not shutil.which("falco"):
        return "Error: falco not found in PATH. Install from https://falco.org/docs/getting-started/installation/"

    cmd = ["timeout", str(duration), "falco", "--json-output", "--config", config_file]
    if rules_file:
        cmd += ["--rules", rules_file]
    if extra:
        cmd += extra.split()

    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=duration + 30)
    await _persist(project_id, "falco_monitor", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return stdout or stderr or f"Falco monitoring ran for {duration}s with no alerts."


register(
    Tool(
        name="falco_monitor",
        description="Runtime container security monitoring with Falco. Detects anomalous behavior, privilege escalation, unexpected network connections, and other runtime threats.",
        inputSchema={
            "type": "object",
            "properties": {
                "duration": {"type": "integer", "description": "Monitoring duration in seconds (default: 60)"},
                "config_file": {"type": "string", "description": "Falco config file path (default: /etc/falco/falco.yaml)"},
                "rules_file": {"type": "string", "description": "Custom Falco rules file path"},
                "additional_args": {"type": "string", "description": "Extra CLI flags"},
                "project_id": {"type": "integer"},
            },
        },
    ),
    _falco_monitor,
)


# ---------------------------------------------------------------------------
# checkov_scan  (IaC security scanning)
# ---------------------------------------------------------------------------

async def _checkov_scan(args: dict) -> str:
    directory = (args.get("directory") or ".").strip()
    framework = (args.get("framework") or "").strip()
    check = (args.get("check") or "").strip()
    skip_check = (args.get("skip_check") or "").strip()
    output_format = (args.get("output_format") or "cli").strip()
    extra = (args.get("additional_args") or "").strip()
    project_id = args.get("project_id")

    if not shutil.which("checkov"):
        return "Error: checkov not found in PATH. Install: pip install checkov"

    cmd = ["checkov", "-d", directory, "--output", output_format]
    if framework:
        cmd += ["--framework", framework]
    if check:
        cmd += ["--check", check]
    if skip_check:
        cmd += ["--skip-check", skip_check]
    if extra:
        cmd += extra.split()

    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=300)
    await _persist(project_id, "checkov_scan", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return stdout or stderr or f"Checkov IaC scan completed for {directory}."


register(
    Tool(
        name="checkov_scan",
        description="Infrastructure as Code (IaC) security scanning with Checkov. Scans Terraform, CloudFormation, Kubernetes, Dockerfiles, and more for misconfigurations.",
        inputSchema={
            "type": "object",
            "properties": {
                "directory": {"type": "string", "description": "Directory containing IaC files to scan (default: current dir)"},
                "framework": {"type": "string", "description": "IaC framework: terraform, cloudformation, kubernetes, dockerfile, helm, etc."},
                "check": {"type": "string", "description": "Run only specific checks (e.g. 'CKV_AWS_1,CKV_AWS_2')"},
                "skip_check": {"type": "string", "description": "Skip specific checks"},
                "output_format": {"type": "string", "description": "Output format: cli, json, junit_xml, sarif (default: cli)"},
                "additional_args": {"type": "string", "description": "Extra CLI flags"},
                "project_id": {"type": "integer"},
            },
        },
    ),
    _checkov_scan,
)


# ---------------------------------------------------------------------------
# terrascan_scan  (IaC security scanning)
# ---------------------------------------------------------------------------

async def _terrascan_scan(args: dict) -> str:
    iac_type = (args.get("iac_type") or "all").strip()
    iac_dir = (args.get("iac_dir") or ".").strip()
    policy_type = (args.get("policy_type") or "").strip()
    severity = (args.get("severity") or "").strip()
    output_format = (args.get("output_format") or "json").strip()
    extra = (args.get("additional_args") or "").strip()
    project_id = args.get("project_id")

    if not shutil.which("terrascan"):
        return "Error: terrascan not found in PATH. Install from https://runterrascan.io/docs/getting-started/"

    cmd = ["terrascan", "scan", "-t", iac_type, "-d", iac_dir, "-o", output_format]
    if policy_type:
        cmd += ["-p", policy_type]
    if severity:
        cmd += ["--severity", severity]
    if extra:
        cmd += extra.split()

    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=300)
    await _persist(project_id, "terrascan_scan", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return stdout or stderr or f"Terrascan IaC scan completed for {iac_dir}."


register(
    Tool(
        name="terrascan_scan",
        description="Infrastructure as Code (IaC) security scanning with Terrascan. Supports Terraform, Kubernetes, Helm, Kustomize, and Dockerfile. Policy-as-code approach.",
        inputSchema={
            "type": "object",
            "properties": {
                "iac_dir": {"type": "string", "description": "Directory containing IaC files to scan (default: current dir)"},
                "iac_type": {"type": "string", "description": "IaC type: terraform, k8s, helm, kustomize, dockerfile, all (default: all)"},
                "policy_type": {"type": "string", "description": "Policy type: aws, azure, gcp, github, k8s"},
                "severity": {"type": "string", "description": "Minimum severity: low, medium, high"},
                "output_format": {"type": "string", "description": "Output format: json, yaml, xml, junit-xml (default: json)"},
                "additional_args": {"type": "string", "description": "Extra CLI flags"},
                "project_id": {"type": "integer"},
            },
        },
    ),
    _terrascan_scan,
)
