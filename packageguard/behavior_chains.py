def _get_tags(finding):
    tags = finding.get("tags") or []
    flat = []
    for tag in tags:
        if isinstance(tag, list):
            flat.extend(tag)
        else:
            flat.append(tag)
    return flat


def has_tag(finding, tag):
    return tag in _get_tags(finding)


def has_any_tag(finding, tags):
    finding_tags = _get_tags(finding)
    return any(tag in finding_tags for tag in tags)


def make_chain_finding(rule_id, title, severity, evidence, tags, explanation):
    return {
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "confidence": "",
        "file": "behavior-chain",
        "line": None,
        "evidence": evidence,
        "explanation_recommendation": explanation,
        "tags": tags,
        "source": "behavior-chain",
    }


def detect_install_time_exfiltration(findings):
    lifecycle_reachable = any(
        has_tag(finding, "lifecycle-reachable")
        for finding in findings
    )

    sensitive = any(
        has_any_tag(finding, ["sensitive-file", "env", "token"])
        for finding in findings
    )

    network = any(
        has_any_tag(finding, ["network", "external-url", "suspicious-service"])
        for finding in findings
    )

    if lifecycle_reachable and sensitive and network:
        return make_chain_finding(
            rule_id="chain-install-time-exfiltration",
            title="Install-time sensitive data exfiltration pattern",
            severity="critical",
            evidence=(
                "A lifecycle script reaches code that accesses sensitive data "
                "and performs network communication."
            ),
            tags=[
                "lifecycle-reachable",
                "sensitive-file",
                "network",
            ],
            explanation="Potential sensitive data exfiltration during install-time.",
        )

    return None


def detect_secret_exfiltration(findings):
    sensitive = any(
        has_any_tag(finding, ["sensitive-file", "env", "token"])
        for finding in findings
    )

    network = any(
        has_any_tag(finding, ["network", "external-url", "suspicious-service"])
        for finding in findings
    )

    if sensitive and network:
        return make_chain_finding(
            rule_id="chain-secret-exfiltration",
            title="Possible secret exfiltration",
            severity="critical",
            evidence=(
                "Sensitive data access appears together with network communication."
            ),
            tags=["sensitive-file", "env", "token", "network"],
            explanation="Sensitive data access combined with network activity.",
        )

    return None


def detect_install_time_command_execution(findings):
    lifecycle_reachable = any(
        has_tag(finding, "lifecycle-reachable")
        for finding in findings
    )

    command_exec = any(
        has_tag(finding, "command-execution")
        for finding in findings
    )

    lifecycle_shell = any(
        finding.get("rule_id") == "shell-execution"
        for finding in findings
    )

    if lifecycle_reachable and (command_exec or lifecycle_shell):
        return make_chain_finding(
            rule_id="chain-install-time-command-execution",
            title="Install-time command execution",
            severity="critical",
            evidence=(
                "Package installation can trigger shell or process execution."
            ),
            tags=["lifecycle-reachable", "command-execution"],
            explanation="Command execution reachable from install-time scripts.",
        )

    return None


def detect_obfuscated_dynamic_execution(findings):
    obfuscation = any(
        has_tag(finding, "obfuscation")
        for finding in findings
    )

    dynamic_exec = any(
        has_tag(finding, "dynamic-execution")
        for finding in findings
    )

    if obfuscation and dynamic_exec:
        return make_chain_finding(
            rule_id="chain-obfuscated-dynamic-execution",
            title="Obfuscated dynamic code execution",
            severity="high",
            evidence=(
                "Obfuscation indicators appear together with dynamic code execution."
            ),
            tags=["obfuscation", "dynamic-execution"],
            explanation="Obfuscation plus dynamic execution suggests hidden behavior.",
        )

    return None


def apply_behavior_chains(findings):
    detectors = [
        detect_install_time_exfiltration,
        detect_secret_exfiltration,
        detect_install_time_command_execution,
        detect_obfuscated_dynamic_execution,
    ]

    existing_rule_ids = {finding.get("rule_id") for finding in findings}
    chain_findings = []

    for detector in detectors:
        finding = detector(findings)
        if finding and finding["rule_id"] not in existing_rule_ids:
            chain_findings.append(finding)
            existing_rule_ids.add(finding["rule_id"])

    return findings + chain_findings