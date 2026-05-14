REGEX = [
    {
        "id": "sensitive-file-reference",
        "title": "Sensitive file reference",
        "severity": "high",
        "pattern": r"(['\"]\.env['\"]|\.npmrc|\.ssh|id_rsa|id_ed25519|\.aws|credentials|\.kube|\.gitconfig)",
        "tags": ["sensitive-file"],
    },
    {
        "id": "specific-token-reference",
        "title": "Specific token reference",
        "severity": "high",
        "pattern": r"(NPM_TOKEN|NODE_AUTH_TOKEN|GITHUB_TOKEN|GH_TOKEN|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|GOOGLE_APPLICATION_CREDENTIALS|AZURE_CLIENT_SECRET|PRIVATE_KEY)",
        "tags": ["token"],
    },
    {
        "id": "generic-secret-name",
        "title": "Generic secret name",
        "severity": "low",
        "pattern": r"\b(TOKEN|SECRET|PASSWORD|API_KEY)\b",
        "tags": ["token"],
    },
    {
        "id": "external-url",
        "title": "External URL",
        "severity": "medium",
        "pattern": r"https?://[^\s\"']+",
        "tags": ["external-url", "network"],
    },
    {
        "id": "suspicious-service-url",
        "title": "Suspicious service URL",
        "severity": "high",
        "pattern": r"(discord\.com/api/webhooks|telegram|pastebin|ngrok|requestbin|interact\.sh|webhook)",
        "tags": ["external-url", "suspicious-service", "network"],
    },
    {
        "id": "obfuscation-indicator",
        "title": "Obfuscation indicator",
        "severity": "medium",
        "pattern": r"(base64|atob\s*\(|Buffer\.from\s*\([^)]*[\"']base64[\"']|\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4})",
        "tags": ["obfuscation"],
    },
    {
        "id": "shell-command-indicator",
        "title": "Suspicious shell command",
        "severity": "high",
        "pattern": r"\b(curl|wget|bash|sh|powershell|cmd\.exe|chmod|rm\s+-rf|del)\b",
        "tags": ["command-execution"],
    },
    {
        "id": "windows-payload-indicator",
        "title": "Windows payload indicator",
        "severity": "medium",
        "pattern": r"(rundll32|regsvr32|certutil|bitsadmin|Invoke-WebRequest|Start-Process|\.exe\b|\.dll\b|\.bat\b|\.vbs\b|%TEMP%)",
        "tags": ["windows-payload", "command-execution"],
    },
    {
        "id": "archive-download-indicator",
        "title": "Archive or download indicator",
        "severity": "medium",
        "pattern": r"(\.zip\b|\.tar\b|\.gz\b|unzip|extract|download|chmod\s+\+x)",
        "tags": ["archive", "download"],
    },
    {
        "id": "cleanup-indicator",
        "title": "Cleanup indicator",
        "severity": "medium",
        "pattern": r"(rm\s+-rf|unlink|delete|remove\s+package\.json|replace\s+package\.json)",
        "tags": ["cleanup"],
    },
]

LIFECYCLE_SCRIPTS = {
    "preinstall",
    "install",
    "postinstall",
    "prepare",
    "prepublish",
    "prepublishOnly"
}


SCRIPT_PATTERNS = [
    {
        "id": "lifecycle-remote-download",
        "title": "Remote Download",
        "pattern": r"\b(curl|wget)\b|https?://",
        "severity": "high",
        "tags": ["lifecycle", "download", "external-url"],
    },
    {
        "id": "lifecycle-shell-execution",
        "title": "Shell Execution",
        "pattern": r"\b(bash|sh|powershell|cmd\.exe)\b",
        "severity": "high",
        "tags": ["lifecycle", "command-execution"],
    },
    {
        "id": "lifecycle-inline-code-execution",
        "title": "Inline Code Execution",
        "pattern": r"\b(node|python|python3)\s+-[ec]\b",
        "severity": "high",
        "tags": ["lifecycle", "dynamic-execution"],
    },
    {
        "id": "lifecycle-obfuscation",
        "title": "Obfuscation Indicators",
        "pattern": r"\b(base64|eval)\b",
        "severity": "medium",
        "tags": ["lifecycle", "obfuscation"],
    },
]