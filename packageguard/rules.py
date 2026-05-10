JS_RULES = [
    {
        "id": "child-process",
        "pattern": r"require\s*\(\s*['\"]child_process['\"]\s*\)|from\s+['\"]child_process['\"]",
        "severity": "high",
        "message": "Uses child_process module",
    },
    {
        "id": "exec-sync",
        "pattern": r"\bexecSync\s*\(",
        "severity": "high",
        "message": "Executes shell commands synchronously",
    },
    {
        "id": "eval",
        "pattern": r"\beval\s*\(",
        "severity": "high",
        "message": "Uses eval for dynamic code execution",
    },
    {
        "id": "function-constructor",
        "pattern": r"\bFunction\s*\(",
        "severity": "high",
        "message": "Uses Function constructor for dynamic code execution",
    },
    {
        "id": "base64-decode",
        "pattern": r"Buffer\.from\s*\([^)]*['\"]base64['\"]",
        "severity": "medium",
        "message": "Decodes Base64 content",
    },
    {
        "id": "env-access",
        "pattern": r"process\.env",
        "severity": "medium",
        "message": "Accesses environment variables",
    },
    {
        "id": "credential-file",
        "pattern": r"\.npmrc|\.ssh|id_rsa|GITHUB_TOKEN|NPM_TOKEN",
        "severity": "high",
        "message": "References credential-related files or tokens",
    },
    {
        "id": "network-url",
        "pattern": r"https?://",
        "severity": "medium",
        "message": "Contains external URL",
    },
]

LIFECYCLE_SCRIPTS = {
    "preinstall",
    "install",
    "postinstall",
    "prepare",
    "prepublish",
}


SCRIPT_PATTERNS = [
    {
        "id": "remote-download",
        "pattern": r"\b(curl|wget)\b|https?://",
        "severity": "high",
        "message": "Lifecycle script downloads or references remote content",
    },
    {
        "id": "shell-execution",
        "pattern": r"\b(bash|sh|powershell|cmd\.exe)\b",
        "severity": "high",
        "message": "Lifecycle script invokes a shell",
    },
    {
        "id": "inline-code-execution",
        "pattern": r"\b(node|python|python3)\s+-[ec]\b",
        "severity": "high",
        "message": "Lifecycle script executes inline code",
    },
    {
        "id": "obfuscation",
        "pattern": r"\b(base64|eval)\b",
        "severity": "medium",
        "message": "Lifecycle script contains obfuscation-related keyword",
    },
]