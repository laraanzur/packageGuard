JS_RULES = [
    {
        "id": "child-process",
        "title": "Child Process Usage",
        "pattern": r"require\s*\(\s*['\"]child_process['\"]\s*\)|from\s+['\"]child_process['\"]",
        "severity": "high",
        "message": "Uses child_process module",
    },
    {
        "id": "exec-sync",
        "title": "Synchronous Shell Execution",
        "pattern": r"\bexecSync\s*\(",
        "severity": "high",
        "message": "Executes shell commands synchronously",
    },
    {
        "id": "eval",
        "title": "Eval Usage",
        "pattern": r"\beval\s*\(",
        "severity": "high",
        "message": "Uses eval for dynamic code execution",
    },
    {
        "id": "function-constructor",
        "title": "Function Constructor Usage",
        "pattern": r"\bFunction\s*\(",
        "severity": "high",
        "message": "Uses Function constructor for dynamic code execution",
    },
    {
        "id": "base64-decode",
        "title": "Base64 Decoding",
        "pattern": r"Buffer\.from\s*\([^)]*['\"]base64['\"]",
        "severity": "medium",
        "message": "Decodes Base64 content",
    },
    {
        "id": "env-access",
        "title": "Environment Variable Access",
        "pattern": r"process\.env",
        "severity": "medium",
        "message": "Accesses environment variables",
    },
    {
        "id": "credential-file",
        "title": "Credential File Reference",
        "pattern": r"\.npmrc|\.ssh|id_rsa|GITHUB_TOKEN|NPM_TOKEN",
        "severity": "high",
        "message": "References credential-related files or tokens",
    },
    {
        "id": "network-url",
        "title": "Network URL Reference",
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
    "prepublishOnly"
}


SCRIPT_PATTERNS = [
    {
        "id": "remote-download",
        "title": "Remote Download",
        "pattern": r"\b(curl|wget)\b|https?://",
        "severity": "high",
        "message": "Lifecycle script downloads or references remote content",
    },
    {
        "id": "shell-execution",
        "title": "Shell Execution",
        "pattern": r"\b(bash|sh|powershell|cmd\.exe)\b",
        "severity": "high",
        "message": "Lifecycle script invokes a shell",
    },
    {
        "id": "inline-code-execution",
        "title": "Inline Code Execution",
        "pattern": r"\b(node|python|python3)\s+-[ec]\b",
        "severity": "high",
        "message": "Lifecycle script executes inline code",
    },
    {
        "id": "obfuscation",
        "title": "Obfuscation Indicators",
        "pattern": r"\b(base64|eval)\b",
        "severity": "medium",
        "message": "Lifecycle script contains obfuscation-related keyword",
    },
]