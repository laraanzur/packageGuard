RULES = [
    {
        "name": "child_process",
        "pattern": r"child_process",
        "severity": 4
    },
    {
        "name": "eval",
        "pattern": r"eval\(",
        "severity": 4
    },
    {
        "name": "buffer",
        "pattern": r"Buffer.from\(",
        "severity": 4
    },
    {
        "name": "env",
        "pattern": r"process.env",
        "severity": 4
    },
    {
        "name": "http",
        "pattern": r"http://",
        "severity": 4
    },
    {
        "name": "https",
        "pattern": r"https://",
        "severity": 4
    },
    {
        "name": "preinstall",
        "pattern": r"preinstall",
        "severity": 4
    },
    {
        "name": "postinstall",
        "pattern": r"postinstall",
        "severity": 4
    }
]


# http://
# https://