const RULES = {
// File system rules
  "fs.readFile": {
    rule_id: "ast-fs-read",
    title: "File read operation",
    severity: "medium",
    confidence: 0.5,
    tags: ["filesystem", "file-read"]
  },
  "fs.readFileSync": {
    rule_id: "ast-fs-read",
    title: "File read operation",
    severity: "medium",
    confidence: 0.5,
    tags: ["filesystem", "file-read"]
  },
  "fs.createReadStream": {
    rule_id: "ast-fs-read",
    title: "File read operation",
    severity: "medium",
    confidence: 0.5,
    tags: ["filesystem", "file-read"]
  },
  "fs.writeFile": {
    rule_id: "ast-fs-write",
    title: "File write operation",
    severity: "medium",
    confidence: 0.5,
    tags: ["filesystem", "file-write"]
  },
  "fs.writeFileSync": {
    rule_id: "ast-fs-write",
    title: "File write operation",
    severity: "medium",
    confidence: 0.5,
    tags: ["filesystem", "file-write"]
  },
  "fs.unlink": {
    rule_id: "ast-fs-delete",
    title: "File deletion operation",
    severity: "high",
    confidence: 0.6,
    tags: ["filesystem", "file-delete", "cleanup"]
  },
  "fs.rm": {
    rule_id: "ast-fs-delete",
    title: "File deletion operation",
    severity: "high",
    confidence: 0.6,
    tags: ["filesystem", "file-delete", "cleanup"]
  },
// Network rules
  "http.request": {
    rule_id: "ast-network-http",
    title: "Network communication",
    severity: "medium",
    confidence: 0.5,
    tags: ["network"]
  },
  "http.get": {
    rule_id: "ast-network-http",
    title: "Network communication",
    severity: "medium",
    confidence: 0.5,
    tags: ["network"]
  },
  "https.request": {
    rule_id: "ast-network-http",
    title: "Network communication",
    severity: "medium",
    confidence: 0.5,
    tags: ["network"]
  },
  "https.get": {
    rule_id: "ast-network-http",
    title: "Network communication",
    severity: "medium",
    confidence: 0.5,
    tags: ["network"]
  },
  "fetch": {
    rule_id: "ast-network-fetch",
    title: "Fetch network request",
    severity: "medium",
    confidence: 0.5,
    tags: ["network"]
  },
// Environment
  "process.env": {
    rule_id: "ast-env-access",
    title: "Environment variable access",
    severity: "medium",
    confidence: 0.2,
    tags: ["env"]
  },

  "os.hostname": {
    rule_id: "ast-os-hostname",
    title: "System hostname access",
    severity: "low",
    confidence: 0.3,
    tags: ["os-info"]
  },
  "os.userInfo": {
    rule_id: "ast-os-userinfo",
    title: "User information access",
    severity: "low",
    confidence: 0.3,
    tags: ["os-info"]
  },
  "os.homedir": {
    rule_id: "ast-os-homedir",
    title: "Home directory access",
    severity: "low",
    confidence: 0.3,
    tags: ["os-info"]
  },
  "os.networkInterfaces": {
    rule_id: "ast-os-network-interfaces",
    title: "Network interface access",
    severity: "medium",
    confidence: 0.5,
    tags: ["os-info"]
  },
// Child processes
  "child_process.exec": {
    rule_id: "ast-child-process-exec",
    title: "Command execution",
    severity: "high",
    confidence: 0.6,
    tags: ["command-execution"]
  },
  "child_process.execSync": {
    rule_id: "ast-child-process-exec",
    title: "Command execution",
    severity: "high",
    confidence: 0.6,
    tags: ["command-execution"]
  },
  "child_process.spawn": {
    rule_id: "ast-child-process-exec",
    title: "Process spawning",
    severity: "high",
    confidence: 0.6,
    tags: ["command-execution"]
  },
  "child_process.spawnSync": {
    rule_id: "ast-child-process-exec",
    title: "Process spawning",
    severity: "high",
    confidence: 0.6,
    tags: ["command-execution"]
  },
  "child_process.fork": {
    rule_id: "ast-child-process-exec",
    title: "Process forking",
    severity: "high",
    confidence: 0.6,
    tags: ["command-execution"]
  },
// Dynamic code execution
  "eval": {
    rule_id: "ast-dynamic-eval",
    title: "Dynamic code execution",
    severity: "high",
    confidence: 0.7,
    tags: ["dynamic-execution"]
  },
  "Function": {
    rule_id: "ast-dynamic-function-constructor",
    title: "Function constructor usage",
    severity: "high",
    confidence: 0.7,
    tags: ["dynamic-execution"]
  }
};

module.exports = RULES;