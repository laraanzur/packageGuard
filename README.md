# PackageGuard

PackageGuard is a static analysis tool for malicious npm packages. It analyzes package metadata, `package.json` lifecycle scripts, performs both AST and regex-based static analysis on relevant JavaScript files and attempts to detect typosquatting.

## 1 Setting up the environment
To be able to run the project, you need to have all **Python 3.x**, **Node.js** and  **npm** installed. After setting this up you are required to install both Node.js dependencies and requirements for Python.
   ```bash
   npm install
   ```
   ```bash
   pip install -r requirements.txt
   ```

## 2 Running the Scanner
You can run the scanner by providing either a local path or a live npm package name.

**Scan a local package directory**
```bash
python3 -m packageguard.cli --path ./malicious
```

**Scan an npm package from the registry**
```bash
python3 -m packageguard.cli lodash
```
If you provide a name instead of a path, PackageGuard will securely download the `.tgz` file (using `npm pack`) into a temporary directory and analyze it. The temporary directory will be deleted at the end of the analysis.

## 3 Using the Attacker Demo Package

We have included a mock `malicious/` package and an `attacker/` receiver server to demonstrate how stealthy npm malware (like a `postinstall` script that steals environment variables) operates.

1. **Start the attacker receiver server:**
   ```bash
   cd attacker
   npm install
   node server.js
   ```

2. **Simulate a victim:**
    ```bash
    cd demo/backend
    npm install
    ```

## 4 Using the LLM Summaries

PackageGuard integrates with local large language models to simplify complex findings into a concise summary.

1. Ensure you have [Ollama](https://ollama.com/) installed and running locally.
2. Pull the model of your choice (e.g., `ollama pull llama3`).
3. Append `--llm <model_name>` to your scan:

   ```bash
   python3 -m packageguard.cli --path ./malicious --llm llama3
   ```
   
*Disclaimer: It advisable not to choose a thinking model, as it may result in timeout, and won't return a summary for the report. AAlso, Ollama should be running on default port.*

## 5 Rules Engine

PackageGuard's detection approach is based on two main tecniques:

### a. Regular Expression Rules (`regex`)

| Tag | Scope/Explanation |
| :------------ | :--------------- | 
| `sensitive-file-reference`        | Access to `.env`, `.ssh`, `.aws`, `.npmrc`, etc.       | 
| `specific-token-reference`        | Mentions of `NPM_TOKEN`, `AWS_ACCESS_KEY_ID`, `PRIVATE_KEY`, etc.         |
| `generic-secret-name`       | Generic strings like `TOKEN`, `PASSWORD`, `SECRET`.      |
| `external-url`       | Standard `http/https` URLs mixed into code.         |
| `suspicious-service-url`       | External webhooks, `pastebin`, `ngrok`, `interact.sh`, etc.     |
| `obfuscation-indicator`       | Explicit uses of `base64`, `atob`, encoded buffers, etc.           |
| `shell-command-indicator`       | Shell executables (`bash`, `sh`, `curl`, `wget`).    |
| `windows-payload-indicator`       | Indicators like `Start-Process`, `rundll32`, `.exe`, `%TEMP%`    | 
| `archive-download-indicator`       | Zips, tars, or file extraction patterns.     |
| `cleanup-indicator`       | Tactics intended to wipe tracks (`rm -rf`, `fs.unlink()`).     |


### AST (Abstract Syntax Tree) Rules (`ast`)
| Category | Tags and cases |
| :------------ | :--------------- | 
| **File System**       | `ast-fs-read` (`fs.readFileSync`), `ast-fs-write` (`fs.writeFile`), `ast-fs-delete` (`fs.unlink`, `fs.rm`)      | 
| **Network**        | `ast-network-http` (`http.request`, `https.get`), `ast-network-fetch` (`fetch`)        |
| **Environment & OS**       |`ast-env-access` (`process.env`), `ast-os-hostname`, `ast-os-homedir`, `ast-os-network-interfaces`, `ast-os-userinfo`|
| **Process & Execution**      | `ast-child-process-exec` (`child_process.exec\|spawn\|fork`), `ast-dynamic-eval` (`eval`), `ast-dynamic-function-constructor` (`new Function()`)        |



### Behavioral Chains
Linking AST and regex findings together to form higher-confidence risks - behavior chains. For example:
- **chain-install-time-exfiltration**: Code reaches a sensitive file + network connection + happens during an install lifecycle.
- **chain-install-time-dropper**: Code connects to network + writes file + executes command + happens during install.

### Package trust risk
We also calculate **Package Trust Risk** by querying the npm registry to identify typosquatting against the top 10,000 most popular packages, cross-referencing recent publication dates and noting suspiciously low download counts.

## 6 Scoring and Risk Assessment

Findings are individually mapped to a severity base, multiplied by a confidence score. 

### Severity Points
| Severity | Points |
| :------- | :----- |
| Low      | 1      |
| Medium   | 3      |
| High     | 10     |
| Critical | 50     |

*Calculation per finding: `Risk Score = Severity Points × Confidence (e.g. 0.0 to 1.0)`*

### Total Risk Levels
The final package score is summed across all unique findings in the package:

| Score Bracket | Final Assessment | Recommendation                                                                 |
| :------------ | :--------------- | :----------------------------------------------------------------------------- |
| `<= 0`        | **CLEAN**        | No suspicious behavior detected. Proceed with standard review practices.       |
| `< 10`        | **LOW**          | Proceed with caution and review the flagged code paths.                        |
| `>= 10`       | **MEDIUM**       | Manual review is recommended before installing this package.                   |
| `>= 25`       | **HIGH**         | Do not install unless manually reviewed and fully verified.                    |
| `>= 50`       | **CRITICAL**     | Do not install! Likely malicious intent detected.                              |







