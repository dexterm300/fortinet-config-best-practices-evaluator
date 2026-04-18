# Fortinet Configuration Best Practices Evaluator

A lightweight, purely client-side web application designed to evaluate FortiGate firewall configuration backup files (`*.conf`) against industry-standard best practices, including CIS (Center for Internet Security) benchmarks.

Made with ❤️ by Dexter M.

## 🚀 Overview

Network security rests on the proper configuration of physical and virtual firewalls. Misconfigurations or outdated settings in FortiOS can lead to security vulnerabilities. 

This tool provides a secure, intuitive, drag-and-drop interface where users can load their `*.conf` config scripts. The application then automatically parses the file and provides:
*   A **Compliance Score** identifying your security posture.
*   **Gap Identification** for any non-compliant findings.
*   **Actionable Remediation Recommendations** to help you harden the appliance.

**Security & Privacy First:** All evaluation happens purely in your browser (client-side). Your sensitive firewall configurations are **never** uploaded to any external server or saved in the cloud.

## ✨ Features

- **Drag-and-Drop Interface**: Easily upload firewall configuration scripts.
- **CIS Benchmark Checks**: Evaluates configuration against known strict standard security best practices (System hardening, password policies, admin restrictions).
- **Client-Side Parsing**: Secure execution natively in JavaScript—no backend required.
- **Clear Readouts**: Generates a visually clean report with pass/fail metrics and specific CLI remedies.

## 🛠 Getting Started

Wait! There is no installation required. Because this is a static client-side web application, you do not need NPM, Python, or a web server to use it locally.

1. **Clone or Download the Repository:**
   ```bash
   git clone https://github.com/yourusername/ftnt-config-evaluator.git
   ```
2. **Open the Application:**
   Navigate into the project directory and double-click `index.html` to open it in any modern web browser (Chrome, Firefox, Safari, Edge).

## 💡 Usage

1. Open `index.html` in your browser.
2. Locate your FortiGate backup configuration file. For testing purposes, you can use the provided `sample.conf` file included in this repository.
3. Drag and drop the `.conf` file into the designated upload area on the screen.
4. Review your compliance score and the recommendations for any failing checks.

## 📂 Project Structure

```text
├── index.html        # Main web application (HTML/CSS/JS)
├── sample.conf       # A dummy FortiOS config file with missing best practices for testing
├── .gitignore        # Ignored files and folders for Git
└── README.md         # Project documentation (You are here)
```

## 🧪 Running Tests

A zero-dependency Node test runner covers the parser and every rule:

```bash
node tests/run-tests.js
```

## 🧩 Adding a Rule

Rules live in the `RULES` array inside `index.html` and are fully declarative:

```js
{
    id: "ftnt-x.y",
    title: "Short headline",
    description: "Why this matters.",
    severity: "critical" | "high" | "medium" | "low",
    category: "Access Control" | "Logging" | "Hardening" | "Network" | "Policy",
    evaluate: (parsedConfig, rawText) => true,  // true = pass
    remediation: `config ...\n  set ...\nend`
}
```

Use `getSetting(parsed, 'config system global', 'key')` and `allEditBlocks(parsed, header, predicate)` helpers for clean access to the parsed tree.

## 📝 Planned Improvements

- Add support for evaluating FortiOS 7.2/8.0 specific context changes.
- Add toggleable standard targets (e.g., PCI-DSS vs CIS vs Custom).
- Export evaluation results to PDF/CSV (JSON export is already available).

## 📜 License

Distributed under the MIT License. See `LICENSE` for more information.
