# 🔒 WEBSECURITY - Web Security Scanner for Developers

![WEBSECURITY Banner](https://img.shields.io/badge/WEBSECURITY-Web%20Security%20Scanner-blue)
![Bash](https://img.shields.io/badge/Bash-Script-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

**Are you a web developer wanting to secure your website with little time and effort?** WEBSECURITY is your ultimate solution - a comprehensive Bash-based security scanner that identifies vulnerabilities and provides actionable fix examples in minutes.
# 🛡️ WebSecurity.sh – Web Application Security Automation Script

## !! Overview

`websecurity.sh` is a **Bash-based web application security script** designed for penetration testers, bug bounty hunters, red teamers, and security enthusiasts.  
It automates essential security assessments to detect vulnerabilities such as:

- **SQL Injection (SQLi)**
- **Cross-Site Scripting (XSS)**
- **Cross-Site Request Forgery (CSRF)**
- **Command Injection**
- **Directory Traversal**
- **Information Disclosure**

This tool is lightweight, fast, and ideal for both **manual testing augmentation** and **automation in CI/CD pipelines**.

---

## !! Features

- ✅ **Automated Vulnerability Scanning**: Quickly identify common web vulnerabilities.
- ✅ **Customizable Payloads**: Extendable to include your own test cases.
- ✅ **Minimal Dependencies**: Only requires Bash, curl, and grep.
- ✅ **Open Source & Free**: MIT License.

---
## Requirements :
```bash
bash
curl
grep
sed
awk
openssl
coreutils        # provides timeout, date, etc. (usually present)
nmap
nikto            # optional: web server scanner (menu mentions Full Scan)
exploitdb        # provides searchsploit (optional: "Search ExploitDB" menu)
certbot          # optional: certificate obtain/renew helper (letsencrypt)
ufw              # optional (firewall-related recommendations)
iptables         # optional (firewall command-line)
# utilities often present by default but listed for completeness:
tr
awk
ps
systemctl
```
---

## !! Installation

1. **Clone the repository:**

```bash
git clone https://github.com/omarmerheb/WEBSECURITY.git
cd WEBSECURITY
```
If this tool helped you secure your applications, consider supporting the project:

BTC: 15o7Md2HJrQU2rSNyf5Azt8SPu9aBCCLi9

Made with ❤️ for developers who care about security

