# 🔒 WEBSECURITY - Web Security Scanner for Developers

![WEBSECURITY Banner](https://img.shields.io/badge/WEBSECURITY-Web%20Security%20Scanner-blue)
![Bash](https://img.shields.io/badge/Bash-Script-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

**Are you a web developer wanting to secure your website with little time and effort?** WEBSECURITY is your ultimate solution - a comprehensive Bash-based security scanner that identifies vulnerabilities and provides actionable fix examples in minutes.

## 🚀 Quick Start

```bash
git clone https://github.com/omarmerbh/WEBSECURITY.git
cd WEBSECURITY
chmod +x websecurity.sh
./websecurity.sh
🛠️ What WEBSECURITY Scans

    🔍 Security Headers (CSP, HSTS, X-Frame-Options, etc.)

    🔒 SSL/TLS Configuration (Certificate validity, configuration)

    🌐 Open Port Detection (Nmap integration for service enumeration)

    🛡️ Web Vulnerabilities (Nikto integration for common web issues)

    💡 Developer-Friendly Fixes (Before/after code examples)

📋 Requirements

System Requirements:

    Linux (Kali, Ubuntu, Debian, CentOS)

    Bash 4.0+

    curl, nmap, nikto, openssl

Install dependencies:
bash

# Ubuntu/Debian
sudo apt update && sudo apt install nmap nikto curl openssl

# CentOS/RHEL  
sudo yum install nmap nikto curl openssl

🎯 Features

    ⚡ Fast Scans - Quick (2 min) or Full (5 min) scanning options

    🎨 Clean Interface - Color-coded output with progress indicators

    📝 Actionable Reports - Specific vulnerability details with fix examples

    🔧 No Dependencies - Pure Bash script, no Python or complex setup

    💾 Results Logging - Automatic saving of scan results

    🌐 ExploitDB Integration - Quick search for known vulnerabilities

📖 Usage Examples

Basic Usage:
bash

./websecurity.sh

Sample Output:
text

================================================================================
                   SCAN RESULTS - 3 VULNERABILITIES FOUND
================================================================================

1. Missing Security Headers (Medium) - Missing CSP, HSTS headers
2. Expired SSL Certificate (High) - Certificate expired 45 days ago  
3. Unnecessary Open Ports (Medium) - Open ports: 21/tcp, 23/tcp, 80/tcp, 443/tcp

🛡️ Sample Fix Examples

WEBSECURITY provides clear before/after code examples:

XSS Protection:
php

// BEFORE (Vulnerable)
echo "Welcome " . $_GET['username'];

// AFTER (Secure)  
echo "Welcome " . htmlspecialchars($_GET['username'], ENT_QUOTES, 'UTF-8');

Security Headers:
apache

# Apache .htaccess
Header always set Content-Security-Policy "default-src 'self'"
Header always set X-Frame-Options "DENY"

🏗️ Project Structure
text

WEBSECURITY/
├── websecurity.sh          # Main scanner script
├── websec_results/         # Scan results directory
├── requirements.txt        # System requirements
├── README.md              # This file
└── test-site/             # Vulnerable test site examples

🤝 Contributing

We welcome contributions! Feel free to submit issues, feature requests, or pull requests.
📄 License

This project is licensed under the MIT License - see the LICENSE file for details.
⚠️ Disclaimer

WEBSECURITY is designed for educational and developmental purposes only. Always ensure you have proper authorization before scanning any website. The authors are not responsible for any misuse of this tool.
💝 Support

If this tool helped you secure your applications, consider supporting the project:

BTC: 15o7Md2HJrQU2rSNyf5Azt8SPu9aBCCLi9

Made with ❤️ for developers who care about security
