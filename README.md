# veizurX ⚡

![Bash](https://img.shields.io/badge/Language-Bash-4EAA25)
![Security](https://img.shields.io/badge/Focus-Pentesting-red)
![Version](https://img.shields.io/badge/Version-1.0.0-blue)

**veizurX** is a modern, automated reconnaissance and vulnerability scanning framework designed for penetration testers and bug bounty hunters. It streamlines the process of asset discovery, crawling, and vulnerability detection using industry-standard tools.

Developed by **Ogabek Ruziev**.

## 🚀 Features

- **Automated Workflow:** From subdomain enumeration to report generation.
- **Smart Recon:** Uses `Subfinder` and `Naabu` for accurate asset discovery.
- **Deep Crawling:** Integrated `Katana` for modern endpoint discovery.
- **Vulnerability Scanning:** Powered by `Nuclei` with customizable severity levels.
- **Auto-Installation:** Automatically checks and installs required Go dependencies.
- **Clean Reporting:** Generates a Markdown summary of findings.

## 🛠 Installation

```bash
# Clone the repository
git clone https://github.com/ruziev1/veizurX.git

# Change directory
cd veizurX

# Give execution permission
chmod +x veizurX.sh

# Run the tool
./veizurX.sh
