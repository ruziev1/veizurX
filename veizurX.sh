#!/bin/bash

# ==============================================================================
# PROJECT: veizurX - Automated Reconnaissance & Vulnerability Scanner
# AUTHOR: Ogabek Ruziev (ruziev1d)
# VERSION: 1.0.1 (Fixes applied)
# ==============================================================================

# --- [ COLORS & STYLING ] ---
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
PURPLE='\033[0;35m'
BOLD='\033[1m'
RESET='\033[0m'

# --- [ CONFIGURATION ] ---
WORK_DIR="$(pwd)/veizurX_Reports"
LOG_FILE="$WORK_DIR/veizurX.log"

# PATH ni to'g'rilash (Go bin papkasi birinchi turishi shart)
export PATH=$HOME/go/bin:/usr/local/go/bin:$PATH

# --- [ BANNER ] ---
banner() {
    clear
    echo -e "${PURPLE}"
    echo "  ██╗   ██╗███████╗██╗███████╗██╗   ██╗██████╗ ██╗  ██╗"
    echo "  ██║   ██║██╔════╝██║╚══███╔╝██║   ██║██╔══██╗╚██╗██╔╝"
    echo "  ██║   ██║█████╗  ██║  ███╔╝ ██║   ██║██████╔╝ ╚███╔╝ "
    echo "  ╚██╗ ██╔╝██╔══╝  ██║ ███╔╝  ██║   ██║██╔══██╗ ██╔██╗ "
    echo "   ╚████╔╝ ███████╗██║███████╗╚██████╔╝██║  ██║██╔╝ ██╗"
    echo "    ╚═══╝  ╚══════╝╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝"
    echo -e "${RESET}"
    echo -e "      ${CYAN}>> Automated Pentesting Framework <<${RESET}"
    echo -e "         ${YELLOW}Author: Ogabek Ruziev (ruziev1d)${RESET}"
    echo -e "         ${BOLD}Version: 1.0.1 (Patched)${RESET}"
    echo ""
}

# --- [ UTILS ] ---
log() {
    local TYPE=$1
    local MSG=$2
    local TIME=$(date '+%H:%M:%S')
    case $TYPE in
        INFO) echo -e "${BLUE}[INFO]${RESET} $MSG" ;;
        SUCCESS) echo -e "${GREEN}[SUCCESS]${RESET} $MSG" ;;
        WARN) echo -e "${YELLOW}[WARNING]${RESET} $MSG" ;;
        ERROR) echo -e "${RED}[ERROR]${RESET} $MSG" ;;
        *) echo "$MSG" ;;
    esac
    echo "[$TIME] [$TYPE] $MSG" >> "$LOG_FILE"
}

check_dependencies() {
    log "INFO" "Checking required tools..."
    
    # Check GO
    if ! command -v go &> /dev/null; then
        log "WARN" "Go is not installed. Installing Go..."
        wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz -O /tmp/go.tar.gz
        sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf /tmp/go.tar.gz
        export PATH=$PATH:/usr/local/go/bin
        rm /tmp/go.tar.gz
    fi

    # Tools List
    local tools=(
        "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
        "github.com/projectdiscovery/httpx/cmd/httpx"
        "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"
        "github.com/projectdiscovery/katana/cmd/katana"
        "github.com/projectdiscovery/naabu/v2/cmd/naabu"
    )

    for tool in "${tools[@]}"; do
        name=$(basename "$tool")
        if ! command -v "$name" &> /dev/null; then
            log "WARN" "Tool '$name' not found. Installing..."
            go install "$tool@latest" &> /dev/null
            if [ $? -eq 0 ]; then
                log "SUCCESS" "$name installed."
            else
                log "ERROR" "Failed to install $name."
            fi
        else
            echo -e "  ${GREEN}✔${RESET} $name found"
        fi
    done
    
    # Update Nuclei Templates (Silent update)
    if command -v nuclei &> /dev/null; then
        nuclei -update-templates -silent &> /dev/null
    fi
    echo ""
}

# --- [ MODULES ] ---

run_recon() {
    local domain=$1
    local output_dir="$WORK_DIR/$domain"
    
    mkdir -p "$output_dir/recon"
    
    log "INFO" "Starting Reconnaissance on: $domain"
    
    # 1. Subdomain Enumeration
    log "INFO" "Running Subfinder..."
    subfinder -d "$domain" -all -silent -o "$output_dir/recon/subdomains_raw.txt"
    
    count=$(wc -l < "$output_dir/recon/subdomains_raw.txt")
    
    # --- FIX: Agar subdomain topilmasa, asosiy domenni qo'shish ---
    if [ "$count" -eq 0 ]; then
        log "WARN" "No subdomains found. Using main domain as target."
        echo "$domain" > "$output_dir/recon/subdomains_raw.txt"
        count=1
    fi
    
    log "SUCCESS" "Target list prepared: $count domains."

    # 2. Port Scanning & Filtering
    log "INFO" "Scanning ports (Naabu) and checking live hosts (Httpx)..."
    
    # --- FIX: Httpx chaqirishda muammo bo'lmasligi uchun full path tekshiramiz ---
    # Naabu ishlatamiz, keyin natijani httpx ga uzatamiz
    naabu -list "$output_dir/recon/subdomains_raw.txt" -rate 1000 -silent | \
    httpx -silent -title -tech-detect -status-code -o "$output_dir/recon/live_hosts.txt"
    
    # Agar live_hosts.txt bo'sh bo'lsa yoki yaratilmasa
    if [ ! -s "$output_dir/recon/live_hosts.txt" ]; then
        log "WARN" "Naabu/Httpx pipeline yielded no results. Trying direct Httpx on raw list..."
        httpx -l "$output_dir/recon/subdomains_raw.txt" -silent -title -tech-detect -status-code -o "$output_dir/recon/live_hosts.txt"
    fi

    # Extract URLs
    if [ -s "$output_dir/recon/live_hosts.txt" ]; then
        awk '{print $1}' "$output_dir/recon/live_hosts.txt" > "$output_dir/recon/target_urls.txt"
        live_count=$(wc -l < "$output_dir/recon/target_urls.txt")
        log "SUCCESS" "Identified $live_count live web services."
    else
        log "ERROR" "No live web services found. Check internet connection or target validity."
        # Bo'sh fayl yaratib qo'yamiz, xato bermasligi uchun
        touch "$output_dir/recon/target_urls.txt"
    fi
}

run_crawling() {
    local domain=$1
    local output_dir="$WORK_DIR/$domain"
    
    if [ ! -s "$output_dir/recon/target_urls.txt" ]; then
        log "ERROR" "Skipping crawling (No live targets)."
        return
    fi
    
    log "INFO" "Starting Crawler (Katana)..."
    katana -list "$output_dir/recon/target_urls.txt" -jc -kf all -silent -o "$output_dir/recon/endpoints.txt"
    
    ep_count=$(wc -l < "$output_dir/recon/endpoints.txt")
    log "SUCCESS" "Crawled $ep_count unique endpoints."
}

run_scanner() {
    local domain=$1
    local output_dir="$WORK_DIR/$domain"
    local severity=$2
    
    if [ ! -s "$output_dir/recon/target_urls.txt" ]; then
        log "ERROR" "Skipping vulnerability scan (No live targets)."
        return
    fi

    log "INFO" "Starting Vulnerability Scan (Nuclei) - Severity: $severity"
    
    mkdir -p "$output_dir/scans"
    
    nuclei -l "$output_dir/recon/target_urls.txt" \
           -severity "$severity" \
           -rate-limit 50 \
           -o "$output_dir/scans/vulnerabilities.txt"
           
    if [ -f "$output_dir/scans/vulnerabilities.txt" ]; then
        vuln_count=$(wc -l < "$output_dir/scans/vulnerabilities.txt")
    else
        vuln_count=0
    fi
    
    if [ "$vuln_count" -gt 0 ]; then
        log "SUCCESS" "Scan finished! Found $vuln_count potential vulnerabilities."
        echo -e "${RED}[!] Check report: $output_dir/scans/vulnerabilities.txt${RESET}"
    else
        log "INFO" "Scan finished. No vulnerabilities found."
        touch "$output_dir/scans/vulnerabilities.txt" # Bo'sh bo'lsa ham yaratib qo'yamiz
    fi
}

generate_report() {
    local domain=$1
    local output_dir="$WORK_DIR/$domain"
    local report_file="$output_dir/REPORT.md"
    
    echo "# Penetration Test Report - $domain" > "$report_file"
    echo "**Date:** $(date)" >> "$report_file"
    echo "**Tool:** veizurX" >> "$report_file"
    echo "" >> "$report_file"
    
    echo "## 1. Summary" >> "$report_file"
    # Fayllar borligini tekshirib keyin o'qiymiz
    local sub_c=0
    local live_c=0
    local end_c=0
    local vuln_c=0
    
    [ -f "$output_dir/recon/subdomains_raw.txt" ] && sub_c=$(wc -l < "$output_dir/recon/subdomains_raw.txt")
    [ -f "$output_dir/recon/target_urls.txt" ] && live_c=$(wc -l < "$output_dir/recon/target_urls.txt")
    [ -f "$output_dir/recon/endpoints.txt" ] && end_c=$(wc -l < "$output_dir/recon/endpoints.txt")
    [ -f "$output_dir/scans/vulnerabilities.txt" ] && vuln_c=$(wc -l < "$output_dir/scans/vulnerabilities.txt")

    echo "- Total Domains/Subdomains: $sub_c" >> "$report_file"
    echo "- Live Web Services: $live_c" >> "$report_file"
    echo "- Endpoints Crawled: $end_c" >> "$report_file"
    echo "- Vulnerabilities Found: $vuln_c" >> "$report_file"
    
    echo "" >> "$report_file"
    echo "## 2. Live Hosts" >> "$report_file"
    echo "\`\`\`" >> "$report_file"
    [ -f "$output_dir/recon/live_hosts.txt" ] && head -n 20 "$output_dir/recon/live_hosts.txt" >> "$report_file"
    echo "\`\`\`" >> "$report_file"
    
    echo "" >> "$report_file"
    echo "## 3. Vulnerabilities" >> "$report_file"
    echo "\`\`\`" >> "$report_file"
    [ -f "$output_dir/scans/vulnerabilities.txt" ] && cat "$output_dir/scans/vulnerabilities.txt" >> "$report_file"
    echo "\`\`\`" >> "$report_file"
    
    log "SUCCESS" "Report generated at: $report_file"
}

# --- [ MAIN MENU ] ---
main() {
    mkdir -p "$WORK_DIR"
    check_dependencies
    banner
    
    echo -e "${CYAN}Target Domain (e.g., example.com):${RESET}"
    read -p "-> " TARGET
    
    if [ -z "$TARGET" ]; then
        log "ERROR" "Target cannot be empty."
        exit 1
    fi

    echo ""
    echo -e "${BOLD}Select Scan Mode:${RESET}"
    echo -e "1) ${GREEN}Fast Scan${RESET} (Recon + Low/Med Vulns)"
    echo -e "2) ${YELLOW}Deep Scan${RESET} (Recon + Crawl + All Vulns)"
    echo -e "3) ${RED}Full Attack${RESET} (Critical/High Focus)"
    read -p "-> " MODE
    
    case $MODE in
        1)
            run_recon "$TARGET"
            run_scanner "$TARGET" "low,medium"
            generate_report "$TARGET"
            ;;
        2)
            run_recon "$TARGET"
            run_crawling "$TARGET"
            run_scanner "$TARGET" "low,medium,high,critical"
            generate_report "$TARGET"
            ;;
        3)
            run_recon "$TARGET"
            run_scanner "$TARGET" "high,critical"
            generate_report "$TARGET"
            ;;
        *)
            log "ERROR" "Invalid option."
            exit 1
            ;;
    esac
    
    echo ""
    echo -e "${CYAN}Thanks for using veizurX.${RESET}"
}

main
