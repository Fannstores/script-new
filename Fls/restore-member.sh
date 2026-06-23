#!/bin/bash
# ============================================
# FTS-Tunnel — Restore Member Data
# Author    : Fantunel Store
# Copyright : © 2026 Fantunel Store. All Rights Reserved.
# ============================================
# Bisa dijalankan dengan 2 cara:
#   1. Langsung dari URL: bash <(curl -s https://raw.githubusercontent.com/Fannstores/script-new/main/Fls/restore-member.sh)
#   2. Via menu: restore-member
#   3. Install ulang otomatis jika nama member sama
# ============================================

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

REPO_URL="https://raw.githubusercontent.com/Fannstores/script-new/main"
BACKUP_DIR="/root/fts-backup"

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════╗"
echo "║       FTS-TUNNEL RESTORE BACKUP         ║"
echo "║   Bisa via URL: restore-member           ║"
echo "╚══════════════════════════════════════════╝"
echo -e "${NC}"

# ────────────────────────────────────────────
# CEK APAKAH MAIN SH UDAH TERINSTAL
# ────────────────────────────────────────────
check_installed() {
    if [[ -f /etc/xray/config.json ]] || [[ -f /usr/local/bin/backup-member ]]; then
        return 0
    else
        return 1
    fi
}

# ────────────────────────────────────────────
# DOWNLOAD BACKUP DARI URL
# ────────────────────────────────────────────
download_from_url() {
    local url="$1"
    local tmpfile="/tmp/fts-restore-$(date +%s).tar.gz"
    
    echo -e "${BLUE}[INFO]${NC} Download backup dari URL..."
    curl -sL "$url" -o "$tmpfile"
    
    if [[ ! -f "$tmpfile" ]] || [[ $(stat -c%s "$tmpfile") -lt 10 ]]; then
        echo -e "${RED}[ERROR]${NC} Gagal download backup dari URL!"
        rm -f "$tmpfile"
        return 1
    fi
    
    echo -e "${GREEN}[OK]${NC} Backup downloaded (${tmpfile})"
    
    RESTORE_DIR="$BACKUP_DIR/restore-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$RESTORE_DIR"
    tar xzf "$tmpfile" -C "$RESTORE_DIR"
    rm -f "$tmpfile"
    echo -e "${GREEN}[OK]${NC} Diekstrak ke $RESTORE_DIR"
    return 0
}

# ────────────────────────────────────────────
# PROSES RESTORE MEMBER
# ────────────────────────────────────────────
process_restore() {
    local restore_dir="$1"
    local auto_install="$2"  # true = auto install ulang jika nama sama
    
    if [[ ! -d "$restore_dir" ]]; then
        echo -e "${RED}[ERROR]${NC} Folder $restore_dir tidak ditemukan!"
        return 1
    fi
    
    echo ""
    echo -e "${BLUE}Memproses restore dari: ${restore_dir}${NC}"
    
    RESTORED_TOTAL=0
    RESTORED_VMESS=0
    RESTORED_VLESS=0
    RESTORED_TROJAN=0
    RESTORED_SS=0
    RESTORED_SSH=0
    AUTO_INSTALLED=0
    
    # Restore database files dulu
    for f in "$restore_dir"/vmess-.vmess.db "$restore_dir"/vless-.vless.db "$restore_dir"/trojan-.trojan.db "$restore_dir"/shadowsocks-.shadowsocks.db "$restore_dir"/ssh-.ssh.db "$restore_dir"/bot-.bot.db; do
        bname=$(basename "$f")
        dirname=$(echo "$bname" | cut -d'-' -f1)
        filename=".${dirname}.db"
        
        if [[ -f "$f" ]]; then
            mkdir -p "/etc/$dirname" 2>/dev/null
            cp "$f" "/etc/$dirname/$filename"
            echo -e "  ${GREEN}[OK]${NC} Restore database /etc/$dirname/$filename"
        fi
    done
    
    # Restore xray config.json
    if [[ -f "$restore_dir/xray-config.json" ]]; then
        cp "$restore_dir/xray-config.json" /etc/xray/config.json
        echo -e "  ${GREEN}[OK]${NC} Restore /etc/xray/config.json"
    fi
    
    # Proses restore per user dari JSON files
    for f in "$restore_dir"/*.json; do
        [[ -f "$f" ]] || continue
        bname=$(basename "$f" .json)
        [[ "$bname" == _* ]] && continue
        
        atype=$(grep -o '"account_type":"[^"]*"' "$f" | cut -d'"' -f4)
        aexp=$(grep -o '"expiry":"[^"]*"' "$f" | cut -d'"' -f4)
        
        # Cek apakah user sudah ada di config
        USER_EXISTS=false
        if grep -qw "### $bname" /etc/xray/config.json 2>/dev/null; then
            USER_EXISTS=true
        fi
        
        if [[ "$USER_EXISTS" == true ]]; then
            if [[ "$auto_install" == "true" ]]; then
                # Auto re-install: hapus dulu, lalu buat ulang
                echo -e "  ${YELLOW}[REINSTALL]${NC} $bname ($atype) — nama sama, auto buat ulang..."
                
                # Hapus user lama dari config
                sed -i "/### $bname /,/^#vmess$/d" /etc/xray/config.json 2>/dev/null
                sed -i "/### $bname /,/^#vless$/d" /etc/xray/config.json 2>/dev/null
                sed -i "/### $bname /,/^#trojan$/d" /etc/xray/config.json 2>/dev/null
                sed -i "/### $bname /,/^#ss$/d" /etc/xray/config.json 2>/dev/null
                
                # Hapus dari database
                case "$atype" in
                    VMess) sed -i "/^${bname}|/d" /etc/vmess/.vmess.db 2>/dev/null ;;
                    VLESS) sed -i "/^${bname}|/d" /etc/vless/.vless.db 2>/dev/null ;;
                    Trojan) sed -i "/^${bname}|/d" /etc/trojan/.trojan.db 2>/dev/null ;;
                    Shadowsocks) sed -i "/^${bname}|/d" /etc/shadowsocks/.shadowsocks.db 2>/dev/null ;;
                    SSH) sed -i "/^${bname}|/d" /etc/ssh/.ssh.db 2>/dev/null ;;
                esac
                
                # Hapus quota tracking
                rm -f /etc/limit/vmess/$bname 2>/dev/null
                rm -f /etc/limit/vless/$bname 2>/dev/null
                rm -f /etc/limit/trojan/$bname 2>/dev/null
                rm -f /etc/limit/shadowsocks/$bname 2>/dev/null
                
                echo "$bname|$atype|$aexp" >> "$restore_dir/_auto_reinstall.txt"
                AUTO_INSTALLED=$((AUTO_INSTALLED + 1))
            else
                echo -e "  ${YELLOW}[SKIP]${NC} $bname ($atype) — sudah ada, skip"
            fi
        else
            echo -e "  ${GREEN}[OK]${NC} $bname ($atype) — data siap, tinggal create via menu"
            echo "$bname|$atype|$aexp" >> "$restore_dir/_recommend_create.txt"
        fi
        
        case "$atype" in
            VMess) RESTORED_VMESS=$((RESTORED_VMESS + 1)) ;;
            VLESS) RESTORED_VLESS=$((RESTORED_VLESS + 1)) ;;
            Trojan) RESTORED_TROJAN=$((RESTORED_TROJAN + 1)) ;;
            Shadowsocks) RESTORED_SS=$((RESTORED_SS + 1)) ;;
            SSH) RESTORED_SSH=$((RESTORED_SSH + 1)) ;;
        esac
        RESTORED_TOTAL=$((RESTORED_TOTAL + 1))
    done
    
    # Restart xray jika ada perubahan
    if [[ -f "$restore_dir/xray-config.json" ]] || [[ $AUTO_INSTALLED -gt 0 ]]; then
        systemctl restart xray 2>/dev/null
        echo -e "  ${GREEN}[OK]${NC} Xray di-restart"
    fi
    
    # ── Tampilkan hasil ──────────────────────
    echo ""
    echo -e "${CYAN}══════════════════════════════════════════${NC}"
    echo -e "  ${GREEN}RESTORE SELESAI!${NC}"
    echo ""
    echo -e "  📊 Member diproses: ${RESTORED_TOTAL}"
    echo -e "    • VMess       : ${RESTORED_VMESS}"
    echo -e "    • VLESS       : ${RESTORED_VLESS}"
    echo -e "    • Trojan      : ${RESTORED_TROJAN}"
    echo -e "    • Shadowsocks : ${RESTORED_SS}"
    echo -e "    • SSH         : ${RESTORED_SSH}"
    
    if [[ $AUTO_INSTALLED -gt 0 ]]; then
        echo ""
        echo -e "  ${GREEN}✅ Auto re-install: ${AUTO_INSTALLED} user${NC}"
        echo -e "     (nama sama, otomatis dibuat ulang)"
    fi
    
    if [[ -f "$restore_dir/_recommend_create.txt" ]]; then
        echo ""
        echo -e "  ${YELLOW}⚠️  ${RESTORED_TOTAL} user perlu dibuat ulang:${NC}"
        echo -e "     Jalankan: ${CYAN}cat ${restore_dir}/_recommend_create.txt${NC}"
        echo -e "     Lalu create manual via menu."
    fi
    
    if [[ -f "$restore_dir/_auto_reinstall.txt" ]]; then
        echo ""
        echo -e "  ${GREEN}📋 User yang auto re-install:${NC}"
        cat "$restore_dir/_auto_reinstall.txt"
    fi
    
    echo ""
    echo -e "  ${YELLOW}📌 Backup data lama: /root/fts-backup/pre-restore/${NC}"
    echo ""
    echo -e "${CYAN}══════════════════════════════════════════${NC}"
    
    # Buat log restore
    mkdir -p "$BACKUP_DIR"
    echo "$(date '+%Y-%m-%d %H:%M:%S') | RESTORE from $restore_dir | Total: $RESTORED_TOTAL | AutoInstall: $AUTO_INSTALLED" >> "$BACKUP_DIR/backup-history.txt"
}

# ────────────────────────────────────────────
# MAIN LOGIC
# ────────────────────────────────────────────

# Jika ada argumen URL, langsung download
if [[ -n "$1" ]] && [[ "$1" == http* ]]; then
    # Cek dulu apakah script tunnel udah terinstall
    if ! check_installed; then
        echo -e "${RED}[ERROR]${NC} FTS-Tunnel belum terinstall di VPS ini!"
        echo -e "Silakan install dulu lewat:"
        echo -e "  ${CYAN}wget https://raw.githubusercontent.com/Fannstores/script-new/main/main.sh && chmod +x main.sh && ./main.sh${NC}"
        exit 1
    fi
    
    echo -e "${BLUE}[INFO]${NC} Mode: Restore via URL"
    download_from_url "$1"
    if [[ $? -ne 0 ]]; then
        exit 1
    fi
    
    # Auto install jika nama member sama
    echo ""
    read -p "Auto re-install member dengan nama sama? (y/n): " auto_yn
    if [[ "$auto_yn" == "y" ]]; then
        process_restore "$RESTORE_DIR" true
    else
        process_restore "$RESTORE_DIR" false
    fi
    exit 0
fi

# Jika ada argumen file path
if [[ -n "$1" ]] && [[ -f "$1" ]]; then
    if ! check_installed; then
        echo -e "${RED}[ERROR]${NC} FTS-Tunnel belum terinstall di VPS ini!"
        exit 1
    fi
    
    echo -e "${BLUE}[INFO]${NC} Mode: Restore dari file lokal"
    if [[ "$1" == *.tar.gz ]]; then
        RESTORE_DIR="$BACKUP_DIR/restore-$(date +%Y%m%d-%H%M%S)"
        mkdir -p "$RESTORE_DIR"
        tar xzf "$1" -C "$RESTORE_DIR"
    else
        RESTORE_DIR="$1"
    fi
    
    read -p "Auto re-install member dengan nama sama? (y/n): " auto_yn
    if [[ "$auto_yn" == "y" ]]; then
        process_restore "$RESTORE_DIR" true
    else
        process_restore "$RESTORE_DIR" false
    fi
    exit 0
fi

# ────────────────────────────────────────────
# INTERAKTIF (tanpa argumen)
# ────────────────────────────────────────────
if ! check_installed; then
    echo -e "${RED}[ERROR]${NC} FTS-Tunnel belum terinstall di VPS ini!"
    echo -e ""
    echo -e "Silakan install dulu lewat perintah:"
    echo -e "  ${CYAN}wget https://raw.githubusercontent.com/Fannstores/script-new/main/main.sh${NC}"
    echo -e "  ${CYAN}chmod +x main.sh && ./main.sh${NC}"
    echo -e ""
    echo -e "Atau restore manual dengan cara:"
    echo -e "  1. Install FTS-Tunnel dulu"
    echo -e "  2. Jalankan: ${CYAN}restore-member ${NC}${YELLOW}<URL_BACKUP>${NC}"
    exit 1
fi

echo -e "${BLUE}Pilih sumber restore:${NC}"
echo "  1) URL backup dari Telegram / GitHub"
echo "  2) File .tar.gz lokal (upload via SFTP)"
echo "  3) Folder backup lokal"
echo "  4) Auto restore dari backup terbaru"
echo ""
read -p "Pilih [1-4]: " src_choice

case "$src_choice" in
    1)
        echo -e "${YELLOW}Masukkan URL file backup (.tar.gz):${NC}"
        echo -e "  Contoh: https://raw.githubusercontent.com/.../backup.tar.gz"
        echo -e "  Atau link dari Telegram (private channel)"
        echo ""
        read -p "URL: " url_backup
        
        download_from_url "$url_backup"
        if [[ $? -ne 0 ]]; then
            exit 1
        fi
        
        read -p "Auto re-install member dengan nama sama? (y/n): " auto_yn
        if [[ "$auto_yn" == "y" ]]; then
            process_restore "$RESTORE_DIR" true
        else
            process_restore "$RESTORE_DIR" false
        fi
        ;;
        
    2)
        echo -e "${YELLOW}Upload file .tar.gz ke VPS dulu (via SFTP/SCP)${NC}"
        echo -e "  Contoh: scp backup.tar.gz root@IP_VPS:/root/"
        echo ""
        read -p "Path file .tar.gz di VPS: " tarfile
        
        if [[ ! -f "$tarfile" ]]; then
            echo -e "${RED}[ERROR]${NC} File $tarfile tidak ditemukan!"
            exit 1
        fi
        
        RESTORE_DIR="$BACKUP_DIR/restore-$(date +%Y%m%d-%H%M%S)"
        mkdir -p "$RESTORE_DIR"
        tar xzf "$tarfile" -C "$RESTORE_DIR"
        
        read -p "Auto re-install member dengan nama sama? (y/n): " auto_yn
        if [[ "$auto_yn" == "y" ]]; then
            process_restore "$RESTORE_DIR" true
        else
            process_restore "$RESTORE_DIR" false
        fi
        ;;
        
    3)
        # List folder backup
        backups=()
        i=1
        echo ""
        echo -e "${BLUE}Daftar backup:${NC}"
        for d in "$BACKUP_DIR"/[0-9]*; do
            if [[ -d "$d" ]]; then
                echo "  $i) $(basename "$d")"
                backups+=("$d")
                i=$((i + 1))
            fi
        done
        for f in "$BACKUP_DIR"/*.tar.gz; do
            if [[ -f "$f" ]]; then
                echo "  $i) $(basename "$f") (archive)"
                backups+=("$f")
                i=$((i + 1))
            fi
        done
        
        if [[ ${#backups[@]} -eq 0 ]]; then
            echo -e "${RED}[ERROR]${NC} Tidak ada backup ditemukan di $BACKUP_DIR"
            exit 1
        fi
        
        echo ""
        read -p "Pilih backup [1-${#backups[@]}]: " sel
        
        if [[ ! "$sel" =~ ^[0-9]+$ ]] || [[ "$sel" -lt 1 ]] || [[ "$sel" -gt ${#backups[@]} ]]; then
            echo -e "${RED}[ERROR]${NC} Pilihan tidak valid!"
            exit 1
        fi
        
        selected="${backups[$((sel - 1))]}"
        
        if [[ -f "$selected" ]]; then
            RESTORE_DIR="$BACKUP_DIR/restore-$(date +%Y%m%d-%H%M%S)"
            mkdir -p "$RESTORE_DIR"
            tar xzf "$selected" -C "$RESTORE_DIR"
        else
            RESTORE_DIR="$selected"
        fi
        
        read -p "Auto re-install member dengan nama sama? (y/n): " auto_yn
        if [[ "$auto_yn" == "y" ]]; then
            process_restore "$RESTORE_DIR" true
        else
            process_restore "$RESTORE_DIR" false
        fi
        ;;
        
    4)
        # Cari backup terbaru
        latest=$(ls -t "$BACKUP_DIR"/*.tar.gz 2>/dev/null | head -1)
        if [[ -z "$latest" ]]; then
            latest=$(find "$BACKUP_DIR" -maxdepth 1 -type d -name "*" ! -name "pre-restore*" ! -name "restore*" | sort -r | head -1)
        fi
        
        if [[ -z "$latest" ]]; then
            echo -e "${RED}[ERROR]${NC} Tidak ada backup ditemukan!"
            exit 1
        fi
        
        echo -e "${BLUE}Backup terbaru: ${latest}${NC}"
        read -p "Gunakan backup ini? (y/n): " use_yn
        if [[ "$use_yn" != "y" ]]; then
            exit 0
        fi
        
        if [[ -f "$latest" ]]; then
            RESTORE_DIR="$BACKUP_DIR/restore-$(date +%Y%m%d-%H%M%S)"
            mkdir -p "$RESTORE_DIR"
            tar xzf "$latest" -C "$RESTORE_DIR"
        else
            RESTORE_DIR="$latest"
        fi
        
        # Auto restore dengan auto-install
        echo -e "${GREEN}Auto restore dengan auto re-install member...${NC}"
        process_restore "$RESTORE_DIR" true
        ;;
        
    *)
        echo -e "${RED}[ERROR]${NC} Pilihan tidak valid!"
        exit 1
        ;;
esac

exit 0
