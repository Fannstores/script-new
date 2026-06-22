#!/bin/bash
# ============================================
# FTS-Tunnel - Backup All Member Accounts
# Author    : Fantunel Store
# Copyright : © 2026 Fantunel Store. All Rights Reserved.
# ============================================
# Script backup member otomatis
# Kirim semua data akun ke Telegram Admin tiap 24 jam
# ============================================

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# ────────────────────────────────────────────
# KONFIGURASI - BACA DARI FILE
# ────────────────────────────────────────────
BACKUP_DIR="/root/fts-backup"
CONFIG_FILE="/etc/fts-backup.conf"
DATE=$(date '+%Y-%m-%d_%H-%M-%S')
DATE_FILE=$(date '+%Y-%m-%d')

# Baca token & chatid dari file config backup
if [[ -f "$CONFIG_FILE" ]]; then
    source "$CONFIG_FILE"
fi

# Fallback: baca dari bot panel (kyt)
if [[ -z "$BOT_TOKEN" || -z "$CHATID" ]]; then
    if [[ -f /etc/bot/.bot.db ]]; then
        CHATID=$(grep -E "^#bot# " /etc/bot/.bot.db | cut -d ' ' -f 3)
        BOT_TOKEN=$(grep -E "^#bot# " /etc/bot/.bot.db | cut -d ' ' -f 2)
    fi
fi

# Kalo masih kosong, beri pesan error
if [[ -z "$BOT_TOKEN" || -z "$CHATID" ]]; then
    echo "[FTS-BACKUP] ERROR: BOT_TOKEN dan CHATID belum diisi!"
    echo "[FTS-BACKUP] Jalankan: setup-backup"
    echo "[FTS-BACKUP] Atau isi manual: nano /etc/fts-backup.conf"
    exit 1
fi

TIME="10"
URL="https://api.telegram.org/bot$BOT_TOKEN/sendMessage"
URL_DOC="https://api.telegram.org/bot$BOT_TOKEN/sendDocument"

# ────────────────────────────────────────────
# FUNCTION
# ────────────────────────────────────────────
send_telegram() {
    local text="$1"
    curl -s --max-time $TIME -d "chat_id=$CHATID&disable_web_page_preview=1&text=$text&parse_mode=html" "$URL" >/dev/null
}

send_file() {
    local file="$1"
    local caption="$2"
    curl -s --max-time $TIME -F "chat_id=$CHATID" -F "document=@$file" -F "caption=$caption" "$URL_DOC" >/dev/null
}

format_bytes() {
    local bytes=$1
    if [[ $bytes -lt 1024 ]]; then echo "${bytes}B"
    elif [[ $bytes -lt 1048576 ]]; then echo "$(( (bytes + 1023)/1024 ))KB"
    elif [[ $bytes -lt 1073741824 ]]; then echo "$(( (bytes + 1048575)/1048576 ))MB"
    else echo "$(( (bytes + 1073741823)/1073741824 ))GB"
    fi
}

# ────────────────────────────────────────────
# MULAI BACKUP
# ────────────────────────────────────────────
mkdir -p "$BACKUP_DIR/$DATE_FILE"
rm -rf "$BACKUP_DIR/$DATE_FILE"/*

TOTAL_MEMBER=0
TOTAL_VMESS=0
TOTAL_VLESS=0
TOTAL_TROJAN=0
TOTAL_SHADOWSOCKS=0
TOTAL_SSH=0

# Backup database files
for db in /etc/vmess/.vmess.db /etc/vless/.vless.db /etc/trojan/.trojan.db /etc/shadowsocks/.shadowsocks.db /etc/ssh/.ssh.db /etc/bot/.bot.db; do
    if [[ -f "$db" ]]; then
        cp "$db" "$BACKUP_DIR/$DATE_FILE/$(basename $(dirname $db))-$(basename $db)"
    fi
done

# Backup xray config
if [[ -f /etc/xray/config.json ]]; then
    cp /etc/xray/config.json "$BACKUP_DIR/$DATE_FILE/xray-config.json"
    
    # Ambil semua member dari config
    MEMBERS=$(grep '^###' /etc/xray/config.json | cut -d ' ' -f 2 | sort | uniq)
    
    for user in $MEMBERS; do
        # Deteksi tipe akun
        EXP_VMESS=$(grep -w "$user" /etc/vmess/.vmess.db 2>/dev/null | cut -d '|' -f 2)
        EXP_VLESS=$(grep -w "$user" /etc/vless/.vless.db 2>/dev/null | cut -d '|' -f 2)
        EXP_TROJAN=$(grep -w "$user" /etc/trojan/.trojan.db 2>/dev/null | cut -d '|' -f 2)
        EXP_SS=$(grep -w "$user" /etc/shadowsocks/.shadowsocks.db 2>/dev/null | cut -d '|' -f 2)
        EXP_SSH=$(grep -w "$user" /etc/ssh/.ssh.db 2>/dev/null | cut -d '|' -f 2)
        
        if [[ -n "$EXP_VMESS" ]]; then TYPE="VMess"; EXP="$EXP_VMESS"; TOTAL_VMESS=$((TOTAL_VMESS + 1))
        elif [[ -n "$EXP_VLESS" ]]; then TYPE="VLESS"; EXP="$EXP_VLESS"; TOTAL_VLESS=$((TOTAL_VLESS + 1))
        elif [[ -n "$EXP_TROJAN" ]]; then TYPE="Trojan"; EXP="$EXP_TROJAN"; TOTAL_TROJAN=$((TOTAL_TROJAN + 1))
        elif [[ -n "$EXP_SS" ]]; then TYPE="Shadowsocks"; EXP="$EXP_SS"; TOTAL_SHADOWSOCKS=$((TOTAL_SHADOWSOCKS + 1))
        elif [[ -n "$EXP_SSH" ]]; then TYPE="SSH"; EXP="$EXP_SSH"; TOTAL_SSH=$((TOTAL_SSH + 1))
        else TYPE="Unknown"; EXP="N/A"
        fi
        
        TOTAL_MEMBER=$((TOTAL_MEMBER + 1))
        
        # Buat file JSON per user - NAMA FILE = USERNAME
        cat > "$BACKUP_DIR/$DATE_FILE/${user}.json" << EOF
{
  "username": "${user}",
  "account_type": "${TYPE}",
  "expiry": "${EXP}",
  "backup_date": "${DATE}",
  "server_ip": "$(curl -s ifconfig.me 2>/dev/null || echo 'unknown')"
}
EOF
    done
fi

# ── Buat file summary ──────────────────────
TOTAL_ALL=$((TOTAL_VMESS + TOTAL_VLESS + TOTAL_TROJAN + TOTAL_SHADOWSOCKS + TOTAL_SSH))

# NAMA FILE BACKUP = username.json biar gampang bedain
SUMMARY=$(cat <<EOF
╔══════════════════════════════════════════╗
║     FTS-TUNNEL BACKUP MEMBER            ║
║     ${DATE_FILE}
╚══════════════════════════════════════════╝

📊 TOTAL MEMBER : ${TOTAL_ALL}

📋 DETAIL:
  • VMess        : ${TOTAL_VMESS}
  • VLESS        : ${TOTAL_VLESS}
  • Trojan       : ${TOTAL_TROJAN}
  • Shadowsocks  : ${TOTAL_SHADOWSOCKS}
  • SSH/OpenVPN  : ${TOTAL_SSH}

🌐 SERVER: $(curl -s ifconfig.me 2>/dev/null || echo 'unknown')

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
LIST MEMBER:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EOF
)

# Append list member
for f in "$BACKUP_DIR/$DATE_FILE"/*.json; do
    [[ -f "$f" ]] || continue
    bname=$(basename "$f" .json)
    [[ "$bname" == _* ]] && continue
    atype=$(grep -o '"account_type":"[^"]*"' "$f" | cut -d'"' -f4)
    aexp=$(grep -o '"expiry":"[^"]*"' "$f" | cut -d'"' -f4)
    SUMMARY+="\n- ${bname} | ${atype} | Exp: ${aexp}"
done

# ── Kirim ke Telegram ──────────────────────
echo "[FTS-BACKUP] Mengirim backup ${TOTAL_ALL} member ke Telegram..."

# Kirim summary
send_telegram "<b>📦 FTS-TUNNEL BACKUP MEMBER</b>
<code>${DATE_FILE}</code>

📊 <b>Total: ${TOTAL_ALL} member</b>
  • VMess: ${TOTAL_VMESS}
  • VLESS: ${TOTAL_VLESS}
  • Trojan: ${TOTAL_TROJAN}
  • Shadowsocks: ${TOTAL_SHADOWSOCKS}
  • SSH: ${TOTAL_SSH}

🌐 Server: $(curl -s ifconfig.me 2>/dev/null || echo '?')
━━━━━━━━━━━━━━━━━━━━━━━━━━━
📁 File name: <b>username.json</b>
⏰ Backup otomatis tiap 24 jam
━━━━━━━━━━━━━━━━━━━━━━━━━━━
© 2026 Fantunel Store"

# Kirim file per user (1-1 biar jelas bedanya)
for f in "$BACKUP_DIR/$DATE_FILE"/*.json; do
    [[ -f "$f" ]] || continue
    bname=$(basename "$f" .json)
    [[ "$bname" == _* ]] && continue
    atype=$(grep -o '"account_type":"[^"]*"' "$f" | cut -d'"' -f4)
    aexp=$(grep -o '"expiry":"[^"]*"' "$f" | cut -d'"' -f4)
    send_file "$f" "📄 <b>${bname}</b> | ${atype} | Exp: ${aexp:-N/A}"
    sleep 2
done

# Kirim full archive
cd "$BACKUP_DIR/$DATE_FILE"
tar czf "$BACKUP_DIR/fts-backup-${DATE_FILE}.tar.gz" . 2>/dev/null
send_file "$BACKUP_DIR/fts-backup-${DATE_FILE}.tar.gz" "📦 <b>Full Backup</b> | ${DATE_FILE} | ${TOTAL_ALL} member"

# ── Log ─────────────────────────────────────
echo "$DATE | TOTAL: $TOTAL_ALL" >> "$BACKUP_DIR/backup-history.txt"
find "$BACKUP_DIR" -name "*.tar.gz" -mtime +7 -delete 2>/dev/null
find "$BACKUP_DIR" -type d -mtime +7 -exec rm -rf {} \; 2>/dev/null

echo "[FTS-BACKUP] ✅ Selesai! ${TOTAL_ALL} member di-backup."
exit 0
