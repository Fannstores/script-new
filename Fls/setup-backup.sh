#!/bin/bash
# ============================================
# FTS-Tunnel - Setup Backup Config
# Author    : Fantunel Store
# ============================================
# Jalankan sekali aja untuk masukin
# Token Bot Telegram & ID Admin buat backup
# ============================================

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
CONFIG_FILE="/etc/fts-backup.conf"
REPO_URL="https://raw.githubusercontent.com/Fannstores/script-new/main"

clear
echo -e "\e[96m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m"
echo -e "\e[97;101m      SETUP BACKUP MEMBER SYSTEM        \e[0m"
echo -e "\e[96m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m"
echo -e ""
echo -e "\e[93m Backup member akan dikirim ke Telegram setiap 24 jam\e[0m"
echo -e "\e[93m Setiap member akan punya file sendiri: username.json\e[0m"
echo -e ""

# Cek apakah udah pernah diisi
if [[ -f "$CONFIG_FILE" ]]; then
    source "$CONFIG_FILE"
    echo -e "\e[92m[OK] Config backup sudah ada!\e[0m"
    echo -e "  BOT_TOKEN: \e[92m${BOT_TOKEN:0:10}...\e[0m"
    echo -e "  CHATID   : \e[92m$CHATID\e[0m"
    echo ""
    read -p "Ubah config? (y/n): " change
    if [[ "$change" != "y" ]]; then
        echo "Setup dibatalkan."
        exit 0
    fi
fi

echo ""
echo -e "\e[36mCARA DAPATKAN TOKEN & CHATID:\e[0m"
echo -e "  \e[33m1.\e[0m Buka @BotFather di Telegram"
echo -e "  \e[33m2.\e[0m Kirim /newbot, ikuti petunjuknya"
echo -e "  \e[33m3.\e[0m Dapatkan TOKEN (contoh: 8553989553:AAG2ag7gtLByORny5br3Nmdzf0lLC07678Y)"
echo -e "  \e[33m4.\e[0m Buka @MissRose_bot, kirim /info"
echo -e "  \e[33m5.\e[0m Dapatkan ID (contoh: 6260838668)"
echo ""

read -p "Masukkan BOT_TOKEN Telegram kamu : " BOT_TOKEN
read -p "Masukkan CHATID Telegram kamu     : " CHATID

if [[ -z "$BOT_TOKEN" || -z "$CHATID" ]]; then
    echo -e "\e[91m[ERROR] Token dan ChatID harus diisi!\e[0m"
    exit 1
fi

# Simpan config
cat > "$CONFIG_FILE" << EOF
# ============================================
# FTS-Tunnel Backup Config
# Author : Fantunel Store
# ============================================
# BOT_TOKEN dan CHATID untuk kirim backup
# ke Telegram setiap 24 jam
# ============================================
BOT_TOKEN="${BOT_TOKEN}"
CHATID="${CHATID}"
EOF

chmod 600 "$CONFIG_FILE"

echo ""
echo -e "\e[92m✅ Config backup tersimpan di $CONFIG_FILE\e[0m"
echo -e ""
echo -e "\e[36m📋 File config berisi:\e[0m"
echo -e "  \e[95mBOT_TOKEN\e[0m = ${BOT_TOKEN:0:15}..."
echo -e "  \e[95mCHATID\e[0m    = $CHATID"
echo ""

# Test kirim pesan
echo -e "\e[93mMengirim test message ke Telegram...\e[0m"
URL="https://api.telegram.org/bot$BOT_TOKEN/sendMessage"
curl -s --max-time 10 -d "chat_id=$CHATID&text=<b>✅ FTS-Tunnel Backup Siap!</b>
<code>Config backup berhasil diisi
File backup: username.json
Backup otomatis tiap 24 jam</code>
© 2026 Fantunel Store" -d "parse_mode=html" "$URL" > /dev/null

if [[ $? -eq 0 ]]; then
    echo -e "\e[92m✅ Test message terkirim! Cek Telegram kamu.\e[0m"
else
    echo -e "\e[91m⚠️ Gagal kirim test. Cek Token & ChatID.\e[0m"
fi

# Jalankan backup sekarang
echo ""
read -p "Jalankan backup sekarang juga? (y/n): " run_now
if [[ "$run_now" == "y" ]]; then
    /usr/local/bin/backup-member
fi

echo ""
echo -e "\e[96m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m"
echo -e "\e[92m           SETUP SELESAI!                \e[0m"
echo -e "\e[96m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m"
echo -e "  \e[97mBackup otomatis jalan tiap jam 3 pagi\e[0m"
echo -e "  \e[97m© 2026 Fantunel Store\e[0m"
echo ""

exit 0
