#!/bin/bash
# ============================================
# FTS-Tunnel License Generator
# Author    : Fantunel Store
# Copyright : © 2026 Fantunel Store. All Rights Reserved.
# ============================================
# Cara pakai:
#   chmod +x fts-licgen.sh
#   ./fts-licgen.sh
# ============================================

clear
echo -e "\e[96m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m"
echo -e "\e[97;44m      FTS-TUNNEL LICENSE GENERATOR       \e[0m"
echo -e "\e[96m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m"
echo ""

# --- Input Data Lisensi ---
read -p "Username / Client Name : " USERNAME
read -p "Max User (angka)       : " MAX_USER
read -p "Masa Aktif (hari)     : " EXPIRY_DAYS
read -p "IP Binding (0.0.0.0 = no bind) : " BOUND_IP

# --- Generate License Key ---
LICENSE_KEY=$(echo -n "${USERNAME}-${BOUND_IP}-${EXPIRY_DAYS}-$(date +%s)" | md5sum | head -c 16 | tr 'a-f' 'A-F')
LICENSE_KEY="FTS-${LICENSE_KEY}"

# --- Hitung Expiry Date ---
EXPIRY_DATE=$(date -d "+${EXPIRY_DAYS} days" +"%Y-%m-%d")

# --- Output ---
echo ""
echo -e "\e[96m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m"
echo -e "\e[92m           LICENSE GENERATED!            \e[0m"
echo -e "\e[96m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m"
echo -e "  \e[97mLicense Key :\e[0m \e[93m$LICENSE_KEY\e[0m"
echo -e "  \e[97mUsername    :\e[0m \e[93m$USERNAME\e[0m"
echo -e "  \e[97mBound IP    :\e[0m \e[93m$BOUND_IP\e[0m"
echo -e "  \e[97mExpiry Date :\e[0m \e[93m$EXPIRY_DATE\e[0m"
echo -e "  \e[97mMax User    :\e[0m \e[93m$MAX_USER\e[0m"
echo -e "\e[96m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m"
echo ""

# --- Simpan ke file ---
OUTPUT_FILE="license_${USERNAME}.txt"
cat > "$OUTPUT_FILE" << EOF
# FTS-Tunnel License
# Format: LICENSE_KEY|BOUND_IP|EXPIRY|USERNAME|MAX_USER
${LICENSE_KEY}|${BOUND_IP}|${EXPIRY_DATE}|${USERNAME}|${MAX_USER}
EOF

echo -e "  \e[92mLicense saved to:\e[0m $OUTPUT_FILE"
echo ""
echo -e "\e[96m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m"
echo -e "\e[97m   Instruksi Upload ke GitHub:           \e[0m"
echo -e "\e[96m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m"
echo ""
echo "  1. Buka repo: github.com/fantunelstore/fts-tunnel"
echo "  2. Edit file: license.txt"
echo "  3. Tambahkan baris berikut di baris BARU:"
echo ""
echo -e "     \e[93m${LICENSE_KEY}|${BOUND_IP}|${EXPIRY_DATE}|${USERNAME}|${MAX_USER}\e[0m"
echo ""
echo "  4. Commit & push file license.txt"
echo "  5. Selesai! Client bisa install script"
echo "     dengan memasukkan license key di atas."
echo ""
echo -e "\e[96m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m"
echo ""
