#!/bin/bash
# ============================================
# FTS-Tunnel Root VPS Script
# Author    : Fantunel Store
# Copyright : © 2026 Fantunel Store. All Rights Reserved.
# ============================================
# Cara pakai:
#   wget -q https://raw.githubusercontent.com/Fannstores/script-new/main/root-vps.sh && bash root-vps.sh
# ============================================
# Script ini untuk meroot VPS baru agar bisa login sebagai root
# ============================================

Green="\e[92;1m"
RED="\033[1;31m"
YELLOW="\033[33m"
NC='\e[0m'

clear
echo -e "\e[96m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m"
echo -e "\e[97;101m         FTS-ROOT VPS SCRIPT           \e[0m"
echo -e "\e[96m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m"
echo -e "\e[97m   © 2026 Fantunel Store                \e[0m"
echo -e "\e[96m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m"
echo ""

# Cek apakah udah root
if [ "$(id -u)" -eq 0 ]; then
    echo -e "${Green}[✓] Already running as root${NC}"
else
    echo -e "${RED}[✗] Must run as root!${NC}"
    echo -e "${YELLOW}Please run: sudo bash root-vps.sh${NC}"
    exit 1
fi

# Set root password
echo ""
echo -e "${YELLOW}[•] Setting root password...${NC}"
echo -e "Masukkan password root baru (min 6 karakter):"
read -sp "  Password: " rootpass
echo ""
read -sp "  Confirm Password: " rootpass2
echo ""

if [ "$rootpass" != "$rootpass2" ]; then
    echo -e "\n${RED}[✗] Password tidak cocok! Ulangi lagi.${NC}"
    exit 1
fi

if [ ${#rootpass} -lt 6 ]; then
    echo -e "\n${RED}[✗] Password minimal 6 karakter!${NC}"
    exit 1
fi

echo "root:$rootpass" | chpasswd
echo -e "${Green}[✓] Root password set successfully${NC}"

# Enable root SSH login
echo ""
echo -e "${YELLOW}[•] Enabling root SSH login...${NC}"

# Backup dulu
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

# Set PermitRootLogin
sed -i 's/^#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
sed -i 's/^PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config

# Set PasswordAuthentication
sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Set ChallengeResponseAuthentication
sed -i 's/^ChallengeResponseAuthentication.*/ChallengeResponseAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^#ChallengeResponseAuthentication.*/ChallengeResponseAuthentication yes/' /etc/ssh/sshd_config

# Set PubkeyAuthentication
sed -i 's/^#PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config

# Set UsePAM
sed -i 's/^UsePAM.*/UsePAM yes/' /etc/ssh/sshd_config
sed -i 's/^#UsePAM.*/UsePAM yes/' /etc/ssh/sshd_config

# Enable root login for dropbear juga kalo ada
if [ -f /etc/default/dropbear ]; then
    sed -i 's/^DROPBEAR_EXTRA_ARGS.*/DROPBEAR_EXTRA_ARGS="-g"/' /etc/default/dropbear
fi

# Restart SSH
systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null
echo -e "${Green}[✓] Root SSH login enabled${NC}"

# Set timezone
echo ""
echo -e "${YELLOW}[•] Setting timezone Asia/Jakarta...${NC}"
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
echo -e "${Green}[✓] Timezone set${NC}"

echo ""
echo -e "\e[96m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m"
echo -e "${Green}       ROOT VPS COMPLETED!             ${NC}"
echo -e "\e[96m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m"
echo ""
echo -e "  ${Green}Username${NC} : root"
echo -e "  ${Green}Password${NC} : (your password)"
echo ""
echo -e "  ${YELLOW}Login via SSH:${NC}"
echo -e "    ssh root@IP_VPS"
echo ""
echo -e "  ${YELLOW}Next step - Install FTS-Tunnel:${NC}"
echo -e "    wget https://raw.githubusercontent.com/Fannstores/script-new/main/main.sh"
echo -e "    bash main.sh"
echo ""
echo -e "\e[96m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m"
echo -e "\e[97m   © 2026 Fantunel Store                \e[0m"
echo -e "\e[96m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m"
echo ""
