#!/bin/bash
# ============================================
# Fantunel Store Tunnel - FTS-Tunnel
# Copyright : © 2026 Fantunel Store. All Rights Reserved.
# ============================================
clear
cd /usr/local/
rm -rf sbin
rm -rf /usr/bin/enc
cd
mkdir -p /usr/local/sbin
dateFromServer=$(curl -v --insecure --silent https://google.com/ 2>&1 | grep Date | sed -e 's/< Date: //')
biji=`date +"%Y-%m-%d" -d "$dateFromServer"`
red() { echo -e "\033[32;1m${*}\033[0m"; }

REPO="https://raw.githubusercontent.com/Fannstores/script-new/main/"

clear
fun_bar() {
    CMD[0]="$1"
    CMD[1]="$2"
    (
        [[ -e $HOME/fim ]] && rm $HOME/fim
        ${CMD[0]} -y >/dev/null 2>&1
        ${CMD[1]} -y >/dev/null 2>&1
        touch $HOME/fim
    ) >/dev/null 2>&1 &
    tput civis
    echo -ne "  \033[1;33mPlease Wait Loading \033[1;37m- \033[1;33m["
    while true; do
        for ((i = 0; i < 18; i++)); do
            echo -ne "\033[1;32m# "
            sleep 0.1s
        done
        [[ -e $HOME/fim ]] && rm $HOME/fim && break
        echo -e "\033[1;33m]"
        sleep 1s
        tput cuu1
        tput dl1
        echo -ne "  \033[1;33mPlease Wait Loading \033[1;37m- \033[1;33m["
    done
    echo -e "\033[1;33m]\033[1;37m -\033[1;32m OK !\033[1;37m"
    tput cnorm
}

res1() {
    # Backup license data before update
    USER_SAVE=""; EXP_SAVE=""; MAX_SAVE=""
    [[ -f /usr/bin/user ]] && USER_SAVE=$(cat /usr/bin/user)
    [[ -f /usr/bin/e ]] && EXP_SAVE=$(cat /usr/bin/e)
    [[ -f /usr/bin/max-user ]] && MAX_SAVE=$(cat /usr/bin/max-user)

    wget -q -O /root/main.sh "${REPO}main.sh"
    chmod +x /root/main.sh
    
    wget -q -O /root/update.sh "${REPO}update.sh"
    chmod +x /root/update.sh
    
    wget -q -O /root/menu.zip "${REPO}Cdy/menu.zip"
    wget -q -O /usr/bin/enc "https://raw.githubusercontent.com/Fannstores/script-new/main/Enc/encrypt"
    chmod +x /usr/bin/enc
    7z x -pCloder07 /root/menu.zip -o/tmp/menu_extract/ 2>/dev/null
    if [[ -d /tmp/menu_extract ]]; then
        chmod +x /tmp/menu_extract/*
        /usr/bin/enc /tmp/menu_extract/* 2>/dev/null
        mv /tmp/menu_extract/* /usr/local/sbin/ 2>/dev/null
        rm -rf /tmp/menu_extract
    fi
    rm -f /root/menu.zip
    
    rm -rf /usr/local/sbin/*~ 2>/dev/null
    rm -rf /usr/local/sbin/gz* 2>/dev/null
    rm -rf /usr/local/sbin/*.bak 2>/dev/null
    
    wget -q -O /usr/local/sbin/m-noobz "${REPO}Cfg/m-noobz"
    chmod +x /usr/local/sbin/m-noobz
    
    wget -q -O /usr/local/bin/check-license "${REPO}Fls/check-license"
    chmod +x /usr/local/bin/check-license
    echo "*/6 * * * * root /usr/local/bin/check-license" > /etc/cron.d/check-license
    service cron restart
    
    # Restore license data
    [[ -n "$USER_SAVE" ]] && echo "$USER_SAVE" > /usr/bin/user
    [[ -n "$EXP_SAVE" ]] && echo "$EXP_SAVE" > /usr/bin/e
    [[ -n "$MAX_SAVE" ]] && echo "$MAX_SAVE" > /usr/bin/max-user
    
    echo "Update completed!"
}

netfilter-persistent
clear
echo -e "\e[96m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m"
echo -e "\e[97;101m           FTS-TUNNEL UPDATE            \e[0m"
echo -e "\e[96m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m"
echo -e ""
echo -e " \033[1;91m Updating all components...\033[1;37m"
fun_bar 'res1'
echo -e "\e[96m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m"
echo -e "\e[97m          Update Complete!               \e[0m"
echo -e "\e[97m     © 2026 Fantunel Store               \e[0m"
echo -e "\e[96m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m"
echo ""
read -n 1 -s -r -p "Press [ Enter ] to back on menu"
menu
