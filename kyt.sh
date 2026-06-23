#!/bin/bash
# ============================================
# FTS-Tunnel - Fantunel Store
# Copyright : © 2026 Fantunel Store. All Rights Reserved.
# ============================================
NS=$( cat /etc/xray/dns )
PUB=$( cat /etc/slowdns/server.pub )
domain=$(cat /etc/xray/domain)

cd /etc/systemd/system/
rm -rf kyt.service
cd
grenbo="\e[92;1m"
NC='\e[0m'

cd /usr/bin
rm -rf kyt
rm -rf bot
apt update && apt upgrade
apt install -y python3 python3-pip git
cd /usr/bin
wget https://raw.githubusercontent.com/Fannstores/script-new/main/Bot/bot.zip
unzip bot.zip
mv bot/* /usr/bin
chmod +x /usr/bin/*
rm -rf bot.zip
clear
cd
wget https://raw.githubusercontent.com/Fannstores/script-new/main/Bot/kyt.zip
unzip kyt.zip
cp -r kyt /usr/bin/
cd /usr/bin
pip3 install -r kyt/requirements.txt

echo ""
figlet  FANTUNEL  | lolcat
echo -e "\e[96m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m"
echo -e "\e[97;101m            ADD BOT PANEL              \e[0m"
echo -e "\e[96m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m"
echo -e "${grenbo}How to Create Bot and Get Telegram ID${NC}"
echo -e "${grenbo}[*] Create Bot & Get Token : @BotFather${NC}"
echo -e "${grenbo}[*] Get Telegram ID : @MissRose_bot, command /info${NC}"
echo -e "\e[96m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m"
read -e -p "[*] Input your Bot Token : " bottoken
read -e -p "[*] Input Your Telegram ID :" admin
echo -e BOT_TOKEN='"'$bottoken'"' >> /usr/bin/kyt/var.txt
echo -e ADMIN='"'$admin'"' >> /usr/bin/kyt/var.txt
echo -e DOMAIN='"'$domain'"' >> /usr/bin/kyt/var.txt
echo -e PUB='"'$PUB'"' >> /usr/bin/kyt/var.txt
echo -e HOST='"'$NS'"' >> /usr/bin/kyt/var.txt
rm -f /etc/bot/.bot.db
echo "#bot# ${bottoken} ${admin}" >>/etc/bot/.bot.db
clear

cat > /etc/systemd/system/kyt.service << END
[Unit]
Description=FTS-Tunnel Bot Service
After=network.target

[Service]
WorkingDirectory=/usr/bin
ExecStart=/usr/bin/python3 -m kyt
Restart=always
MemoryMax=100M

[Install]
WantedBy=multi-user.target
END

systemctl start kyt 
systemctl enable kyt
systemctl restart kyt
cd /root
rm -rf kyt*
clear
echo "Done"
echo "Your Bot Data"
echo -e "==============================="
echo "Token Bot         : $bottoken"
echo "Admin          : $admin"
echo "Domain        : $domain"
echo -e "==============================="
echo "Setting done"
echo "Installations complete, type /menu on your bot"
echo " "
echo "© 2026 Fantunel Store. All Rights Reserved."
read -p "press any key for exit"
menu
