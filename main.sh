#!/bin/bash
if ! apt update -y; then
echo -e "${red}Failed to update${neutral}"
fi
if ! dpkg -s sudo >/dev/null 2>&1; then
if ! apt install sudo -y; then
echo -e "${red}Failed to install sudo${neutral}"
fi
else
echo -e "${green}sudo is already installed, skipping...${neutral}"
fi
if ! dpkg -s software-properties-common debconf-utils >/dev/null 2>&1; then
if ! apt install -y --no-install-recommends software-properties-common debconf-utils; then
echo -e "${red}Failed to install basic packages${neutral}"
fi
else
echo -e "${green}software-properties-common and debconf-utils are already installed, skipping...${neutral}"
fi
if dpkg -s exim4 >/dev/null 2>&1; then
if ! apt remove --purge -y exim4; then
echo -e "${red}Failed to remove exim4${neutral}"
else
echo -e "${green}exim4 removed successfully${neutral}"
fi
else
echo -e "${green}exim4 is not installed, skipping...${neutral}"
fi
if dpkg -s ufw >/dev/null 2>&1; then
if ! apt remove --purge -y ufw; then
echo -e "${red}Failed to remove ufw${neutral}"
else
echo -e "${green}ufw removed successfully${neutral}"
fi
else
echo -e "${green}ufw is not installed, skipping...${neutral}"
fi
if dpkg -s firewalld >/dev/null 2>&1; then
if ! apt remove --purge -y firewalld; then
echo -e "${red}Failed to remove firewalld${neutral}"
else
echo -e "${green}firewalld removed successfully${neutral}"
fi
else
echo -e "${green}firewalld is not installed, skipping...${neutral}"
fi
if ! echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections; then
echo -e "${red}Failed to configure iptables-persistent v4${neutral}"
fi
if ! echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections; then
echo -e "${red}Failed to configure iptables-persistent v6${neutral}"
fi
if ! debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layout select English"; then
echo -e "${red}Failed to configure keyboard layout${neutral}"
fi
if ! debconf-set-selections <<<"keyboard-configuration keyboard-configuration/variant select English"; then
echo -e "${red}Failed to configure keyboard variant${neutral}"
fi
# INSTALL WEBSOCKET PROXY.JS
# ==========================================
LOG_FILE="/var/log/ws-proxy-install.log"
exec > >(tee -a "$LOG_FILE") 2>&1

echo "========================================="
echo "Starting WebSocket Proxy.js installation..."
echo "========================================="

# -------------------------------
# Set non-interactive mode
# -------------------------------
export DEBIAN_FRONTEND=noninteractive

# -------------------------------
# Update & Install dependencies
# -------------------------------
echo "[STEP 1] Updating system and installing packages..."
apt update -y || true
apt upgrade -y || true
apt install -y wget curl lsof net-tools ufw build-essential || true
# -------------------------------
# Install Node.js
# -------------------------------
echo "[STEP 2] Checking Node.js version..."
apt remove -y nodejs npm || true
NODE_VERSION=$(node -v 2>/dev/null || echo "v0")
NODE_MAJOR=${NODE_VERSION#v}
NODE_MAJOR=${NODE_MAJOR%%.*}

if [[ $NODE_MAJOR -lt 16 ]]; then
    echo "Node.js version too old ($NODE_VERSION). Installing Node.js 18..."
    curl -fsSL https://deb.nodesource.com/setup_18.x | bash - || true
    apt install -y nodejs || true
else
    echo "Node.js version is sufficient ($NODE_VERSION)"
fi

# -------------------------------
# Download proxy.js
# -------------------------------
echo "[STEP 3] Downloading proxy.js..."
rm -f /usr/local/bin/proxy.js
wget -q -O /usr/local/bin/proxy.js https://raw.githubusercontent.com/givps/AutoScriptXray/master/ws-stunnel/proxy.js
chmod +x /usr/local/bin/proxy.js
echo "[STEP 3] proxy.js installed at /usr/local/bin/proxy.js"

# -------------------------------
# Download systemd service
# -------------------------------
echo "[STEP 4] Setting up ws-proxy systemd service..."
rm -f /etc/systemd/system/ws-proxy.service
wget -q -O /etc/systemd/system/ws-proxy.service https://raw.githubusercontent.com/givps/AutoScriptXray/master/ws-stunnel/ws-proxy.service
chmod 644 /etc/systemd/system/ws-proxy.service

cd /usr/local/bin
npm install ws
npm init -y

# Reload systemd to recognize new service
systemctl daemon-reload || true

# Enable and start ws-proxy service
systemctl enable ws-proxy || true
systemctl restart ws-proxy || true

# -------------------------------
# Verify service
# -------------------------------
if systemctl is-active --quiet ws-proxy; then
    echo "[STEP 5] ws-proxy service is active and running."
else
    echo "[WARNING] ws-proxy service failed to start. Check logs with: journalctl -u ws-proxy -f"
fi

# -------------------------------
# Final message
# -------------------------------
echo "========================================="
echo "WebSocket Proxy.js installation complete!"
echo "You can check the service status: systemctl status ws-proxy"
echo "========================================="

if ! apt update -y; then
echo -e "${red}Failed to update${neutral}"
fi
if ! apt-get upgrade -y; then
echo -e "${red}Failed to upgrade${neutral}"
else
echo -e "${green}System upgraded successfully${neutral}"
fi
if ! apt dist-upgrade -y; then
echo -e "${red}Failed to dist-upgrade${neutral}"
else
echo -e "${green}System dist-upgraded successfully${neutral}"
fi
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
apt install -y
apt upgrade -y
apt update -y
apt install curl -y
apt install wondershaper -y
apt install lolcat -y
gem install lolcat
Green="\e[92;1m"
RED="\033[1;31m"
YELLOW="\033[33m"
BLUE="\033[36m"
FONT="\033[0m"
GREENBG="\033[42;37m"
REDBG="\033[41;37m"
OK="${Green}--->${FONT}"
ERROR="${RED}[ERROR]${FONT}"
GRAY="\e[1;30m"
NC='\e[0m'
red='\e[1;31m'
green='\e[0;32m'
TIME=$(date '+%d %b %Y')
ipsaya=$(wget -qO- ipinfo.io/ip)
TIMES="10"
eval $(wget -qO- "https://raw.githubusercontent.com/Pemulaajiw/klmpkfsvpn/main/botkey")
URL="https://api.telegram.org/bot$KEY/sendMessage"
banner_url="https://raw.githubusercontent.com/Fannstores/script-new/main/Bnr/issue.net"
nginx_key_url="https://nginx.org/keys/nginx_signing.key"
dropbear_init_url="https://raw.githubusercontent.com/joytun21/gerhana/main/fodder/dropbear/dropbear"
dropbear_conf_url="https://raw.githubusercontent.com/joytun21/gerhana/main/fodder/examples/dropbear"
dropbear_dss_url="https://raw.githubusercontent.com/joytun21/gerhana/main/fodder/dropbear/dropbear_dss_host_key"
xray_conf_url="https://raw.githubusercontent.com/joytun21/gerhana/main/fodder/nginx/xray.conf"
nginx_conf_url="https://raw.githubusercontent.com/joytun21/gerhana/main/fodder/nginx/nginx.conf"
clear
export IP=$( curl -sS icanhazip.com )
clear
clear && clear && clear
clear;clear;clear
echo -e "${YELLOW}----------------------------------------------------------${NC}"
echo -e "\033[96;1m           WELCOME TO SRICPT FANNTUNEL VIP           \033[0m"
echo -e "${YELLOW}----------------------------------------------------------${NC}"
echo ""
sleep 3
if [[ $( uname -m | awk '{print $1}' ) == "x86_64" ]]; then
echo -e "${OK} Your Architecture Is Supported ( ${green}$( uname -m )${NC} )"
else
echo -e "${EROR} Your Architecture Is Not Supported ( ${YELLOW}$( uname -m )${NC} )"
exit 1
fi
os_id=$(grep -w ID /etc/os-release | head -n1 | sed 's/ID=//g' | sed 's/"//g')
os_version=$(grep -w VERSION_ID /etc/os-release | head -n1 | sed 's/VERSION_ID=//g' | sed 's/"//g')
echo "OS: $os_id, Version: $os_version"
if [ "$EUID" -ne 0 ]; then
echo -e "${red}This script must be run as root${neutral}"
exit 1
fi
if [[ $ipsaya == "" ]]; then
echo -e "${EROR} IP Address ( ${RED}Not Detected${NC} )"
else
echo -e "${OK} IP Address ( ${green}$IP${NC} )"
fi
echo ""
read -p "$( echo -e "Press ${GRAY}[ ${NC}${green}Enter${NC} ${GRAY}]${NC} For Starting Installation") "
echo ""
clear
if [ "${EUID}" -ne 0 ]; then
echo "You need to run this script as root"
exit 1
fi
# -------------------------------
# 1️⃣ Set timezone ke Asia/Jakarta
# -------------------------------
echo "Setting timezone to Asia/Jakarta..."
timedatectl set-timezone Asia/Jakarta
echo "Timezone set:"
timedatectl | grep "Time zone"

# -------------------------------
# 2️⃣ Enable NTP (auto-sync waktu)
# -------------------------------
echo "Enabling NTP..."
timedatectl set-ntp true

# Cek status sinkronisasi
timedatectl status | grep -E "NTP enabled|NTP synchronized"

# -------------------------------
# 3️⃣ Install & enable cron
# -------------------------------
if ! systemctl list-unit-files | grep -q '^cron.service'; then
    echo "Cron not found. Installing cron..."
    apt update -y
    apt install -y cron
fi

echo "Enabling and starting cron service..."
systemctl enable cron
systemctl restart cron

echo ""
echo "✅ VPS timezone, NTP, and cron setup complete!"

if [ "$(systemd-detect-virt)" == "openvz" ]; then
echo "OpenVZ is not supported"
exit 1
fi
red='\e[1;31m'
green='\e[0;32m'
NC='\e[0m'
MYIP=$(curl -sS ipv4.icanhazip.com)
echo -e "\e[32mloading...\e[0m"
clear
MYIP=$(curl -sS ipv4.icanhazip.com)
echo -e "\e[32mloading...\e[0m"
clear
clear
rm -f /usr/bin/user
username=$(curl https://raw.githubusercontent.com/Fannstores/izin/main/ip | grep $MYIP | awk '{print $2}')
echo "$username" >/usr/bin/user
expx=$(curl https://raw.githubusercontent.com/Fannstores/izin/main/ip | grep $MYIP | awk '{print $3}')
echo "$expx" >/usr/bin/e
username=$(cat /usr/bin/user)
exp=$(cat /usr/bin/e)
clear
d1=$(date -d "$valid" +%s)
d2=$(date -d "$today" +%s)
certifacate=$(((d1 - d2) / 86400))
DATE=$(date +'%Y-%m-%d')
datediff() {
d1=$(date -d "$1" +%s)
d2=$(date -d "$2" +%s)
echo -e "$COLOR1 $NC Expiry In   : $(( (d1 - d2) / 86400 )) Days"
}
mai="datediff "$Exp" "$DATE""
Info="(${green}Active${NC})"
Error="(${RED}ExpiRED${NC})"
today=`date -d "0 days" +"%Y-%m-%d"`
Exp1=$(curl https://raw.githubusercontent.com/Fannstores/izin/main/ip | grep $MYIP | awk '{print $4}')
if [[ $today < $Exp1 ]]; then
sts="${Info}"
else
sts="${Error}"
fi
echo -e "\e[32mloading...\e[0m"
clear
REPO="https://raw.githubusercontent.com/Fannstores/script-new/main/"
start=$(date +%s)
secs_to_human() {
echo "Installation time : $((${1} / 3600)) hours $(((${1} / 60) % 60)) minute's $((${1} % 60)) seconds"
}
function print_ok() {
echo -e "${OK} ${BLUE} $1 ${FONT}"
}
function print_install() {
echo -e "${green} =============================== ${FONT}"
echo -e "${YELLOW} # $1 ${FONT}"
echo -e "${green} =============================== ${FONT}"
sleep 1
}
function print_error() {
echo -e "${ERROR} ${REDBG} $1 ${FONT}"
}
function print_success() {
if [[ 0 -eq $? ]]; then
echo -e "${green} =============================== ${FONT}"
echo -e "${Green} # $1 berhasil dipasang"
echo -e "${green} =============================== ${FONT}"
sleep 2
fi
}
function is_root() {
if [[ 0 == "$UID" ]]; then
print_ok "Root user Start installation process"
else
print_error "The current user is not the root user, please switch to the root user and run the script again"
fi
}
print_install "Membuat direktori xray"
mkdir -p /etc/xray
curl -s ifconfig.me > /etc/xray/ipvps
touch /etc/xray/domain
mkdir -p /var/log/xray
chown www-data.www-data /var/log/xray
chmod +x /var/log/xray
touch /var/log/xray/access.log
touch /var/log/xray/error.log
mkdir -p /var/lib/kyt >/dev/null 2>&1
while IFS=":" read -r a b; do
case $a in
"MemTotal") ((mem_used+=${b/kB})); mem_total="${b/kB}" ;;
"Shmem") ((mem_used+=${b/kB}))  ;;
"MemFree" | "Buffers" | "Cached" | "SReclaimable")
mem_used="$((mem_used-=${b/kB}))"
;;
esac
done < /proc/meminfo
Ram_Usage="$((mem_used / 1024))"
Ram_Total="$((mem_total / 1024))"
export tanggal=`date -d "0 days" +"%d-%m-%Y - %X" `
export OS_Name=$( cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/PRETTY_NAME//g' | sed 's/=//g' | sed 's/"//g' )
export Kernel=$( uname -r )
export Arch=$( uname -m )
export IP=$( curl -sS ipv4.icanhazip.com )
function first_setup(){
    timedatectl set-timezone Asia/Jakarta
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
    print_success "Directory Xray"
    ln -fs /usr/share/zoneinfo/$timezone /etc/localtime
    os_id=$(grep -w ID /etc/os-release | head -n1 | sed 's/ID=//g' | sed 's/"//g')
if [[ $os_id == "ubuntu" ]]; then
sudo apt update -y || echo -e "${red}Failed to update package list${neutral}"
if ! dpkg -s software-properties-common >/dev/null 2>&1; then
apt-get install --no-install-recommends software-properties-common || echo -e "${red}Failed to install software-properties-common${neutral}"
else
echo -e "${green}software-properties-common is already installed, skipping...${neutral}"
fi
rm -f /etc/apt/sources.list.d/nginx.list || echo -e "${red}Failed to delete nginx.list${neutral}"
if ! dpkg -s ubuntu-keyring >/dev/null 2>&1; then
apt install -y ubuntu-keyring || echo -e "${red}Failed to install ubuntu-keyring${neutral}"
else
echo -e "${green}ubuntu-keyring is already installed, skipping...${neutral}"
fi
curl $nginx_key_url | gpg --dearmor | tee /usr/share/keyrings/nginx-archive-keyring.gpg >/dev/null
echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] http://nginx.org/packages/ubuntu $(lsb_release -cs) nginx" | tee /etc/apt/sources.list.d/nginx.list
echo -e "Package: *\nPin: origin nginx.org\nPin: release o=nginx\nPin-Priority: 900\n" | tee /etc/apt/preferences.d/99nginx
if ! dpkg -s nginx >/dev/null 2>&1; then
if ! apt install -y nginx; then
echo -e "${red}Failed to install nginx${neutral}"
fi
else
echo -e "${green}nginx is already installed, skipping...${neutral}"
fi
if [ -f /etc/nginx/conf.d/default.conf ]; then
rm /etc/nginx/conf.d/default.conf || echo -e "${red}Failed to delete /etc/nginx/conf.d/default.conf${neutral}"
else
echo -e "${yellow}/etc/nginx/conf.d/default.conf does not exist, skipping deletion${neutral}"
fi
elif [[ $os_id == "debian" ]]; then
sudo apt update -y || echo -e "${red}Failed to update package list${neutral}"
rm -f /etc/apt/sources.list.d/nginx.list || echo -e "${red}Failed to delete nginx.list${neutral}"
if ! dpkg -s debian-archive-keyring >/dev/null 2>&1; then
apt install -y debian-archive-keyring || echo -e "${red}Failed to install debian-archive-keyring${neutral}"
else
echo -e "${green}debian-archive-keyring is already installed, skipping...${neutral}"
fi
curl $nginx_key_url | gpg --dearmor | tee /usr/share/keyrings/nginx-archive-keyring.gpg >/dev/null
echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] http://nginx.org/packages/debian $(lsb_release -cs) nginx" | tee /etc/apt/sources.list.d/nginx.list
echo -e "Package: *\nPin: origin nginx.org\nPin: release o=nginx\nPin-Priority: 900\n" | tee /etc/apt/preferences.d/99nginx
if ! dpkg -s nginx >/dev/null 2>&1; then
apt install -y nginx || echo -e "${red}Failed to install nginx${neutral}"
else
echo -e "${green}nginx is already installed, skipping...${neutral}"
fi
else
echo -e "${red}Unsupported OS. Exiting.${neutral}"
exit 1
fi
if [[ $os_id == "ubuntu" && $os_version == "18.04" ]]; then
add-apt-repository -y ppa:vbernat/haproxy-2.6 || echo -e "${red}Failed to add haproxy repository${neutral}"
sudo apt update -y || echo -e "${red}Failed to update package list${neutral}"
apt-get install -y haproxy=2.6.\* || echo -e "${red}Failed to install haproxy${neutral}"
elif [[ $os_id == "ubuntu" && $os_version == "20.04" ]]; then
add-apt-repository -y ppa:vbernat/haproxy-2.9 || echo -e "${red}Failed to add haproxy repository${neutral}"
sudo apt update -y || echo -e "${red}Failed to update package list${neutral}"
apt-get install -y haproxy=2.9.\* || echo -e "${red}Failed to install haproxy${neutral}"
elif [[ $os_id == "ubuntu" && $os_version == "22.04" ]]; then
add-apt-repository -y ppa:vbernat/haproxy-3.0 || echo -e "${red}Failed to add haproxy repository${neutral}"
sudo apt update -y || echo -e "${red}Failed to update package list${neutral}"
apt-get install -y haproxy=3.0.\* || echo -e "${red}Failed to install haproxy${neutral}"
elif [[ $os_id == "ubuntu" && $os_version == "24.04" ]]; then
add-apt-repository -y ppa:vbernat/haproxy-3.0 || echo -e "${red}Failed to add haproxy repository${neutral}"
sudo apt update -y || echo -e "${red}Failed to update package list${neutral}"
apt-get install -y haproxy=3.0.\* || echo -e "${red}Failed to install haproxy${neutral}"
elif [[ $os_id == "debian" && $os_version == "10" ]]; then
curl https://haproxy.debian.net/bernat.debian.org.gpg | gpg --dearmor >/usr/share/keyrings/haproxy.debian.net.gpg || echo -e "${red}Failed to add haproxy repository${neutral}"
echo deb "[signed-by=/usr/share/keyrings/haproxy.debian.net.gpg]" http://haproxy.debian.net buster-backports-2.6 main >/etc/apt/sources.list.d/haproxy.list || echo -e "${red}Failed to add haproxy repository${neutral}"
sudo apt update -y || echo -e "${red}Failed to update package list${neutral}"
apt-get install -y haproxy=2.6.\* || echo -e "${red}Failed to install haproxy${neutral}"
elif [[ $os_id == "debian" && $os_version == "11" ]]; then
curl https://haproxy.debian.net/bernat.debian.org.gpg | gpg --dearmor >/usr/share/keyrings/haproxy.debian.net.gpg || echo -e "${red}Failed to add haproxy repository${neutral}"
echo deb "[signed-by=/usr/share/keyrings/haproxy.debian.net.gpg]" http://haproxy.debian.net bullseye-backports-3.0 main >/etc/apt/sources.list.d/haproxy.list || echo -e "${red}Failed to add haproxy repository${neutral}"
sudo apt update -y || echo -e "${red}Failed to update package list${neutral}"
apt-get install -y haproxy=3.0.\* || echo -e "${red}Failed to install haproxy${neutral}"
elif [[ $os_id == "debian" && $os_version == "12" ]]; then
curl https://haproxy.debian.net/bernat.debian.org.gpg | gpg --dearmor >/usr/share/keyrings/haproxy.debian.net.gpg || echo -e "${red}Failed to add haproxy repository${neutral}"
echo deb "[signed-by=/usr/share/keyrings/haproxy.debian.net.gpg]" http://haproxy.debian.net bookworm-backports-3.0 main >/etc/apt/sources.list.d/haproxy.list || echo -e "${red}Failed to add haproxy repository${neutral}"
sudo apt update -y || echo -e "${red}Failed to update package list${neutral}"
apt-get install -y haproxy=3.0.\* || echo -e "${red}Failed to install haproxy${neutral}"
elif [[ $os_id == "debian" && $os_version == "13" ]]; then
    echo "deb [signed-by=/usr/share/keyrings/haproxy.debian.net.gpg] http://haproxy.debian.net trixie-backports-3.0 main" >/etc/apt/sources.list.d/haproxy.list || echo -e "${red}Gagal menambahkan repository HAProxy${neutral}"
sudo apt update -y || echo -e "${red}Gagal update daftar paket${neutral}"
apt-get apt install -y haproxy || echo -e "${red}Gagal menginstal HAProxy${neutral}"
elif [[ $os_id == "ubuntu" && $os_version == "25.04" ]]; then
# add-apt-repository -y ppa:vbernat/haproxy-3.2 || echo -e "${red}Failed to add haproxy repository${neutral}"
sudo apt update -y || echo -e "${red}Failed to update package list${neutral}"
apt-get install -y haproxy || echo -e "${red}Failed to install haproxy${neutral}"
else
echo -e "${red}Unsupported OS. Exiting.${neutral}"
exit 1
fi
}
clear
function nginx_install() {
if [[ $(cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g') == "ubuntu" ]]; then
print_install "Setup nginx For OS Is $(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')"
sudo apt-get install nginx -y
elif [[ $(cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g') == "debian" ]]; then
print_success "Setup nginx For OS Is $(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')"
apt -y install nginx
else
echo -e " Your OS Is Not Supported ( ${YELLOW}$(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')${FONT} )"
fi
}
function base_package() {
clear
print_install "Menginstall Packet Yang Dibutuhkan"
echo 'openssh-server openssh-server/keep-obsolete-conffile boolean true' | debconf-set-selections
apt install zip pwgen openssl netcat socat cron bash-completion -y
apt install figlet -y
apt update -y
apt upgrade -y
apt dist-upgrade -y
systemctl enable chronyd
systemctl restart chronyd
systemctl enable chrony
systemctl restart chrony
chronyc sourcestats -v
chronyc tracking -v
apt install ntpdate -y
ntpdate pool.ntp.org
apt install sudo -y
sudo apt-get clean all
sudo apt-get autoremove -y
sudo apt-get install -y debconf-utils
sudo apt-get remove --purge exim4 -y
sudo apt-get remove --purge ufw firewalld -y
sudo apt-get install -y --no-install-recommends software-properties-common
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
# Remove unused or conflicting firewall/mail services
systemctl stop ufw 2>/dev/null
systemctl disable ufw 2>/dev/null
apt-get remove --purge -y ufw firewalld exim4
# Install base system tools and network utilities
apt install -y \
  shc wget curl figlet ruby python3 make cmake \
  iptables iptables-persistent netfilter-persistent \
  coreutils rsyslog net-tools htop screen \
  zip unzip nano sed gnupg bc jq bzip2 gzip \
  apt-transport-https build-essential dirmngr \
  libxml-parser-perl neofetch git lsof iftop \
  libsqlite3-dev libz-dev gcc g++ libreadline-dev \
  zlib1g-dev libssl-dev dos2unix

# Install Ruby gem (colorized text)
gem install lolcat

# Enable and start logging service
systemctl enable rsyslog
systemctl start rsyslog
print_success "Packet Yang Dibutuhkan"
    
}
clear
function pasang_domain() {
echo -e ""
clear
echo -e "    ----------------------------------"
echo -e "   |\e[1;32mPlease Select a Domain Type Below \e[0m|"
echo -e "    ----------------------------------"
echo -e "     \e[1;32m1)\e[0m Your Domain"
echo -e "     \e[1;32m2)\e[0m Random Domain "
echo -e "   ------------------------------------"
read -p "   Please select numbers 1-2 or Any Button(Random) : " host
echo ""
if [[ $host == "1" ]]; then
clear
echo ""
echo ""
echo -e "   \e[1;36m_______________________________$NC"
echo -e "   \e[1;32m      CHANGES DOMAIN $NC"
echo -e "   \e[1;36m_______________________________$NC"
echo -e ""
read -p "   INPUT YOUR DOMAIN :   " host1
echo "IP=${host1}" >> /var/lib/kyt/ipvps.conf
echo $host1 > /etc/xray/domain
echo $host1 > /root/domain
echo ".::. KLMPKFSVPN .::." > /etc/xray/username
echo ""
elif [[ $host == "2" ]]; then
wget https://raw.githubusercontent.com/Pemulaajiw/script/main/files/cf.sh && chmod +x cf.sh && ./cf.sh
rm -f /root/cf.sh
clear
else
print_install "Random Subdomain/Domain is Used"
clear
fi
}
clear
restart_system() {
USRSC=$(wget -qO- https://raw.githubusercontent.com/Fannstores/izin/main/ip | grep $ipsaya | awk '{print $2}')
EXPSC=$(wget -qO- https://raw.githubusercontent.com/Fannstores/izin/main/ip | grep $ipsaya | awk '{print $3}')
TIMEZONE=$(printf '%(%H:%M:%S)T')
TEXT="
<code>────────────────────</code>
<b> 🟢 NOTIFICATIONS INSTALL 🟢</b>
<code>────────────────────</code>
<code>user   : </code><code>$Username</code>
<code>PW     : </code><code>$Password</code>
<code>ID     : </code><code>$USRSC</code>
<code>Domain : </code><code>$domain</code>
<code>Date   : </code><code>$TIME</code>
<code>Time   : </code><code>$TIMEZONE</code>
<code>Ip vps : </code><code>$ipsaya</code>
<code>Exp Sc : </code><code>$EXPSC</code>
<code>────────────────────</code>
<i>Automatic Notification from Github</i>
"
curl -s --max-time $TIMES -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" $URL >/dev/null
}
clear
function pasang_ssl() {
clear
print_install "Memasang SSL Pada Domain"
rm -rf /etc/xray/xray.key
rm -rf /etc/xray/xray.crt
domain=$(cat /root/domain)
STOPWEBSERVER=$(lsof -i:80 | cut -d' ' -f1 | awk 'NR==2 {print $1}')
rm -rf /root/.acme.sh
mkdir /root/.acme.sh
systemctl stop $STOPWEBSERVER
systemctl stop nginx
curl https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
chmod +x /root/.acme.sh/acme.sh
/root/.acme.sh/acme.sh --upgrade --auto-upgrade
/root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
/root/.acme.sh/acme.sh --issue -d $domain --standalone -k ec-256
~/.acme.sh/acme.sh --installcert -d $domain --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc
chmod 777 /etc/xray/xray.key
print_success "SSL Certificate"
}
function make_folder_xray() {
rm -rf /etc/vmess/.vmess.db
rm -rf /etc/vless/.vless.db
rm -rf /etc/trojan/.trojan.db
rm -rf /etc/shadowsocks/.shadowsocks.db
rm -rf /etc/ssh/.ssh.db
rm -rf /etc/bot/.bot.db
mkdir -p /etc/bot
mkdir -p /etc/xray
mkdir -p /etc/vmess
mkdir -p /etc/vless
mkdir -p /etc/trojan
mkdir -p /etc/shadowsocks
mkdir -p /etc/ssh
mkdir -p /usr/bin/xray/
mkdir -p /var/log/xray/
mkdir -p /var/www/html
mkdir -p /etc/kyt/limit/vmess/ip
mkdir -p /etc/kyt/limit/vless/ip
mkdir -p /etc/kyt/limit/trojan/ip
mkdir -p /etc/kyt/limit/ssh/ip
mkdir -p /etc/limit/vmess
mkdir -p /etc/limit/vless
mkdir -p /etc/limit/trojan
mkdir -p /etc/limit/ssh
chmod +x /var/log/xray
touch /etc/xray/domain
touch /var/log/xray/access.log
touch /var/log/xray/error.log
touch /etc/vmess/.vmess.db
touch /etc/vless/.vless.db
touch /etc/trojan/.trojan.db
touch /etc/shadowsocks/.shadowsocks.db
touch /etc/ssh/.ssh.db
touch /etc/bot/.bot.db
echo "& plughin Account" >>/etc/vmess/.vmess.db
echo "& plughin Account" >>/etc/vless/.vless.db
echo "& plughin Account" >>/etc/trojan/.trojan.db
echo "& plughin Account" >>/etc/shadowsocks/.shadowsocks.db
echo "& plughin Account" >>/etc/ssh/.ssh.db
}
function install_xray() {
clear
print_install "Core Xray 1.8.24 Latest Version"
domainSock_dir="/run/xray";! [ -d $domainSock_dir ] && mkdir  $domainSock_dir
chown www-data.www-data $domainSock_dir
latest_version="$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version 1.8.24
wget -O /etc/xray/config.json "${REPO}Cfg/config.json" >/dev/null 2>&1
wget -O /etc/systemd/system/runn.service "${REPO}Fls/runn.service" >/dev/null 2>&1
domain=$(cat /etc/xray/domain)
IPVS=$(cat /etc/xray/ipvps)
print_success "Core Xray 1.8.24 Latest Version"
clear
curl -s ipinfo.io/city >>/etc/xray/city
curl -s ipinfo.io/org | cut -d " " -f 2-10 >>/etc/xray/isp
print_install "Memasang Konfigurasi Packet"
    wget -O /etc/haproxy/haproxy.cfg "https://raw.githubusercontent.com/joytun21/schaya/main/other/haproxy.cfg" >/dev/null 2>&1
wget -O /etc/nginx/conf.d/xray.conf "${REPO}Cfg/xray.conf" >/dev/null 2>&1
sed -i "s/xxx/${domain}/g" /etc/haproxy/haproxy.cfg
sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/xray.conf
curl https://raw.githubusercontent.com/givps/AutoScriptXray/master/ssh/nginx.conf > /etc/nginx/nginx.conf
cat /etc/xray/xray.crt /etc/xray/xray.key | tee /etc/haproxy/hap.pem
chmod +x /etc/systemd/system/runn.service
rm -rf /etc/systemd/system/xray.service.d
cat >/etc/systemd/system/xray.service <<EOF
[Unit]
Description=Xray Service
Documentation=https://github.com
After=network.target nss-lookup.target
[Service]
User=www-data
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNOFILE=1000000
LimitNPROC=65535
[Install]
WantedBy=multi-user.target
EOF
print_success "Konfigurasi Packet"
}
function ssh(){
clear
print_install "Memasang Password SSH"
wget -O /etc/pam.d/common-password "${REPO}Fls/password"
chmod +x /etc/pam.d/common-password
DEBIAN_FRONTEND=noninteractive dpkg-reconfigure keyboard-configuration
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/altgr select The default for the keyboard layout"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/compose select No compose key"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/ctrl_alt_bksp boolean false"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layoutcode string de"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layout select English"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/modelcode string pc105"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/model select Generic 105-key (Intl) PC"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/optionscode string "
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/store_defaults_in_debconf_db boolean true"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/switch select No temporary switch"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/toggle select No toggling"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_config_layout boolean true"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_config_options boolean true"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_layout boolean true"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_options boolean true"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/variantcode string "
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/variant select English"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/xkb-keymap select "
cd
# ==============================================
# SSLH Multi-port Installer (non-root, safe ports)
# ==============================================
# Update system & install dependencies
apt update -y
apt install -y sslh wget build-essential libconfig-dev iproute2

# Buat user/group sslh jika belum ada
getent group sslh >/dev/null || groupadd -r sslh
id -u sslh >/dev/null 2>&1 || useradd -r -g sslh -s /usr/sbin/nologin -d /nonexistent sslh

# Set capability untuk bind port 80/443
getcap /usr/sbin/sslh | grep -q cap_net_bind_service || setcap 'cap_net_bind_service=+ep' /usr/sbin/sslh

# Buat folder run sslh
mkdir -p /run/sslh && chown sslh:sslh /run/sslh

# Buat systemd service type = simple/forking
cat > /etc/systemd/system/sslh.service <<'EOF'
[Unit]
Description=SSL/SSH/OpenVPN/XMPP/tinc port multiplexer
After=network.target

[Service]
ExecStart=/usr/sbin/sslh \
  --listen 0.0.0.0:443 \
  --listen 0.0.0.0:80 \
  --ssh 127.0.0.1:22 \
  --openvpn 127.0.0.1:1196 \
  --tls 127.0.0.1:4433 \
  --http 127.0.0.1:8080 \
  --pidfile /run/sslh/sslh.pid \
  --foreground
User=sslh
Group=sslh
Restart=on-failure
Type=simple

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd dan start service
systemctl daemon-reload
systemctl enable sslh
systemctl restart sslh

# install stunnel
apt install -y stunnel4

cat > /etc/stunnel/stunnel.conf <<EOF
pid = /var/run/stunnel.pid
cert = /etc/stunnel/stunnel.pem
client = no
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

# =====================================
# ssh openssh
# =====================================
[ssh-ssl]
accept = 222
connect = 127.0.0.1:22

# =====================================
# ssh dropbear
# =====================================
[dropbear-ssl]
accept = 333
connect = 127.0.0.1:110

# =====================================
# wss
# =====================================
[wss-ssl]
accept = 444
connect = 127.0.0.1:1444

# =====================================
# tor
# =====================================
[tor-ssl]
accept = 0.0.0.0:777
connect = 127.0.0.1:2222

# =====================================
# openvpn
# =====================================
[openvpn-ssl]
accept = 8443
connect = 127.0.0.1:1196
EOF

# make a certificate
openssl genrsa -out key.pem 2048
openssl req -new -x509 -key key.pem -out cert.pem -days 3650 \
-subj "/C=ID/ST=Jakarta/L=Jakarta/O=givps/OU=IT/CN=localhost/emailAddress=admin@localhost"
cat key.pem cert.pem > /etc/stunnel/stunnel.pem
chmod 600 /etc/stunnel/stunnel.pem

cat > /etc/default/stunnel4 <<EOF
ENABLED=1
FILES="/etc/stunnel/*.conf"
OPTIONS=""
PPP_RESTART=0
EOF

systemctl daemon-reload
systemctl enable stunnel4
systemctl start stunnel4

# install tor
apt install -y tor

cat > /etc/tor/torrc <<'EOF'
Log notice file /var/log/tor/notices.log
SOCKSPort 127.0.0.1:9050
TransPort 127.0.0.1:9040
DNSPort 127.0.0.1:5353
AvoidDiskWrites 1
RunAsDaemon 1
ControlPort 9051
CookieAuthentication 1
EOF

# disable auto start after reboot
systemctl disable tor
systemctl stop tor
# enable auto start after reboot
#systemctl restart tor
#systemctl enable tor

#iptables -t nat -L TOR &>/dev/null || iptables -t nat -N TOR
#TOR_UID=$(id -u debian-tor 2>/dev/null || echo 0)
#iptables -t nat -C TOR -m owner --uid-owner $TOR_UID -j RETURN 2>/dev/null || \
#iptables -t nat -A TOR -m owner --uid-owner $TOR_UID -j RETURN
#iptables -t nat -C TOR -d 127.0.0.0/8 -j RETURN 2>/dev/null || \
#iptables -t nat -A TOR -d 127.0.0.0/8 -j RETURN
#iptables -t nat -C TOR -p udp --dport 53 -j REDIRECT --to-ports 5353 2>/dev/null || \
#iptables -t nat -A TOR -p udp --dport 53 -j REDIRECT --to-ports 5353
#iptables -t nat -C TOR -p tcp -j REDIRECT --to-ports 9040 2>/dev/null || \
#iptables -t nat -A TOR -p tcp -j REDIRECT --to-ports 9040
#iptables -t nat -C OUTPUT -p tcp -j TOR 2>/dev/null || \
#iptables -t nat -I OUTPUT -p tcp -j TOR
cat > /etc/systemd/system/rc-local.service <<-END
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
END
cat > /etc/rc.local <<-END
exit 0
END
chmod +x /etc/rc.local
systemctl enable rc-local
systemctl start rc-local.service
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
print_success "Password SSH"
}
function udp_mini(){
clear
print_install "Memasang Service limit Quota"
wget -q raw.githubusercontent.com/arivpnstores/v10/main/Fls/limit.sh && chmod +x limit.sh && ./limit.sh
mkdir -p /usr/local/kyt/
wget -q -O /usr/local/kyt/udp-mini "${REPO}Fls/udp-mini"
chmod +x /usr/local/kyt/udp-mini
wget -q -O /etc/systemd/system/udp-mini-1.service "${REPO}Fls/udp-mini-1.service"
wget -q -O /etc/systemd/system/udp-mini-2.service "${REPO}Fls/udp-mini-2.service"
wget -q -O /etc/systemd/system/udp-mini-3.service "${REPO}Fls/udp-mini-3.service"
systemctl disable udp-mini-1
systemctl stop udp-mini-1
systemctl enable udp-mini-1
systemctl start udp-mini-1
systemctl disable udp-mini-2
systemctl stop udp-mini-2
systemctl enable udp-mini-2
systemctl start udp-mini-2
systemctl disable udp-mini-3
systemctl stop udp-mini-3
systemctl enable udp-mini-3
systemctl start udp-mini-3
print_success "files Quota Service"
}
function ssh_slow(){
clear
print_install "Memasang modul SlowDNS Server"
wget -q -O /tmp/nameserver "${REPO}Fls/nameserver" >/dev/null 2>&1
chmod +x /tmp/nameserver
bash /tmp/nameserver | tee /root/install.log
clear
print_success "SlowDNS"
}
clear
function ins_SSHD(){
clear
print_install "Memasang SSHD"
wget -q -O /etc/ssh/sshd_config "${REPO}Fls/sshd" >/dev/null 2>&1
chmod 700 /etc/ssh/sshd_config
/etc/init.d/ssh restart
systemctl restart ssh
/etc/init.d/ssh status
print_success "SSHD"
}
clear
function ins_dropbear(){
clear
print_install "Menginstall Dropbear"
# // Installing Dropbear
if [ -n "$dropbear_conf_url" ]; then
[ -f /etc/default/dropbear ] && rm /etc/default/dropbear
wget -q -O /etc/default/dropbear $dropbear_conf_url >/dev/null 2>&1 || echo -e "${red}Failed to download dropbear.conf${neutral}"
[ -f /etc/init.d/dropbear ] && rm /etc/init.d/dropbear
wget -q -O /etc/init.d/dropbear $dropbear_init_url && chmod +x /etc/init.d/dropbear >/dev/null 2>&1 || echo -e "${red}Failed to download dropbear.init${neutral}"
[ -f /etc/dropbear/dropbear_dss_host_key ] && rm /etc/dropbear/dropbear_dss_host_key
wget -q -O /etc/dropbear/dropbear_dss_host_key $dropbear_dss_url && chmod +x /etc/dropbear/dropbear_dss_host_key >/dev/null 2>&1 || echo -e "${red}Failed to download dropbear_dss_host_key${neutral}"
else
echo -e "${yellow}dropbear_conf_url is not set, skipping download of dropbear_dss_host_key${neutral}"
fi
if [ -n "$banner_url" ]; then
wget -q -O /etc/gerhanatunnel.txt $banner_url && chmod +x /etc/gerhanatunnel.txt >/dev/null 2>&1 || echo -e "${red}Failed to download gerhanatunnel.txt${neutral}"
else
echo "Fannatores" > /etc/handeling
echo "Yellow" >> /etc/handeling
fi
print_success "Dropbear"
}
clear
function ins_vnstat(){
clear
print_install "Menginstall Vnstat"
apt -y install vnstat > /dev/null 2>&1
/etc/init.d/vnstat restart
apt -y install libsqlite3-dev > /dev/null 2>&1
wget https://humdi.net/vnstat/vnstat-2.6.tar.gz
tar zxvf vnstat-2.6.tar.gz
cd vnstat-2.6
./configure --prefix=/usr --sysconfdir=/etc && make && make install
cd
vnstat -u -i $NET
sed -i 's/Interface "'""eth0""'"/Interface "'""$NET""'"/g' /etc/vnstat.conf
chown vnstat:vnstat /var/lib/vnstat -R
systemctl enable vnstat
/etc/init.d/vnstat restart
/etc/init.d/vnstat status
rm -f /root/vnstat-2.6.tar.gz
rm -rf /root/vnstat-2.6
print_success "Vnstat"
}
function ins_openvpn(){
clear
print_install "Menginstall OpenVPN"
apt install openvpn -y
wget ${REPO}Vpn/openvpn &&  chmod +x openvpn && ./openvpn
/etc/init.d/openvpn restart
print_success "OpenVPN"
}
function ins_backup(){
clear
print_install "Memasang Backup Server"
apt install rclone -y
printf "q\n" | rclone config
wget -O /root/.config/rclone/rclone.conf "${REPO}Cfg/rclone.conf"
cd /bin
git clone https://github.com/magnific0/wondershaper.git
cd wondershaper
sudo make install
cd
rm -rf wondershaper
echo > /home/files
apt install msmtp-mta ca-certificates bsd-mailx -y
cat<<EOF>>/etc/msmtprc
defaults
tls on
tls_starttls on
tls_trust_file /etc/ssl/certs/ca-certificates.crt
account default
host smtp.gmail.com
port 587
auth on
user oceantestdigital@gmail.com
from oceantestdigital@gmail.com
password jokerman77
logfile ~/.msmtp.log
EOF
chown -R www-data:www-data /etc/msmtprc
wget -q -O /etc/ipserver "${REPO}Fls/ipserver" && bash /etc/ipserver
print_success "Backup Server"
}
clear
function ins_swab(){
clear
print_install "Memasang Swap 1 G"
gotop_latest="$(curl -s https://api.github.com/repos/xxxserxxx/gotop/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
gotop_link="https://github.com/xxxserxxx/gotop/releases/download/v$gotop_latest/gotop_v"$gotop_latest"_linux_amd64.deb"
curl -sL "$gotop_link" -o /tmp/gotop.deb
dpkg -i /tmp/gotop.deb >/dev/null 2>&1
dd if=/dev/zero of=/swapfile bs=1024 count=1048576
mkswap /swapfile
chown root:root /swapfile
chmod 0600 /swapfile >/dev/null 2>&1
swapon /swapfile >/dev/null 2>&1
sed -i '$ i\/swapfile      swap swap   defaults    0 0' /etc/fstab
chronyd -q 'server 0.id.pool.ntp.org iburst'
chronyc sourcestats -v
chronyc tracking -v
wget ${REPO}Fls/bbr.sh &&  chmod +x bbr.sh && ./bbr.sh
print_success "Swap 1 G"
}
function ins_Fail2ban(){
clear
print_install "Menginstall Fail2ban"
clear
apt -y install fail2ban

cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
banaction = iptables-multiport
backend = auto

[sshd]
enabled  = true
port     = 22,2222,109,110
filter   = sshd
backend = systemd
maxretry = 3
findtime = 600
bantime  = 3600

[sshd-ddos]
enabled  = true
port = 22,2222,109,110
filter = sshd
backend = systemd
maxretry = 5
findtime = 300
bantime = 604800

[openvpn-tcp]
enabled  = true
port     = 1195
filter   = openvpn
logpath  = /var/log/openvpn/server-tcp.log
maxretry = 5
bantime  = 86400

[openvpn-udp]
enabled  = true
port     = 51825
filter   = openvpn
logpath  = /var/log/openvpn/server-udp.log
maxretry = 5
bantime  = 86400

[openvpn-ssl]
enabled  = true
port     = 443
filter   = openvpn
logpath  = /var/log/openvpn/server-ssl.log
maxretry = 5
bantime  = 86400

[recidive]
enabled = true
filter = recidive
logpath = /var/log/fail2ban.log
action = iptables-allports[name=recidive, protocol=all]
bantime = 1209600
findtime = 86400
maxretry = 5
EOF

systemctl daemon-reload
systemctl enable fail2ban
systemctl start fail2ban

# Instal DDOS Deflate
wget -qO- https://raw.githubusercontent.com/givps/AutoScriptXray/master/ssh/auto-install-ddos.sh | bash

# install blokir torrent
wget -qO- https://raw.githubusercontent.com/givps/AutoScriptXray/master/ssh/auto-torrent-blocker.sh | bash
print_success "Fail2ban"
}
function ins_epro(){
clear
print_install "Menginstall ePro WebSocket Proxy"
wget -O /usr/bin/install-ws.sh "https://raw.githubusercontent.com/givps/AutoScriptXray/master/ws/install-ws.sh" >/dev/null 2>&1
wget -O /usr/bin/proxy.js "https://raw.githubusercontent.com/givps/AutoScriptXray/master/ws/proxy.js" >/dev/null 2>&1
wget -O /etc/systemd/system/ws-proxy.service "https://raw.githubusercontent.com/givps/AutoScriptXray/master/ws/ws-proxy.service" >/dev/null 2>&1
chmod +x /etc/systemd/system/ws-proxy.service
chmod +x /usr/bin/install-ws.sh
chmod 644 /usr/bin/proxy.js
systemctl disable install-ws.sh
systemctl stop install-ws.sh
systemctl enable install-ws.sh
systemctl start install-ws.sh
systemctl restart install-ws.sh
wget -q -O /usr/local/share/xray/geosite.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" >/dev/null 2>&1
wget -q -O /usr/local/share/xray/geoip.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat" >/dev/null 2>&1
wget -O /usr/sbin/ftvpn "${REPO}Fls/ftvpn" >/dev/null 2>&1
chmod +x /usr/sbin/ftvpn
iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP
iptables -A FORWARD -m string --string "announce_peer" --algo bm -j DROP
iptables -A FORWARD -m string --string "find_node" --algo bm -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP
iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce" -j DROP
iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP
iptables-save > /etc/iptables.up.rules
iptables-restore -t < /etc/iptables.up.rules
netfilter-persistent save
netfilter-persistent reload
cd
apt autoclean -y >/dev/null 2>&1
apt autoremove -y >/dev/null 2>&1
print_success "ePro WebSocket Proxy"

clear
print_install "Menginstall UDP-CUSTOM"
cd
rm -rf /root/udp
mkdir -p /root/udp

# change to time GMT+7
echo "change to time GMT+7"
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime

# install udp-custom
echo downloading udp-custom
wget -q --show-progress --load-cookies /tmp/cookies.txt "https://docs.google.com/uc?export=download&confirm=$(wget --quiet --save-cookies /tmp/cookies.txt --keep-session-cookies --no-check-certificate 'https://docs.google.com/uc?export=download&id=1_VyhL5BILtoZZTW4rhnUiYzc4zHOsXQ8' -O- | sed -rn 's/.*confirm=([0-9A-Za-z_]+).*/\1\n/p')&id=1_VyhL5BILtoZZTW4rhnUiYzc4zHOsXQ8" -O /root/udp/udp-custom && rm -rf /tmp/cookies.txt
chmod +x /root/udp/udp-custom

echo downloading default config
wget -q --show-progress --load-cookies /tmp/cookies.txt "https://docs.google.com/uc?export=download&confirm=$(wget --quiet --save-cookies /tmp/cookies.txt --keep-session-cookies --no-check-certificate 'https://docs.google.com/uc?export=download&id=1_XNXsufQXzcTUVVKQoBeX5Ig0J7GngGM' -O- | sed -rn 's/.*confirm=([0-9A-Za-z_]+).*/\1\n/p')&id=1_XNXsufQXzcTUVVKQoBeX5Ig0J7GngGM" -O /root/udp/config.json && rm -rf /tmp/cookies.txt
chmod 644 /root/udp/config.json

if [ -z "$1" ]; then
cat <<EOF > /etc/systemd/system/udp-custom.service
[Unit]
Description=UDP Custom by ePro Dev. Team

[Service]
User=root
Type=simple
ExecStart=/root/udp/udp-custom server
WorkingDirectory=/root/udp/
Restart=always
RestartSec=2s

[Install]
WantedBy=default.target
EOF
else
cat <<EOF > /etc/systemd/system/udp-custom.service
[Unit]
Description=UDP Custom by ePro Dev. Team

[Service]
User=root
Type=simple
ExecStart=/root/udp/udp-custom server -exclude $1
WorkingDirectory=/root/udp/
Restart=always
RestartSec=2s

[Install]
WantedBy=default.target
EOF
fi

echo start service udp-custom
systemctl start udp-custom &>/dev/null

echo enable service udp-custom
systemctl enable udp-custom &>/dev/null
print_success "UDP-CUSTOM BY NEWBIE STORE VPN"
clear
print_install "MEMASANG NOOBZVPNS"
cd
apt install git -y
git clone https://github.com/Ilham24022001/noobzvpn.git
cd noobzvpn/
chmod +x install.sh
./install.sh

echo start service noobzvpns
systemctl start noobzvpns &>/dev/null

echo enable service noobzvpns
systemctl enable noobzvpns &>/dev/null
print_success "NOOBZVPNS BY NEWBIE STORE"
}
function ins_restart(){
clear
print_install "Restarting  All Packet"
/etc/init.d/nginx restart
/etc/init.d/openvpn restart
/etc/init.d/ssh restart
/etc/init.d/dropbear restart
/etc/init.d/fail2ban restart
/etc/init.d/vnstat restart
systemctl restart haproxy
/etc/init.d/cron restart
systemctl daemon-reload
systemctl start netfilter-persistent
systemctl enable --now nginx
systemctl enable --now xray
systemctl enable --now rc-local
systemctl enable --now dropbear
systemctl enable --now openvpn
systemctl enable --now cron
systemctl enable --now haproxy
systemctl enable --now netfilter-persistent
systemctl enable --now ws
systemctl enable --now fail2ban
systemctl enable --now udp-custom
systemctl enable --NOW noobzvpns
history -c
echo "unset HISTFILE" >> /etc/profile
cd
rm -f /root/openvpn
rm -f /root/key.pem
rm -f /root/cert.pem
print_success "All Packet"
}
function menu(){
clear
print_install "Memasang Menu Packet"
wget https://raw.githubusercontent.com/Fannstores/script-new/main/Cdy/menu.zip
7z x -pCloder07 menu.zip
chmod +x menu/*
mv menu/* /usr/local/sbin
rm -rf menu
rm -rf menu.zip
rm -rf /usr/local/sbin/*~
rm -rf /usr/local/sbin/gz*
rm -rf /usr/local/sbin/*.bak
rm -rf /usr/local/sbin/m-noobz
wget https://raw.githubusercontent.com/Fannstores/script-new/main/Cfg/m-noobz 
cp m-noobz /usr/local/sbin
rm m-noobz*
chmod +x /usr/local/sbin/m-noobz
}
function profile(){
clear
cat >/root/.profile <<EOF
if [ "$BASH" ]; then
if [ -f ~/.bashrc ]; then
. ~/.bashrc
fi
fi
mesg n || true
welcome
EOF
# Install speedtest (using modern method)
curl -s https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.deb.sh | sudo bash
apt-get install -y speedtest || true
cat >/etc/cron.d/daily_backup <<-END
		0 23 * * * root /usr/local/bin/daily_backup
	END

cat >/usr/local/bin/daily_backup <<-END
#!/bin/bash
/usr/local/sbin/backup -r now
END
	chmod +x /usr/local/bin/daily_backup

cat >/etc/cron.d/xp_sc <<-END
		1 0 * * * root /usr/local/bin/xp_sc
	END

cat >/usr/local/bin/xp_sc <<-END
#!/bin/bash
/usr/local/sbin/expsc -r now
END
	chmod +x /usr/local/bin/xp_sc

cat >/etc/cron.d/xp_all <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 2 * * * root /usr/local/sbin/xp
END
cat >/etc/cron.d/logclean <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/10 * * * * root truncate -s 0 /var/log/syslog && truncate -s 0 /var/log/nginx/error.log && truncate -s 0 /var/log/nginx/access.log && truncate -s 0 /var/log/xray/error.log && truncate -s 0 /var/log/xray/access.log
END
chmod 644 /root/.profile
cat >/etc/cron.d/daily_reboot <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 3 * * * root /sbin/reboot
END
echo "*/1 * * * * root echo -n > /var/log/nginx/access.log" >/etc/cron.d/log.nginx
echo "*/1 * * * * root echo -n > /var/log/xray/access.log" >>/etc/cron.d/log.xray
service cron restart
cat >/home/daily_reboot <<-END
5
END
cat >/etc/systemd/system/rc-local.service <<EOF
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
EOF
echo "/bin/false" >>/etc/shells
echo "/usr/sbin/nologin" >>/etc/shells
cat >/etc/rc.local <<EOF
#!/bin/bash
iptables -I INPUT -p udp --dport 5300 -j ACCEPT
iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
# Flush
iptables -F f2b-sshd
iptables -L INPUT -n --line-numbers
# Allow loopback
iptables -I INPUT -i lo -j ACCEPT
# Allow established connections
iptables -I INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
# SSH ports
iptables -C INPUT -p tcp --dport 22 -j ACCEPT 2>/dev/null || \
iptables -I INPUT -p tcp --dport 22 -j ACCEPT
iptables -C INPUT -p tcp --dport 2222 -j ACCEPT 2>/dev/null || \
iptables -I INPUT -p tcp --dport 2222 -j ACCEPT
# HTTP/HTTPS
iptables -C INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || \
iptables -I INPUT -p tcp --dport 80 -j ACCEPT
iptables -C INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || \
iptables -I INPUT -p tcp --dport 443 -j ACCEPT
# HAProxy ports
iptables -C INPUT -p tcp --dport 1443 -j ACCEPT 2>/dev/null || \
iptables -I INPUT -p tcp --dport 1443 -j ACCEPT
iptables -C INPUT -p tcp --dport 1444 -j ACCEPT 2>/dev/null || \
iptables -I INPUT -p tcp --dport 1444 -j ACCEPT
iptables -C INPUT -p tcp --dport 1445 -j ACCEPT 2>/dev/null || \
iptables -I INPUT -p tcp --dport 1445 -j ACCEPT
iptables -C INPUT -p tcp --dport 1446 -j ACCEPT 2>/dev/null || \
iptables -I INPUT -p tcp --dport 1446 -j ACCEPT
iptables -C INPUT -p tcp --dport 1936 -j ACCEPT 2>/dev/null || \
iptables -I INPUT -p tcp --dport 1936 -j ACCEPT
# Save rules
netfilter-persistent save
# chattr +i /etc/iptables/rules.v4
netfilter-persistent reload

systemctl enable netfilter-persistent
systemctl start netfilter-persistent
exit 0
EOF
chmod +x /etc/rc.local
AUTOREB=$(cat /home/daily_reboot)
SETT=11
if [ $AUTOREB -gt $SETT ]; then
TIME_DATE="PM"
else
TIME_DATE="AM"
fi
print_success "Menu Packet"
}
function enable_services(){
clear
print_install "Enable Service"
systemctl daemon-reload
systemctl start netfilter-persistent
systemctl enable --now rc-local
systemctl enable --now cron
systemctl enable --now netfilter-persistent
systemctl restart nginx
systemctl restart xray
systemctl restart cron
systemctl restart haproxy
print_success "Enable Service"
clear
}
function instal(){
clear
first_setup
make_folder_xray
pasang_domain
nginx_install
base_package
password_default
pasang_ssl
install_xray
ssh
udp_mini
ssh_slow
ins_SSHD
ins_dropbear
ins_vnstat
ins_openvpn
ins_backup
ins_swab
ins_Fail2ban
ins_epro
ins_restart
menu
profile
enable_services
restart_system
}
instal
NEW_FILE_MAX=65535
NF_CONNTRACK_MAX="net.netfilter.nf_conntrack_max=262144"
NF_CONNTRACK_TIMEOUT="net.netfilter.nf_conntrack_tcp_timeout_time_wait=30"
SYSCTL_CONF="/etc/sysctl.conf"
CURRENT_FILE_MAX=$(grep "^fs.file-max" "$SYSCTL_CONF" | awk '{print $3}' 2>/dev/null)
if [ "$CURRENT_FILE_MAX" != "$NEW_FILE_MAX" ]; then
    if grep -q "^fs.file-max" "$SYSCTL_CONF"; then
        sed -i "s/^fs.file-max.*/fs.file-max = $NEW_FILE_MAX/" "$SYSCTL_CONF" >/dev/null 2>&1
    else
        echo "fs.file-max = $NEW_FILE_MAX" >> "$SYSCTL_CONF" 2>/dev/null
    fi
fi
if ! grep -q "^net.netfilter.nf_conntrack_max" "$SYSCTL_CONF"; then
    echo "$NF_CONNTRACK_MAX" >> "$SYSCTL_CONF" 2>/dev/null
fi
if ! grep -q "^net.netfilter.nf_conntrack_tcp_timeout_time_wait" "$SYSCTL_CONF"; then
    echo "$NF_CONNTRACK_TIMEOUT" >> "$SYSCTL_CONF" 2>/dev/null
fi
sysctl -p >/dev/null 2>&1
echo ""
history -c
rm -rf /root/menu
rm -rf /root/*.zip
rm -rf /root/*.sh
rm -rf /root/LICENSE
rm -rf /root/README.md
rm -rf /root/domain
secs_to_human "$(($(date +%s) - ${start}))"
sudo hostnamectl set-hostname $username
LOCAL_IP="127.0.1.1"
if ! grep -q "$username" /etc/hosts; then
    echo "$LOCAL_IP    $username" >> /etc/hosts
fi
clear
echo -e ""
echo -e ""
echo -e "\033[96m==========================\033[0m"
echo -e "\033[92m      INSTALL SUCCES      \033[0m"
echo -e "\033[96m==========================\033[0m"
echo -e ""
sleep 2
clear
echo -e "\033[93;1m Wait inn 4 sec...\033[0m"
sleep 4
clear
echo ""
echo ""
echo ""
read -p "Press [ Enter ]  TO REBOOT"
clear
reboot
