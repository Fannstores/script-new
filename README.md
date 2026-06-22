
# FTS-Tunnel — Fantunel Store Tunnel
**Proprietary Software** — © 2026 Fantunel Store. All Rights Reserved.

---

## 🔥 FITUR TUNNELING TERBARU
- ✅ **Xray-core v26.3.27** (VLESS, VMess, Trojan, Shadowsocks + WS/gRPC)
- ✅ **HAProxy 3.1** (Loadbalancer terbaru)
- ✅ **vnStat 2.13** (Monitoring bandwidth terbaru)
- ✅ OpenSSH, Dropbear, SlowDNS, OpenVPN
- ✅ WebSocket Proxy, UDP-Custom, Noobzvpns
- ✅ BBR + Swap 1GB (optimasi RAM kecil)
- ✅ Fail2ban + Anti-Torrent + IP Limit
- ✅ Auto License via IP (cek lisensi otomatis dari repo)
- ✅ **Backup Member Otomatis** — backup semua akun ke Telegram tiap 24 jam
- ✅ **Restore via URL** — restore dari link backup langsung
- ✅ **Optimized for 500MB RAM** — bisa handle 100+ akun VPN tetap gacor

---

## 📋 DAFTAR ISI
1. [Sistem Operasi yang Didukung](#1-sistem-operasi-yang-didukung)
2. [Contoh Lisensi](#2-contoh-lisensi)
3. [Cara Install](#3-cara-install)
4. [Cloudflare API (Domain Random)](#4-cloudflare-api-untuk-domain-random)
5. [Backup & Restore Member](#5-backup--restore-member)
6. [Cara Update](#6-cara-update)
7. [Cara Uninstall](#7-cara-uninstall)
8. [Struktur Repo](#8-struktur-repo)

---

## 1. SISTEM OPERASI YANG DIDUKUNG

### ✅ Debian Series
| OS | Versi | Codename | Arch | Status |
|----|-------|----------|------|--------|
| Debian | 10 | Buster | x86_64 | ✅ Supported |
| Debian | 11 | Bullseye | x86_64 | ✅ Supported |
| Debian | 12 | Bookworm | x86_64 | ✅ Supported |

### ✅ Ubuntu Series
| OS | Versi | Codename | Arch | Status |
|----|-------|----------|------|--------|
| Ubuntu | 20.04 | Focal Fossa | x86_64 | ✅ Supported |
| Ubuntu | 22.04 | Jammy Jellyfish | x86_64 | ✅ Supported |
| Ubuntu | 24.04 | Noble Numbat | x86_64 | ✅ Supported |

### ❌ Tidak Didukung
- OpenVZ / LXC (hanya KVM)
- i386 / ARM (hanya x86_64 / AMD64)
- RAM di bawah 512MB

---

## 2. CONTOH LISENSI

### Untuk Admin (Bebas IP / Floating)
```bash
ADMIN-KEY|0.0.0.0|2027-12-31|admin|9999
```
> `0.0.0.0` = Bisa install di VPS mana saja

### Untuk User (Terikat IP)
```bash
FTS-USER001|103.25.12.34|2027-12-31|pelanggan1|5
```
> Ganti `103.25.12.34` dengan IP VPS user. `5` = max 5 akun VPN

### Cara Nambah Lisensi
1. Buka `license.txt` di repo GitHub
2. Tambah baris baru:
   ```
   FTS-NAMA|IP_VPS_USER|TGL_EXPIRED|USERNAME|MAX_USER
   ```
3. Commit & push

Atau gunakan **Bot Telegram License Manager** — tambah/hapus lisensi via chat:
> 🤖 [bot-license-manager/](https://github.com/Fannstores/script-new/tree/main/bot-license-manager)

---

## 3. CARA INSTALL

### Syarat VPS:
- ✅ **Debian 10 / 11 / 12** atau **Ubuntu 20.04 / 22.04 / 24.04**
- ✅ **x86_64 (AMD64)** — cek dengan `uname -m`
- ✅ **KVM** (bukan OpenVZ) — cek dengan `systemd-detect-virt`
- ✅ **RAM minimal 512MB**
- ✅ **Root akses**

### Perintah Install (Universal — semua OS):

```bash
apt update && apt upgrade -y && apt install wget curl -y && \
wget https://raw.githubusercontent.com/Fannstores/script-new/main/main.sh && \
chmod +x main.sh && ./main.sh
```

> Lisensi akan dicek otomatis berdasarkan IP VPS Anda.

### Install per OS (Detail)

#### 🐧 Debian 10 (Buster)
```bash
apt update && apt upgrade -y
apt install wget curl -y
wget https://raw.githubusercontent.com/Fannstores/script-new/main/main.sh
chmod +x main.sh
./main.sh
```

#### 🐧 Debian 11 (Bullseye)
```bash
apt update && apt upgrade -y
apt install wget curl -y
wget https://raw.githubusercontent.com/Fannstores/script-new/main/main.sh
chmod +x main.sh
./main.sh
```

#### 🐧 Debian 12 (Bookworm)
```bash
apt update && apt upgrade -y
apt install wget curl -y
wget https://raw.githubusercontent.com/Fannstores/script-new/main/main.sh
chmod +x main.sh
./main.sh
```

#### 🟠 Ubuntu 20.04 (Focal)
```bash
apt update && apt upgrade -y
apt install wget curl -y
wget https://raw.githubusercontent.com/Fannstores/script-new/main/main.sh
chmod +x main.sh
./main.sh
```

#### 🟠 Ubuntu 22.04 (Jammy)
```bash
apt update && apt upgrade -y
apt install wget curl -y
wget https://raw.githubusercontent.com/Fannstores/script-new/main/main.sh
chmod +x main.sh
./main.sh
```

#### 🟠 Ubuntu 24.04 (Noble)
```bash
apt update && apt upgrade -y
apt install wget curl -y
wget https://raw.githubusercontent.com/Fannstores/script-new/main/main.sh
chmod +x main.sh
./main.sh
```

> **💡 Semua perintah di atas IDENTIK.**  
> Script `main.sh` sudah otomatis mendeteksi OS dan versinya, lalu menyesuaikan repo package (HAProxy PPA untuk Ubuntu, HAProxy Debian repo untuk Debian).

### Yang Terinstall Nanti:
| Komponen | Fungsi |
|----------|--------|
| Xray-core v26.3.27 | Tunnel utama (VLESS, VMess, Trojan, Shadowsocks) |
| HAProxy 3.1 | Loadbalancer |
| Nginx | Web server + WebSocket |
| OpenSSH | SSH tunnel |
| Dropbear | SSH alt port |
| SlowDNS | DNS tunnel |
| OpenVPN | OpenVPN TCP/UDP |
| WebSocket Proxy | WS tunnel (python) |
| UDP-Custom | UDP tunnel |
| Noobzvpns | VPN tunnel |
| vnStat 2.13 | Bandwidth monitor |
| BBR + Swap 1GB | Optimasi jaringan |
| Fail2ban | Security |
| IP Limit | Limit user per IP |
| Bot Panel | Management via Telegram |

---

## 4. BACKUP & RESTORE MEMBER

Sistem backup otomatis untuk semua akun member (VMess, VLESS, Trojan, Shadowsocks, SSH).

### Fitur Backup
- ✅ **Backup otomatis setiap 24 jam** (jam 3 pagi)
- ✅ Dikirim ke **Telegram Admin** (file per user + full archive)
- ✅ Nama file = `username.json` — gampang bedain
- ✅ History backup di `/root/fts-backup/backup-history.txt`
- ✅ Hapus otomatis backup > 7 hari
- ✅ **Notifikasi summary** ke Telegram

### Cara Restore

Ada 3 cara restore:

#### 1️⃣ Restore via URL (LANGSUNG dari link)
```bash
restore-member https://raw.githubusercontent.com/Fannstores/script-new/main/Fls/backup.tar.gz
```
Atau link dari Telegram (private channel):
```bash
restore-member https://t.me/c/.../123
```

#### 2️⃣ Restore dari Menu
```bash
restore-member
```
Lalu pilih:
- URL backup
- File .tar.gz lokal
- Folder backup lokal
- Auto restore backup terbaru

#### 3️⃣ Restore via URL tanpa install (curl)
```bash
bash <(curl -s https://raw.githubusercontent.com/Fannstores/script-new/main/Fls/restore-member.sh) https://link-backup.tar.gz
```

### Auto Re-Install
Saat restore, jika ada member dengan **nama yang sama**, script akan:
- ❌ SKIP (tidak diubah)
- ✅ **Auto re-install** (hapus lama → buat ulang dengan data backup)

> Pilih auto re-install jika kamu ingin memulihkan data lama yang mungkin expired/quota-nya berbeda.

### Format File Backup
Setiap user punya file JSON:
```json
{
  "username": "pelanggan1",
  "account_type": "VMess",
  "expiry": "2027-12-31",
  "quota_bytes": "1048576",
  "quota_display": "1MB",
  "backup_date": "2026-06-22 03:00:00",
  "server_ip": "103.25.12.34"
}
```

---

## 5. CLOUDFLARE API (UNTUK DOMAIN RANDOM)

Untuk menggunakan fitur **Random Domain** saat instalasi, wajib isi **Cloudflare API Key** & **Email** di file:

📁 **`Fls/cf.sh`**

Edit file tersebut dan isi:
```bash
CF_EMAIL="email@example.com"
CF_API_KEY="your_cloudflare_global_api_key"
```

---

## 6. CARA UPDATE

### Update Semua Komponen
```bash
wget -q https://raw.githubusercontent.com/Fannstores/script-new/main/update.sh && \
chmod +x update.sh && ./update.sh
```

Atau via menu VPS (jika sudah terinstall):
```bash
menu
```
Lalu pilih opsi **Update**.

### Yang Diupdate:
| Komponen | Sumber |
|----------|--------|
| main.sh | Repo terbaru |
| update.sh | Repo terbaru |
| Menu files | `Cdy/menu.zip` |
| Encrypt binary | `Enc/encrypt` |
| m-noobz binary | `Cfg/m-noobz` |
| check-license | `Fls/check-license` |
| Cron check-license | Setiap 6 menit |

### Update Manual per Komponen
Jika hanya ingin update file tertentu:
```bash
# Update main.sh saja
wget -q -O /root/main.sh https://raw.githubusercontent.com/Fannstores/script-new/main/main.sh
chmod +x /root/main.sh

# Update check-license
wget -q -O /usr/local/bin/check-license https://raw.githubusercontent.com/Fannstores/script-new/main/Fls/check-license
chmod +x /usr/local/bin/check-license

# Restart cron
service cron restart
```

---

## 7. CARA UNINSTALL

> ⚠️ **PERHATIAN:** Uninstall akan MENGHAPUS semua komponen FTS-Tunnel termasuk data user VPN!

### Metode 1: Via Menu (Jika Masih Bisa Akses)
```bash
menu
```
Lalu pilih opsi **Uninstall** / **Remove**.

### Metode 2: Manual (Full Cleanup)
Jalankan perintah berikut untuk menghapus total:

```bash
# Hentikan semua service
systemctl stop xray 2>/dev/null
systemctl stop nginx 2>/dev/null
systemctl stop haproxy 2>/dev/null
systemctl stop dropbear 2>/dev/null
systemctl stop sshd 2>/dev/null
systemctl stop udp-custom 2>/dev/null
systemctl stop ws 2>/dev/null
systemctl stop ws-openssh 2>/dev/null
systemctl stop ws-dropbear 2>/dev/null
systemctl stop cron 2>/dev/null
systemctl stop noobzvpns 2>/dev/null
systemctl stop openvpn 2>/dev/null

# Disable semua service
systemctl disable xray 2>/dev/null
systemctl disable nginx 2>/dev/null
systemctl disable haproxy 2>/dev/null
systemctl disable dropbear 2>/dev/null
systemctl disable udp-custom 2>/dev/null
systemctl disable ws 2>/dev/null
systemctl disable noobzvpns 2>/dev/null
systemctl disable openvpn 2>/dev/null

# Hapus package
apt remove --purge xray nginx haproxy dropbear stunnel4 openvpn -y
apt remove --purge vnstat fail2ban -y
apt autoremove -y
apt autoclean

# Hapus direktori FTS-Tunnel
rm -rf /etc/xray
rm -rf /etc/vmess
rm -rf /etc/vless
rm -rf /etc/trojan
rm -rf /etc/shadowsocks
rm -rf /etc/ssh
rm -rf /etc/bot
rm -rf /etc/fts
rm -rf /var/lib/fts
rm -rf /usr/local/sbin/*
rm -rf /usr/bin/xray
rm -rf /var/log/xray
rm -rf /etc/nginx
rm -rf /etc/haproxy
rm -rf /etc/dropbear
rm -rf /etc/openvpn
rm -rf /root/main.sh
rm -rf /root/update.sh

# Hapus file FTS
rm -f /usr/bin/user
rm -f /usr/bin/e
rm -f /usr/bin/max-user
rm -f /etc/fts-license.conf
rm -f /etc/cron.d/check-license

# Hapus sisa menu
rm -f /usr/local/sbin/menu
rm -f /usr/local/sbin/m-noobz
rm -f /usr/local/bin/check-license
rm -f /usr/bin/enc

# Hapus file installer
rm -f /root/main.sh
rm -f /root/update.sh
rm -f /root/kyt.sh

echo ""
echo "✅ Uninstall selesai! System sudah bersih dari FTS-Tunnel."
echo "Disarankan reboot: reboot"
```

### Metode 3: Script Uninstall (Jika Tersedia)
```bash
wget -q https://raw.githubusercontent.com/Fannstores/script-new/main/uninstall.sh
chmod +x uninstall.sh
./uninstall.sh
```

> Jika `uninstall.sh` belum ada di repo, gunakan **Metode 2** (manual).

---

## 8. STRUKTUR REPO
```
Fannstores/script-new/
├── main.sh              # Installer utama
├── update.sh            # Updater
├── license.txt          # Database lisensi
├── filelist.txt         # Manifest update
├── fts-licgen.sh        # License generator (admin)
├── README.md            # Dokumentasi ini
│
├── Cfg/                 # Konfigurasi
│   ├── config.json      # Xray config
│   ├── haproxy.cfg      # HAProxy config
│   ├── xray.conf        # Nginx Xray config
│   ├── nginx.conf       # Nginx main config
│   ├── dropbear.conf    # Dropbear config
│   ├── tun.conf         # WebSocket tunnel config
│   ├── rclone.conf      # Backup config
│   └── m-noobz          # Noobzvpns binary
│
├── Fls/                 # Service & binary files
│   ├── sshd             # SSHD config
│   ├── password         # PAM password config
│   ├── ws / ws.service  # WebSocket proxy
│   ├── udp-mini*        # UDP Mini
│   ├── runn.service     # Xray runner
│   ├── openvpn          # OpenVPN installer
│   ├── bbr.sh           # BBR installer
│   ├── cf.sh            # Cloudflare (ISI API KEY!)
│   ├── ftvpn            # FTVPN binary
│   ├── limit.sh         # Limit installer
│   ├── limit-ip         # IP limit binary
│   ├── nameserver       # SlowDNS
│   ├── check-license    # License checker cron
│   └── ...              # File limit services
│
├── Enc/encrypt          # Binary encrypt file
├── Bnr/                 # Banner files
├── Bot/                 # Bot Telegram files
├── Cdy/menu.zip         # Menu encrypted
├── Vpn/openvpn          # OpenVPN config
│
├── bot-license-manager/ # 🤖 Bot Telegram License Manager
│   ├── bot.py           # Main bot script
│   ├── README.md        # Panduan install bot
│   ├── install.sh       # One-liner installer
│   └── config.py.example
```

---

## 📦 BOT TELEGRAM LICENSE MANAGER

Ingin kelola lisensi lebih mudah tanpa edit file manual?

Gunakan **FTS-Tunnel License Manager Bot** → tambah/hapus/cek lisensi langsung dari Telegram, otomatis commit ke GitHub.

**Install:**
```bash
bash <(curl -s https://raw.githubusercontent.com/Fannstores/script-new/main/bot-license-manager/install.sh)
```

📖 Panduan lengkap: [bot-license-manager/README.md](https://github.com/Fannstores/script-new/blob/main/bot-license-manager/README.md)

---

## 🐛 TROUBLESHOOTING

### Install gagal?
```
✅ Cek OS: cat /etc/os-release
✅ Cek Arch: uname -m (harus x86_64)
✅ Cek virtualisasi: systemd-detect-virt  (jangan OpenVZ)
✅ Cek RAM: free -m (minimal 512MB)
✅ Cek koneksi: ping google.com
```

### Lisensi tidak valid?
```
✅ Cek IP VPS: curl ifconfig.me
✅ Cek license.txt di repo apakah IP kamu terdaftar
✅ Cek expired date (format YYYY-MM-DD)
✅ Cek floating license (0.0.0.0) — untuk admin
```

### Update gagal?
```
✅ Cek koneksi internet
✅ Cek disk space: df -h
✅ Cek apakah update.sh terdownload: ls -la update.sh
```

---

**© 2026 Fantunel Store. All Rights Reserved.**
