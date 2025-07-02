# 🛡️ **SQL Guardian Pro Elite - Security Testing Framework**

---

## 👋 **Selamat Datang!**

Hai sobat! Kenalin, ini adalah **SQL Guardian Pro Elite**, sebuah tools pentesting yang bisa membantu kamu untuk testing keamanan website. Tools ini dibuat untuk para pemula yang ingin belajar security testing dan juga buat yang udah berpengalaman.

---

## 📖 **Apa itu SQL Guardian Pro Elite?**

SQL Guardian Pro Elite adalah framework sederhana untuk testing keamanan web yang menggabungkan berbagai teknik modern. Tools ini cocok banget buat kamu yang mau belajar atau praktek penetration testing.

### ✨ **Fitur yang Tersedia:**
- 🎯 **300+ Payload SQL Injection** dengan berbagai variasi
- ⚡ **200+ Teknik XSS** termasuk DOM-based
- 🔄 **100+ Vektor Serangan SSRF** untuk testing
- 🦠 **50+ Teknik Malware Injection** 
- 🤖 **AI-Powered WAF Bypass** untuk bypass firewall
- ⚡ **Multi-Threading** biar scanning lebih cepat
- 📊 **Laporan Otomatis** dalam format JSON

---

## ⚙️ **Yang Kamu Butuhkan**

### 📋 **Persyaratan Sistem**
```bash
Python 3.7+ 
pip (Package installer)
Git 
```

### 📚 **Library yang Diperlukan**
```bash
requests
colorama
argparse
urllib3
dnspython
python-whois
cryptography
pyOpenSSL
```

---

## 🔧 **Cara Install Dependencies Library**

### 🐧 **Di Linux (Ubuntu/Debian/Kali)**
```bash
# Update sistem dulu
sudo apt update

# Install Python dan pip
sudo apt install python3 python3-pip git

# Install library yang diperlukan
pip3 install requests
pip3 install colorama
pip3 install argparse
pip3 install urllib3
pip3 install dnspython
pip3 install python-whois
pip3 install cryptography
pip3 install pyOpenSSL

# Atau install sekaligus
pip3 install requests colorama argparse urllib3 dnspython python-whois cryptography pyOpenSSL
```

### 🎩 **Di Linux (CentOS/RHEL/Fedora)**
```bash
# Install Python dan pip
sudo yum install python3 python3-pip git
# atau untuk Fedora:
sudo dnf install python3 python3-pip git

# Install library
pip3 install requests colorama argparse urllib3 dnspython python-whois cryptography pyOpenSSL
```

### 🍎 **Di macOS**
```bash
# Install Homebrew dulu (kalau belum punya)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python
brew install python3 git

# Install library
pip3 install requests colorama argparse urllib3 dnspython python-whois cryptography pyOpenSSL
```

### 🪟 **Di Windows (Command Prompt)**
```cmd
# Install Python dari python.org dulu, terus jalankan:
pip install requests
pip install colorama
pip install argparse
pip install urllib3
pip install dnspython
pip install python-whois
pip install cryptography
pip install pyOpenSSL

# Atau sekaligus:
pip install requests colorama argparse urllib3 dnspython python-whois cryptography pyOpenSSL
```

### ⚡ **Di Windows (PowerShell)**
```powershell
# Install library satu per satu
pip install requests
pip install colorama
pip install urllib3
pip install dnspython
pip install python-whois
pip install cryptography
pip install pyOpenSSL

# Atau langsung sekaligus
pip install requests colorama urllib3 dnspython python-whois cryptography pyOpenSSL
```

### 📱 **Di Termux (Android)**
```bash
# Update Termux
pkg update && pkg upgrade

# Install Python dan Git
pkg install python git

# Install library yang diperlukan
pip install requests
pip install colorama
pip install urllib3
pip install dnspython
pip install python-whois
pip install cryptography
pip install pyOpenSSL

# Atau install sekaligus
pip install requests colorama urllib3 dnspython python-whois cryptography pyOpenSSL
```

---

## 🛠️ **Cara Install Tools**

### 📥 **Download dan Setup**
```bash
# Clone repository
git clone https://github.com/SerpentSecHunter/SQL-Guardian-Pro-Elite.git

# Masuk ke folder
cd SQL-Guardian-Pro-Elite

# Install semua requirements (kalau ada file requirements.txt)
pip install -r requirements.txt
```

---

## 🚀 **Cara Menjalankan Tools**

### 🐧 **Di Linux/macOS**
```bash
python3 sql_guardian.py -u "http://target.com" -p id,username -w -t 15 -o report.json
```

### 📱 **Di Termux**
```bash
python sql_guardian.py -u "http://target.com" -p id -w
```

### 🪟 **Di Windows (CMD)**
```cmd
python sql_guardian.py -u "http://target.com" -p id -w -o report.json
```

### ⚡ **Di Windows (PowerShell)**
```powershell
python sql_guardian.py -u "http://target.com" -p id,username --bypass-waf --threads 10
```

---

## 🔧 **Parameter yang Bisa Digunakan**

| 🎛️ Parameter | 📝 Fungsi | 💡 Contoh |
|--------------|-----------|-----------|
| `-u/--url` | URL target yang mau di-test | `http://example.com?id=1` |
| `-p/--params` | Parameter yang mau dicek | `id,username,email` |
| `-w/--bypass-waf` | Nyalain mode bypass WAF | `-w` |
| `-t/--threads` | Jumlah thread (default: 10) | `-t 15` |
| `-o/--output` | Simpan hasil ke file | `-o hasil.json` |
| `--full-scan` | Mode scan lengkap | `--full-scan` |

---

## 🛠️ **Kalau Ada Error, Ini Solusinya**

### ❌ **Error: ModuleNotFoundError**
**Kalau muncul:**
```bash
ModuleNotFoundError: No module named 'requests'
```

**Solusinya:**
```bash
# Install library yang kurang
pip install requests

# Atau install semua sekaligus
pip install requests colorama argparse urllib3 dnspython python-whois cryptography pyOpenSSL

# Kalau masih error, coba upgrade pip
python -m pip install --upgrade pip
```

### 🔒 **Error: SSL Certificate**
**Solusinya:**
Tambahin kode ini di awal script:
```python
import requests
import urllib3
urllib3.disable_warnings()
```

### ⏱️ **Error: Timeout/Connection**
**Solusinya:**
1. Kurangin jumlah threads:
   ```bash
   python sql_guardian.py -t 5 -u "http://target.com"
   ```
2. Pakai VPN atau proxy
3. Cek koneksi internet kamu

### 🔗 **Error: URL Tidak Valid**
**Pastikan:**
- URL pakai http:// atau https://
- Tidak ada spasi di URL
- Kalau URL panjang, pakai tanda kutip:
  ```bash
  python sql_guardian.py -u "http://example.com/page.php?id=1&user=admin"
  ```

---

## ⚠️ **Peringatan Penting**

### 🚨 **Harus Dibaca:**
1. 📋 **Tools ini cuma buat belajar dan testing legal aja**
2. 📄 **Minta izin dulu sebelum testing website orang**
3. 🚫 **Jangan dipake buat hal-hal yang nggak baik**
4. ⚖️ **Penulis nggak bertanggung jawab kalau disalahgunakan**

---

## 💡 **Contoh Penggunaan**

### 🎯 **Testing Dasar**
```bash
# Scan sederhana dengan bypass WAF
python sql_guardian.py -u "http://testsite.com/profile?id=1" -p id -w
```

### 🔍 **Testing Lengkap**
```bash
# Scan komprehensif dengan banyak thread
python sql_guardian.py -u "http://test.com/login" -p username,password --full-scan -t 15 -o hasil_scan.json
```

---

## 📚 **Belajar Lebih Lanjut**

Kalau mau belajar lebih dalam tentang security testing:
- 🌐 [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- 🎓 [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- 🔬 [MITRE ATT&CK Framework](https://attack.mitre.org/)

---

## 📞 **Bantuan dan Laporan Bug**

Kalau ada masalah atau mau lapor bug:
- 🐙 **GitHub Issues:** [SerpentSecHunter/SQL-Guardian-Pro-Elite](https://github.com/SerpentSecHunter/SQL-Guardian-Pro-Elite/issues)

---

## 🎉 **Penutup**

Makasih udah pakai **SQL Guardian Pro Elite**! Tools ini dibuat dengan harapan bisa membantu teman-teman belajar tentang keamanan web. Ingat ya, pakai tools ini dengan bijak dan selalu untuk hal-hal yang positif.

Semoga bermanfaat dan selamat belajar! 🚀

---

**© 2024 SQL Guardian Pro Elite | By MESTER A**  
*🔐 "Gunakan Dengan Bijak, Belajar Dengan Semangat!"*

---
