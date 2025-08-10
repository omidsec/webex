# Webex

**Fast web crawler with regex search support for precise, in-scope data extraction.**

---

## 📜 Description
Webex is a fast, multi-threaded web crawler designed to scan only within a given domain and its subdomains.  
It allows you to extract and search for specific patterns in HTML content using **regular expressions (regex)**.  
With proxy support (HTTP/SOCKS5), custom headers, and URL filtering, Webex is ideal for penetration testers, bug bounty hunters, and OSINT researchers who need focused crawling without leaving the target scope.

---

## ✨ Features
- 🚀 Multi-threaded crawling for speed  
- 🌐 Domain & subdomain scope restriction  
- 🔍 Regex-based content search  
- 🛡 Proxy support (HTTP/SOCKS5)  
- 🎯 Custom headers & User-Agent  
- ⏱ Delay and timeout control  
- 📂 Automatic results saving  
- 🔄 Self-update from GitHub  

---

## 📥 Installation
**Clone the repository:**
```bash
git clone https://github.com/omidsec/webex.git
cd webex
```

# Install requirements from file
```
pip install -r requirements.txt
```

# Or install manually
```
pip install requests beautifulsoup4 colorama PySocks
```

---
## Usage

# Basic crawling
```
python3 webex.py -u https://example.com
```

# With regex search
```
python3 webex.py -u https://example.com -r "admin|login"
```

# Multi-threaded crawling
```
python3 webex.py -u https://example.com -t 10
```

# Using HTTP proxy
```
python3 webex.py -u https://example.com -p http://127.0.0.1:8080
```

# Using SOCKS5 proxy
```
python3 webex.py -u https://example.com -p socks5://127.0.0.1:9050
```

# Custom headers and User-Agent
```
python3 webex.py -u https://example.com -H "Authorization: Bearer TOKEN" -a "MyCrawler/1.0"
```

# Exclude specific keywords from URLs
```
python3 webex.py -u https://example.com --no logout,exit
```

# Self-update from GitHub before running
```
python3 webex.py -u https://example.com --update
```

