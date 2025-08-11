<p align="center">
  <img src="https://omidsec.ir/wp-content/uploads/2025/08/Untitled-1.png" width="250" alt="The lilspider has grown up — once you get to know it, you’ll fall in love">
</p>
# Webex

**Fast web crawler with regex search support for precise, in-scope data extraction.**

<p align="center">
  <img src="https://omidsec.ir/wp-content/uploads/2025/08/tumblr_ojvxu6l2gz1vzgo6mo1_500.gif" width="480" alt="webex is powerful web regex crawler">
</p>
---

## 📜 Description
Webex is a fast, multi-threaded web crawler designed to scan only within a given domain and its subdomains.  
It allows you to extract and search for specific patterns in HTML content using **regular expressions (regex)**.  
With proxy support (HTTP/SOCKS5), custom headers, and URL filtering, Webex is ideal for penetration testers, bug bounty hunters, and OSINT researchers who need focused crawling without leaving the target scope.

---

## ✨ Features
- 🕵️‍♂️ It even gets past CDNs.
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
git clone https://github.com/omidsec/webex
cd webex
```

Install requirements from file
```
pip install -r requirements.txt
```

Or install manually
```
pip install requests beautifulsoup4 colorama PySocks
```

---
## 🖥 Usage

Basic crawling
```
python3 webex.py -u https://example.com
```

With Multiple regex >:)
```
python3 webex.py -u https://example.com -r "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",".*backup.*\.zip$"
```

Multi-threaded crawling
```
python3 webex.py -u https://example.com -t 10
```

Using proxy: HTTP & SOCKS5
```
python3 webex.py -u https://example.com -p http://127.0.0.1:8080
python3 webex.py -u https://example.com -p socks5://127.0.0.1:9050
```

Custom headers and User-Agent
```
python3 webex.py -u https://example.com -H "Authorization: Bearer TOKEN" -a "OmidSec_WebEX_Crawler/1.0"
```

Exclude specific keywords from URLs
```
python3 webex.py -u https://example.com --no logout,exit
```

Self-update from GitHub before running
```
python3 webex.py -u https://example.com --update
```
