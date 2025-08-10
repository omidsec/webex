# webex
Fast WEB CRAWLER with REGEX search support for precise, in-scope data extraction

# Webex

**Fast domain-scoped web crawler with regex search support for precise, in-scope data extraction.**  
**خزنده سریع محدوده‌دار با پشتیبانی از جستجوی Regex برای استخراج دقیق داده‌ها**

---

## 📜 Description
Webex is a fast, multi-threaded web crawler designed to scan only within a given domain and its subdomains.  
Webex یک ابزار خزنده سریع و چندنخی است که فقط در دامنه و زیردامنه‌های مشخص‌شده جستجو می‌کند.  

It allows you to extract and search for specific patterns in HTML content using **regular expressions (regex)**.  
این ابزار امکان جستجوی الگوهای خاص در محتوای HTML را با استفاده از **عبارات منظم (Regex)** فراهم می‌کند.  

With proxy support (HTTP/SOCKS5), custom headers, and URL filtering, Webex is ideal for penetration testers, bug bounty hunters, and OSINT researchers who need focused crawling without leaving the target scope.  
با پشتیبانی از پراکسی (HTTP/SOCKS5)، هدرهای سفارشی و فیلتر کردن لینک‌ها، Webex گزینه‌ای مناسب برای متخصصان تست نفوذ، شکارچیان باگ و محققان OSINT است که می‌خواهند بدون خروج از محدودهٔ هدف، جستجوی دقیق انجام دهند.

---

## ✨ Features
- 🚀 Multi-threaded crawling for speed  
  🚀 خزنده چندنخی برای سرعت بالا  
- 🌐 Domain & subdomain scope restriction  
  🌐 محدودسازی به دامنه و زیردامنه  
- 🔍 Regex-based content search  
  🔍 جستجوی محتوا با Regex  
- 🛡 Proxy support (HTTP/SOCKS5)  
  🛡 پشتیبانی از پراکسی HTTP/SOCKS5  
- 🎯 Custom headers & User-Agent  
  🎯 هدر سفارشی و User-Agent  
- ⏱ Delay and timeout control  
  ⏱ کنترل تأخیر و زمان انتظار  
- 📂 Automatic results saving  
  📂 ذخیره خودکار نتایج  
- 🔄 Self-update from GitHub  
  🔄 بروزرسانی خودکار از GitHub  

---

## 📥 Installation
**Clone the repository:**  
**کلون کردن مخزن:**
```bash
git clone https://github.com/omidsec/webex.git
cd webex

# Install requirements from file
pip install -r requirements.txt

# Or install manually
pip install requests beautifulsoup4 colorama PySocks

---
Usage

# Basic crawling
python3 webex.py -u https://example.com

# With regex search
python3 webex.py -u https://example.com -r "admin|login"

# Multi-threaded crawling
python3 webex.py -u https://example.com -t 10

# Using HTTP proxy
python3 webex.py -u https://example.com -p http://127.0.0.1:8080

# Using SOCKS5 proxy
python3 webex.py -u https://example.com -p socks5://127.0.0.1:9050

# Custom headers and User-Agent
python3 webex.py -u https://example.com -H "Authorization: Bearer TOKEN" -a "MyCrawler/1.0"

# Exclude specific keywords from URLs
python3 webex.py -u https://example.com --no logout,exit

# Self-update from GitHub before running
python3 webex.py -u https://example.com --update


