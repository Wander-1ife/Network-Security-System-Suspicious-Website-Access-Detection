# 🚀 Network Security System - Suspicious Website Access Detection

This project is a **network security monitoring system** that identifies and flags suspicious website access attempts in **real-time**. It continuously captures **HTTP and HTTPS traffic**, logs accessed domains, and alerts users if a site matches a predefined list of **suspicious websites**.

---

## 📌 Features

✅ **Real-time network traffic monitoring** (HTTP & HTTPS)  
✅ **Extracts domains from packets** and logs all accessed websites  
✅ **Flags and logs suspicious website access attempts**  
✅ **Multi-threaded design** for efficient sniffing  
✅ **Works on Windows & Linux (with correct interface settings)**  

---

## 🛠 Installation & Setup

### 1️⃣ **Install Dependencies**
Ensure you have **Python 3.10+** installed. Then, install the required libraries:

```sh
pip install scapy pyshark
```

**For Windows Users:**  
Make sure you have **Npcap** installed (needed for packet sniffing). Download it from:  
🔗 [https://nmap.org/npcap/](https://nmap.org/npcap/)

**For Linux Users:**  
Ensure **Wireshark & TShark** are installed:

```sh
sudo apt install tshark -y
```

---

### 2️⃣ **Find Your Network Interface**
Run the following command in Python to get your correct interface name:

```python
import pyshark
print(pyshark.LiveCapture().get_tshark_interfaces())
```

Replace **"Wi-Fi"** in the code with your actual **interface name**.

---

### 3️⃣ **Run the Script**

```sh
python network_monitor.py
```

This will start monitoring network traffic. If any suspicious website is accessed, an alert will be logged.

---

## 📜 Logs & Alerts

The script maintains two log files:

📂 **`network_traffic.log`** → Logs **all** accessed websites with timestamps.  
📂 **`suspicious_access.log`** → Logs **only flagged suspicious** websites.  

### Example:

✅ **`network_traffic.log`** (All captured traffic)
```plaintext
[2025-03-07 14:30:15] google.com
[2025-03-07 14:30:20] facebook.com
[2025-03-07 14:30:25] flexstudent.nu.edu.pk (SUSPICIOUS)
```

⚠️ **`suspicious_access.log`** (Only flagged traffic)
```plaintext
[2025-03-07 14:30:25] flexstudent.nu.edu.pk (SUSPICIOUS)
```

---

## 🚀 Future Enhancements

🔹 **Email Alerts** – Notify admins via email for suspicious access attempts.  
🔹 **Threat Intelligence API** – Use VirusTotal API to check domains dynamically.  
🔹 **Live Dashboard** – A web interface to monitor traffic in real time.  

---

## 🤝 Contributing

Want to improve this project? Feel free to fork it and submit a **pull request**!  
For major changes, please open an **issue** first.

---
