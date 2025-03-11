# 🚀 Network Security System - Suspicious Website Access Detection

This project is a **network security monitoring system** that identifies and flags suspicious website access attempts in **real-time**. It continuously captures **HTTP and HTTPS traffic**, logs accessed domains, and alerts users via **email notifications** if a site matches a predefined list of **suspicious websites**.

---

## 📌 Features

✅ **Real-time network traffic monitoring** (HTTP & HTTPS)  
✅ **Extracts domains from packets** and logs all accessed websites  
✅ **Flags and logs suspicious website access attempts**  
✅ **Multi-threaded design** for efficient sniffing  
✅ **Email alerts for suspicious activity**  
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

### 3️⃣ **Set Up Email Alerts**
Edit the script and replace these placeholders with your email credentials:

```python
SENDER_EMAIL = "your_email@gmail.com"
SENDER_PASSWORD = "your_password"
RECEIVER_EMAIL = "receiver_email@gmail.com"
```

Ensure **Less Secure Apps** is enabled on your email provider or use an **App Password** for authentication.

---

### 4️⃣ **Run the Script**

```sh
python network_monitor.py
```

This will start monitoring network traffic. If any suspicious website is accessed, an **alert will be logged and an email will be sent**.

---

## 📚 Logs & Alerts

The script maintains two log files:

📂 **`network_traffic.log`** → Logs **all** accessed websites with timestamps.  
📂 **`suspicious_access.log`** → Logs **only flagged suspicious** websites.  

### Example:

✅ **`network_traffic.log`** (All captured traffic)
```plaintext
[2025-03-07 14:30:15] 192.168.1.5 -> 8.8.8.8 | google.com
[2025-03-07 14:30:20] 192.168.1.5 -> 31.13.72.36 | facebook.com
[2025-03-07 14:30:25] 192.168.1.5 -> 203.99.99.99 | flexstudent.nu.edu.pk (SUSPICIOUS)
```

⚠️ **`suspicious_access.log`** (Only flagged traffic)
```plaintext
[2025-03-07 14:30:25] 192.168.1.5 -> 203.99.99.99 | flexstudent.nu.edu.pk (SUSPICIOUS)
```

---

## 🚀 Future Enhancements

🔹 **Threat Intelligence API** – Use VirusTotal API to check domains dynamically.  
🔹 **Live Dashboard** – A web interface to monitor traffic in real time.  
🔹 **Machine Learning-based Anomaly Detection** for smarter threat detection.  

---

## 🤝 Contributing

Want to improve this project? Feel free to fork it and submit a **pull request**!  
For major changes, please open an **issue** first.

---

