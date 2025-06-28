# accurate_cyber_defense_network_security_tool_gui

The Accurate Cyber Defense Network Security Tool (GUI) is an advanced Python-based cybersecurity monitoring application designed to detect and analyze network threats in real time. 

his tool provides a comprehensive graphical interface for monitoring IP addresses, identifying malicious activities such as DoS/DDoS attacks, port scanning, and suspicious traffic patterns, and visualizing security data through interactive charts.

**Key Features**

✅ Real-Time Threat Detection – Monitors live network traffic to detect:

SYN Floods (DoS)

UDP Floods (DDoS)

ICMP Ping Floods

Port Scanning Attempts

📊 Interactive Dashboard – Displays security metrics in real time, including:

Packet statistics (TCP/UDP/ICMP)

Top source IPs and destination ports

Threat distribution (pie chart)

Protocol usage (bar chart)

🖥️ Built-in Terminal – Execute network commands directly:

netstat (view active connections)

ifconfig /all (network interface details)

ping <IP> (check host availability)

start monitoring <IP> (begin security monitoring)

📂 Data Export – Save logs and statistics in:

JSON (structured monitoring data)

TXT (security alerts and logs)

🎨 Customizable UI – Switch between themes:

Purple (default)

Green

Black

**Use Cases**

Network administrators monitoring suspicious traffic

Security analysts investigating potential attacks

Penetration testers assessing network vulnerabilities

Technologies Used
Python 3 (Tkinter, Scapy, Matplotlib, Psutil)

Packet sniffing & analysis (real-time detection)

Multithreading for non-blocking UI

🔗 **Installation & Usage:**

**Clone the repository**

git clone https://github.com/Iankulani/accurate_cyber_defense_network_security_tool_gui.git

Install dependencies (pip install -r requirements.txt)

Run python accurate_cyber_defense_network_security_tool_gui.py

This tool is designed for real-world cybersecurity monitoring, not simulations, making it ideal for professionals and researchers. Contributions and feature requests are welcome!
