# My_Personal_Firewal and System Hardening Audit Tool For Linux 
1.A full GUI-Based Firewall for Linux System 
---
using Python, Tkinter, Scapy, and iptables is a moderately advanced project that involves Packet Sniffing, Firewall Rules Management, Logging.

---
Tools: 
1. GUI Development – Using Tkinter. 
2. Packet Sniffing – Using Scapy. 
3. Firewall Rules Management – Interfacing with iptables. 
4. Logging – Capturing packet info and firewall decisions. 
---
Features: 
1.	Add Rules – Allow/block IP, port, protocol.
2.	View Rules – Display currently added iptables rules.
3.	Remove Rules – Select and remove rules.
4.	Packet Logging – Show sniffed packets + firewall decisions.
---
I have attached python file named " mpfirewall.py "  
To run this file on linux system needs to install dependencies using command: </br>
  
       pip install scapy
Now run this command to run the application: 

       sudo python3 mpfirewall.py       
---
2.A Linux Hardening Audit Tool 
---
using python, os commands that Check firewall rules, unused services, SSH settings, rootkit indicators and Generate a score/report based on CIS benchmarks and Recommend hardening actions.

---
Tools: Python, OS commands.

---
Features: 
	
1.	Check firewall rules, unused services, SSH settings
2.	Verify permissions on key files
3.	Check for rootkit indicators
4.	Generate a score/report based on CIS benchmarks
5.	Recommend hardening actions


---
I have attached python file to run this tool by using command: 

    sudo python3 linux_hardening.py 


---
