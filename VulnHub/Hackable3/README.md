# Hackable III

## Recon
- Ports: 80 (HTTP), 22 (SSH filtered)
- Port knocking detected (SSH filtered)

## Enumeration
- /config/1.txt → base64 → port 10000
- /css/2.txt → Brainfuck → port 4444
- /backup/wordlist.txt → passwords
- /login_page/ → SQL injection

## Exploitation
- SQL injection in login page
- 3.jpg with steghide → port 65535
- Port knocking: 10000, 4444, 65535
- SSH opened on port 22

## User Access
- Brute-forced SSH with wordlist.txt
- Got user: jubiscleudo

## Privilege Escalation
- Found .backup_config.php in /var/www/html
- Got credentials for hackable_3
- User in lxd group
- LXD privilege escalation → mount host filesystem
- root!

