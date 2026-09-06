# Symfonos 2

## recon
- ports: 21, 22, 80, 139, 445
- FTP: ProFTPD 1.3.5

## exploitation
1. SMB anonymous → log.txt
2. ProFTPD mod_copy → shadow.bak
3. Crack → SSH aeolus

## PrivEsc
- LibreNMS RCE → cronus
- (root) NOPASSWD: /usr/bin/mysql
- sudo mysql -e '\! /bin/sh' --> root

## flags
- proof.txt (ASCII art)
