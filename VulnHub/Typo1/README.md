# Typo 1

## Recon
- Ports: 80, 8000, 8080, 8081

## Enumeration
- Found TYPO3 CMS on port 80
- Found phpMyAdmin on port 8081

## Exploitation
- phpMyAdmin: root:root
- Changed admin password hash in database
- Logged into TYPO3 as admin

## User Access
- Uploaded PHP reverse shell
- Got shell as www-data

## Privilege Escalation
- SUID binary: apache2-restart
- PATH injection (system("service"))
- Got root
