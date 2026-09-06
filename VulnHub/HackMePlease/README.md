# Hack Me Please

## Recon
- Ports: 80 (HTTP), 3306 (MySQL)

## Enumeration
- Found SeedDMS 5.1.22 via JavaScript
- Found settings.xml → MySQL creds (seeddms:seeddms)

## Exploitation
- MySQL access → changed admin password hash
- Logged into SeedDMS as admin
- Uploaded PHP reverse shell

## User Access
- Reverse shell as www-data

## Privilege Escalation
- Found credentials in MySQL (saket: Saket@#$1337)
- su saket → sudo -l → (ALL:ALL) ALL
- sudo su → root
