# Enigma (HTB Easy)

## Recon
- Ports: 22 (SSH), 80 (HTTP), 110/143/993/995 (mail), 2049 (NFS)

## Enumeration
- NFS share: /srv/nfs/onboarding (public)
- Found OpenSTAManager web app

## Exploitation
- SQL Injection in OpenSTAManager (CVE-2026-24418)
- Dumped users: admin, haris
- Cracked hash → haris:bestfriends

## User Access
- Web shell via P7M upload (CVE-2025-69212)
- Reverse shell as haris

## Privilege Escalation
- Found OliveTin on localhost:1337
- CVE-2026-27626 → command injection
- Got root
