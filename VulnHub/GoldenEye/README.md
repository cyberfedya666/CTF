# GoldenEye 1

## Recon
- Ports: 25 (SMTP), 80 (HTTP), 55006/55007 (POP3)

## Enumeration
- Found /sev-home/ via terminal.js
- Decoded HTML entities → InvincibleHack3r
- Brute-forced POP3: boris:secret1!, natalya:bird

## Exploitation
- Read emails → Moodle creds (xenia, dr_doak)
- Found base64 in image → xWinter1995x!
- Moodle RCE via TinyMCE spellchecker

## User Access
- Reverse shell as www-data

## Privilege Escalation
- Kernel 3.13 → CVE-2015-1328 (overlayfs)
- Compiled exploit with cc
- Got root
