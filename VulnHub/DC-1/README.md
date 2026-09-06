# DC-1

## Recon
- Ports: 22 (SSH), 80 (HTTP)
- Web: Drupal 7

## Enumeration
- Found Drupal CMS via headers

## Exploitation
- Used Drupalgeddon2 (CVE-2018-7600) for RCE
- Got reverse shell as www-data

## Privilege Escalation
- Found SUID binary: /usr/bin/find
- Exploited: find . -exec /bin/sh \;
- Got root shell
