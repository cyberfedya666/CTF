# Checkpoint (HTB Medium)

## Recon
- Ports: 22 (SSH), 80 (HTTP), 445 (SMB), etc.

## Enumeration
- SMB with alex.turner:Checkpoint2024!
- Restored deleted user Mark Davies via bloodyad

## Exploitation
- Mark Davies had WRITE on DevDrop share
- Uploaded malicious VSIX (CVE-2025-55319)
- Reverse shell as ryan.brooks

## Privilege Escalation
- Found CreateChild on OU via BadSuccessor
- Created dMSA linked to svc_deploy (CVE-2025-53779)
- BackupAccess → VMBackups → extracted Administrator hash
- Pass-the-Hash → Domain Admin
