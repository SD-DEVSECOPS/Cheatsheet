# OSCP Weaponry: The Ultimate Tool & Setup Guide

This guide is your primary asset for ensuring your Kali environment is prepped and your Windows binaries are ready for any lab or exam scenario.

---

## 1. Reconnaissance & Initial Foothold

### **Checklist**
- [ ] **Nmap**: Standard scanning.
- [ ] **ffuf / Gobuster**: Fast fuzzing. (Use `ffuf` for VHosts and Extensions).
- [ ] **NetExec (nxc)**: The Swiss Army knife for protocol enumeration (SMB, LDAP, MSSQL, WinRM).
- [ ] **Wpscan**: WordPress specific scanning.
- [ ] **Cadaver**: Command-line WebDAV client (essential if write access is found).

### **Operational Tips**
*   **WebDAV**: If `cadaver` reveals write access, always test file filters with a `.txt` before uploading a `.php` shell.
*   **NetExec**: Use `--rid-brute` on SMB to find user accounts if you have guest/null session access.

---

## 2. Active Directory & Kerberos

### **Checklist**
- [ ] **Impacket Suite**: `secretsdump`, `ntlmrelayx`, `mssqlclient`, `getST`, `ticketer`, `GetNPUsers`, `GetUserSPNs`.
- [ ] **Certipy**: Modern AD CS (Certificate Services) exploitation tool.
- [ ] **bloodyAD**: Python-based AD object manipulator (best for GenericAll/WriteMember rights).
- [ ] **Rubeus.exe**: The Kerberos engine for Windows. (Keep .NET 3.5 and 4.5 versions).
- [ ] **SharpHound.exe**: AD data collector for BloodHound.
- [ ] **Whisker / PyWhisker**: Shadow Credentials (msDS-KeyCredentialLink).

### **Operational Tips**
*   **Faketime (Clock Skew Fix)**: If your Kali time differs from the DC and you can't change your system clock (due to `ntpdate` restrictions), use `faketime`:
    *   `faketime '2023-12-01 12:00:00' impacket-GetUserSPNs ...`
    *   Alternatively, use the relative offset: `faketime -5m impacket-secretsdump ...`
*   **bloodyAD Flags**:
    *   Always use `--host [DC_IP]` to avoid DNS resolution issues.
    *   `bloodyAD add right 'DC=domain,DC=local' 'CN=user,CN=Users...' DCSync` (Granting DCSync).
*   **Certipy DNS**: You **MUST** put the CA hostname in `/etc/hosts`:
    *   `10.10.10.10  dc01.domain.local  CA-SERVER`

---

## 3. Lateral Movement & Post-Exploitation

### **Checklist**
- [ ] **Evil-WinRM**: Best WinRM shell environment. Supports PTH and file uploads.
- [ ] **Mimikatz.exe**: Credential and ticket extraction on Windows.
- [ ] **pyLAPS**: Reading LAPS passwords from Kali.
- [ ] **GMSAPasswordReader.exe**: Reading managed service account passwords.
- [ ] **Invoke-RunasCs.ps1**: PowerShell utility to spawn processes as other users.
- [ ] **KeeThief / KeeFarce**: If you encounter KeePass databases. (Less common in OSCP but good for red teaming).

### **Operational Tips**
*   **Mimikatz**: Run `privilege::debug` before anything else.
*   **Evil-WinRM**: Use the `-H` flag for Pass-the-Hash if you only have the NTLM hash.

---

## 4. Privilege Escalation (.exe & .ps1)

### **Checklist**
- [ ] **PrintSpoofer.exe**: SeImpersonate (Win Server 2016/2019).
- [ ] **GodPotato.exe**: SeImpersonate (Modern Windows/Server 2022).
- [ ] **JuicyPotato.exe**: SeImpersonate (Legacy/Windows 10 <= 1809).
- [ ] **SharpGPOAbuse.exe**: Exploit GenericWrite on GPOs.
- [ ] **SeManageVolumeExploit.exe**: Exploit SeManageVolumePrivilege (custom compile required).
- [ ] **WinPEASany.exe / linpeas.sh**: Automated enumeration.
- [ ] **PowerUp.ps1**: Legacy PowerShell privesc check (`Invoke-AllChecks`).

---

## 5. Pivoting & Tunnels

### **Checklist**
- [ ] **Chisel**: HTTP tunnels for port forwarding.
- [ ] **Ligolo-ng**: TUN-based networking (allows transparent scanning through pivot).
- [ ] **SSH**: Native port forwarding (Local, Remote, Dynamic).
- [ ] **Socat**: Relaying connections from a compromised host to Kali.

### **Operational Tips**
*   **SSH Tunneling Types**:
    *   **Local (-L)**: Forward a remote port to your Kali: `ssh -L 8080:127.0.0.1:80 user@victim -N`
    *   **Remote (-R)**: Forward a Kali port to the victim (e.g., for rev shells): `ssh -R 4444:127.0.0.1:4444 user@victim -N`
    *   **Dynamic (-D)**: SOCKS Proxy for proxychains: `ssh -D 1080 user@victim -N`
*   **Ligolo-ng (Setup)**:
    ```bash
    sudo ip tuntap add user [USER] mode tun ligolo
    sudo ip link set ligolo up
    sudo ip route add 10.10.10.0/24 dev ligolo
    ```

---

## 🛠️ Compilation & Cross-OS Setup

### **Cross-Compiling (Kali -> Windows)**
Ensure `mingw-w64` is installed.

| Target | Command |
| :--- | :--- |
| **64-bit EXE** | `x86_64-w64-mingw32-gcc exploit.c -o exploit.exe -lntdll -lws2_32` |
| **32-bit EXE** | `i686-w64-mingw32-gcc exploit.c -o exploit.exe -lntdll -lws2_32` |
| **DLL** | `x86_64-w64-mingw32-gcc -shared -o output.dll input.c` |

### **Environment Hardening**
1.  **[/etc/hosts]**: Your most frequent update. Map all target IPs to Hostnames.
2.  **[NTP Sync]**: If possible, `sudo ntpdate [DC_IP]`. If blocked, use `faketime`.
3.  **[Python Web Server]**: `python3 -m http.server 80` (From your tools folder).
4.  **[Proxychains]**: Configure `/etc/proxychains4.conf` to match your Chisel/SSH port.

---

## 📂 Pre-Compiled Windows Tools (Download List)
Before the exam, ensure you have pre-compiled versions of these in a "transfer" folder:
- `nc.exe` (both 32 and 64 bit)
- `winPEASany.exe`
- `Rubeus.exe` (.NET 3.5 & 4.5)
- `SharpHound.exe`
- `GodPotato.exe` / `PrintSpoofer.exe`
- `Chisel.exe` (Windows binary)
- `SharpGPOAbuse.exe`
