![RDP connection to the Windows laboratory host](images/01-rdp-connection.png)

![Windows login using the low-privileged user](images/02-low-privilege-login.png)

![Security tools available on the target](images/03-tools-directory.png)

![Autoruns showing the vulnerable My Program entry](images/04-autorun-entry.png)

![AccessChk showing FILE_ALL_ACCESS for Everyone](images/05-accesschk-permissions.png)

![Metasploit reverse TCP handler configuration](images/06-metasploit-handler.png)

![Generating the Meterpreter executable with msfvenom](images/07-payload-generation.png)

![Python HTTP server transferring program.exe](images/08-http-server.png)

![Windows downloading program.exe from Kali](images/09-payload-download.png)

![Replacement executable inside the Autorun Program directory](images/10-payload-replacement.png)

![Login using the privileged TCM account](images/11-privileged-login.png)

![Windows security warning for the unsigned executable](images/12-security-warning.png)

![Meterpreter session opened as TCM-PC TCM](images/13-meterpreter-session.png)
