# Kerberos Overview

> Kerberos is a protocol that allows users to authenticate on the network and access services once authenticated. Kerberos uses port 88 by default and has been the default authentication protocol for domain accounts since Windows 2000. When a user logs into their PC, Kerberos is used to authenticate them. It is used whenever a user wants to access a service on the network. Thanks to Kerberos, a user doesn't need to type their password in constantly, and the server won't need to know every user's password. This is an example of centralized authentication.  

> Kerberos is a stateless authentication protocol based on tickets. It effectively decouples a user's credentials from their requests to consumable resources, ensuring their password is not transmitted over the network. It is a Zero-knowledge proof protocol. The Kerberos Key Distribution Center (KDC) does not record previous transactions; instead, the Kerberos Ticket Granting Service (TGS) relies on a valid Ticket Granting Ticket (TGT). It assumes that if a user has a valid TGT, they must have proven their identity.  


## Basic Understanding
>
> At a very high level, when a user wants to interact with available resources on the network, the following occurs:
>
>> - They will first ask a centralized server for an "identity card".  
>>
>> - The user will then have to prove who they are, and in exchange, they will receive their "identity card," or **Ticket Granting Ticket (TGT)**.  
>>
>> - This **TGT** will be presented whenever they want to access a service.  
>>> - Thus, each time they want to access a service, they will present this ID, and if it is valid, the central server will provide a temporary ticket to present to the requested resource.
>>
>> - This temporary ticket contains all the user's information, such as their name, group membership, etc.
>>
>> - The resource will then receive this ticket and will be able to grant access to its services if the user has the right to do so.
>
### This process takes place in two stages.  
>
> - First, via a ticket request to identify a user's TGT.
>
> - Second, a request to access services using a **Ticket Granting Service (TGS)** ticket or **Service Tecket (ST)**. 

#### Note: Ticket Granting Service (TGS) is a component of the Key Distribution Center (KDC), which is responsible for issuing service tickets.  

#### Note: Throughout the module, when the term TGS ticket is used, it is as if we are referring to a Service Ticket (ST). 


## Kerberos Benefits  
>
> - With all the talk about Kerberos attacks and the dangers of the Golden Ticket attack, it is easy to think it is an inferior authenticaion protocol.  
>
> - Before Kerberos, authentication happened over SMB/NTLM, and the user's hash was stored within memory upon authentication. If a target machine was compromised and the NTLM hash was stolen, the attacker could access anything that the user account had access to via a **Pass-the-Hash** attack.
>
> - As previously mentioned, Kerberos tickets do not contain a user's password and will specify the machine to which the ticket grants access.
>
> - This is why the **Double Hop Problem** exists when accessing machines remotely via **WinRM**.  
>
> - When a non-Kerberos protocol is utilized to access a machine remotely, it is possible to use that connection to access other machines as that user without re-prompting for authentication because the **NTLM** password hash is tied to that session.  
>
> - With Kerberos authentication, credentials must be specific for every machine they want to access because there is no password.
>
> - Suppose a compromised machine with active sessions is authenticated via Kerberos. In that case, performing a **Pass-the-Ticket** attack is possible, which will be explained and demonstrated later in this module.  
>
> - However, unlike **Pass-the-Hash**, the attacker will be limited to the resources that the victim user authenticated against.  
>
> - Additionally, these tickets have a lifetime, meaning the attacker has a limited time window to access the resource(s) and attempt to establish persistence.

## Next Steps
>
> - The following section explains the Kerberos authentication process in detail, including how the tickets are protected and what they contain.
>
> - An understanding of this process is essential before diving into Kerberos-related attacks.  
>
> - There are many ways that Kerberos can be abused within an Active Directory (AD) environment for lateral movement, privilege escalation, and persistence.  
>
> - We will encounter many of these techniques during our penetration tests and red team assessments. 
>
> - As security practitioners, we must deeply understand how Kerberos works and how it can be abused to our benefit.  
>
> - It is also essential to explain how Kerberos attacks work and how customers can protect against them and set up proper monitoring to detect Kerberos abuse.

