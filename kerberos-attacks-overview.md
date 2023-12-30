# Kerberos Attacks Overview

> Now that we've covered the basic principles of Kerberos, we'll dive into the exploitation and dissection of specific weaknesses or opportunities offered by this protocol.
>
> For example, we will highlight attacks related to ticket requests, ticket forging, and delegation. We will also see that performing user reconnaissance using this protocol and even password spraying to find some accounts' passwords is possible.

## Ticket Request Atacks

> There are two ways to request a ticket: 
> 1. TGT request, or **AS-REQ**, to which the KDC responds with an **AS-REP** 
> 2. TGS request, or **TGS-REQ**, to which the KDC responds with a **TGS-REP** 


### AS-REQ Roasting

> When requesting a **TGT (AS-REQ)**, we saw that **by default**, a user must authenticate via an **authenticator** encrypted with their secret. However, if a user has **preauthentication disabled**, we could request authentication data for that user, and the KDC would return an AS-REP message. Since part of that message (the shared temporary session key) is encrypted using the user’s password, it is possible to perform an offline brute-force attack to try and retrieve the user's password.


### Kerberoasting

> Similarly, when a user has a TGT, they can request a Service Ticket for any existing service. The KDC response (TGS-REP) contains information encrypted with the secret of the **service account**. If the service account has a weak password, it is possible to perform the same offline attack to retrieve the password for that account.


## Kerberos Delegation Attacks

> [Kerberos Delegation](https://blog.netwrix.com/2021/11/30/what-is-kerberos-delegation-an-overview-of-kerberos-delegation) allows a service to impersonate a user to access another resource. Authentication is delegated, and the final resource responds to the service as if it had the first user's rights. There are different types of delegation, each with weaknesses that may allow an attacker to impersonate (sometimes arbitrary) users to leverage other services. We will cover the following attacks that abuse Kerberos: **unconstrained delegation, constrained delegation, and resource-based constrained delegation**.

## Ticket Forging Attacks

> Tickets are protected with secrets to prevent the forging of arbitrary tickets (the TGT is protected with the KDC key, and the TGS ticket is protected with the service account key). If an attacker gets hold of one of these keys, they can forge arbitrary tickets to access services with arbitrary rights. The following sections describe these two attacks: Silver Ticket for TGS forging and Golden Ticket for TGT forging. 

## Recon and Password Spraying

> Finally, it is possible to enumerate users and test passwords using the Kerberos protocol. If we ask for a TGT for a specific user, the server will respond differently depending on the user's existence in its database. In the same way, by encrypting the authenticator with different passwords, it is possible to check if the password is valid for the chosen user. 

