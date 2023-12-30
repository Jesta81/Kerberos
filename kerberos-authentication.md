# Kerberos Authentication Process

> In a Kerberos context, there are three entities when a user wants to access a service:
>> - #### The User
>> - #### The Service
>> - #### The Authentication Server, also known as the Key Distribution Center, or KDC.
>
> The KDC is the entity that knows all accounts' credentials.

![Kerberos Authentication](/Kerberos/images/kerberos-auth.png) 


## Why Kerberos?

> The first question we can ask ourselves is, what is this protocol used for?
>
> - On the one hand, it is used to **centralize authentication** to avoid all services having to know every user's credentials.
>
> - This is extremely practical in a context where users are regularly updated, whether because of a password change, the addition of a new user, or the deactivation or deletion of a user.  
>
> - If all services had to know the status of all users, this would create immense complexity.
>
> - Instead, only one entity, the KDC, must have an up-to-date list of existing users.
>
> - On the other hand, this protocol allows users to authenticate against services **without sending a password over the network**.
>
> - This is an excellent security measure to protect against **man-in-the middle (MiTM)** (also known as **on-path**) attacks.


## High-level overview

### Tickets

>
> - To meet both needs, Kerberos uses secret keys and a ticketing mechansim.
>
> - The secret keys are, in practice, in an Active Directory environment, the passwords of the different accounts (or at least a hash of these passwords).
>
> - From a high-level perspective, here's how a user can access a service.
>>
>> 1. To start, the user will request the first ticket from the key server (the KDC), proving they are who they claim to be.
>>>
>>> - This is when the client **authenticates** to the KDC.
>>> - This ticket, called a **TGT (Ticket Granting Ticket)**, is the user's identity card.
>>> - It contains all the information about the user, such as name, date of account creation, security information about the user, the groups to which the user belongs, etc.
>>> - This identity card, the TGT, is limited to a few hours by default. 
>>> - This ticket is presented for all other requests to the KDC. 
>>
>> 2. Once this TGT has been obtained, the user will present it to the KDC each time they need to access a service.
>>>
>>> - The KDC will then verify that the submitted TGT is valid and that the user did not forge it, and if so, it will return a **Ticket Granting Service (TGS) ticket or Service Ticket (ST)** to the user.
>>> - A copy of the user's information in the TGT is included in the TGS ticket.
>>
>> 3. Now that the user has a TGS ticket for a particular service, they will present this TGS ticket to the service to use it.
>>>
>>> - The serivice will then check the validity of this ticket, and if all is well, it will read the content of the user's information to determine if the user is entitled to suer the requested service.
>>> - It is, therefore, **the service that checks the user's access rights**. 


![Kerberos Tickets](/Kerberos/images/kerberos-tickets.png) 
![Kerberos Tickets](/Kerberos/images/kerberos-tickets-2.png) 


### Ticket Protection


> - Thanks to the above diagram, we understand the different exchanges well.
>
> - However, as explained above, the TGT and TGS ticket contain all the infromation related to the user. The service uses this information to verify the user's access rights.
>
> - This information provided by the KDC must be protected. The user must not be able to forge it. This is where encryption keys come into play.
>
> - Each account has a password or secret, which acts as an encryption and decryption key. The KDC knows the keys of all users. To protect the tickets, here is how these keys are used.
>>
>> 1. The **TGT** sent by the KDC to the user is encrypted using **the secret key of the KDC**, which only the KDC knows.
>>>
>>> - Thus, the user cannot read or modify the information about themself
>>> - The KDC itself protects it. 
>>
>>
>> 2. The **TGS ticket** sent by the KDC to the user is encrypted using **the service's secret key**. 
>>>
>>> - In the same way, as the user does not know the service key, they cannot modify the information in the **TGS ticket**. 
>>> - On the other hand, when they send this **TGS ticket** to the service, the latter can decrypt the ticket's content and read the user's information.

![Kerberos Ticket Protection](/Kerberos/images/ticket-protection.png) 
![Kerberos Ticket Protection](/Kerberos/images/ticket-protection-2.png) 


### Technical Details

> We will now go into detail to understand how the authentication process fits all together and the protection mechanisms it utilizes against numerous attacks. We have seen that access to a service is carried out it three phases. These phases are named as follows:
>
> 1. **TGT request: Authentication Service (AS)** 
> 2. **TGS request: Ticket-Granting Service (TGS)** 
> 3. **Service request: Application Request (AP)** 
>
> The client sends a request in each phase, and the server responds. We will describe how these three exchanges work, who the tickets are protected, and with what key.
a


## Authentication Service (AS) 

### Request (AS-REQ) 

> 1. First, the user makes a TGT (or identity card) request. This is called **AS-REQ**. 
>> - This request is called **AS-REQ**. But to receive the TGT, they must be albe to prove their identity.
>> - This request is made to the KDC **(which is the Domain Controller in an Active Directory environment)**.
>> - The KDC holds all user keys.
>
> 2. To prove their identity, the user will send an **authenticator**.
>> - It's the **current timestamp** that the user will encrypt their key with. 
>> - The username is also sent in cleartext so the KDC can know whom it is dealing with.

![Authentication Request](/Kerberos/images/auth-request.png) 

> 2. Upon receiving this request, the KDC will retrieve the username, look for the associated key in its directory, and attempt to decrypt the authenticator.
>> - If it succeeds, it means that the user has used the same key as the one registered in its database, so they are authenticated.
>> - Otherwise, authentication fails.

> 3. This step, called **pre-authentication**, is not mandatory, but all accounts must do it **by default**.
>> - However, it should be noted that an administrator can disable pre-authentication. 
>> - In this case, the client no longer needs to send an authenticator. 
>> - The KDC will send the TGT no matter what happens.


### Response (AS-REP)

> 1. The KDC, therefore, received the client's request for a TGT.
>> - If the KDC successfully decrypts the authenticator (or if pre-authentication is disabled for the client), it sends a response called **AS-REP** to the user. 

> 2. To protect the rest of the exchanges, the KDC will generate a **temporary session key** before replying to the user. 
>> - The client will use this key for further exchanges.
>> - The KDC avoids encrypting all information with the user's key. 
>> - Kerberos is a stateless protocol, so the KDC will not store this session key anywhere.

> 3. There are two elements taht we will find in the **AS-REP response**: 
>
>> 1. First, we are waiting for the **TGT** that the user requested. It contains all the user's information and is protected with the KDC's key, so the user can't tamper with it. It also contains a **copy** of the **generated session key**.
>>
>> 2. Second is the **session key**, but this time **protected** with the **user's key**.

![Authentication Response](/Kerberos/images/auth-response.png) 

> Therefore, this session key is duplicated in the response -- one version is protected with the KDC's key, and another is protected with the user's key.


## Ticket-Granting Service (TGS) 

> - The Ticket-Granting Service is a component of the Key Distribution Center (KDC) that is responsible for issuing service tickets. 
>
> - Typically hosted on a domain controller in the AD domain.
>
> - When a user or computer requests a service ticket, the request is sent to the TGS component of the KDC, which verifies the user's or computer's identity and checks their authorization to access the requested resource before issuing a service ticket that can be used to gain access to the resource. 


### Request (TGS-REQ)

> - The client now has a response from the server to its TGT request. 
>
> - This response contains the TGT, protected by the KDC's key, and a session key, protected by the client's/user's key. 
>
> - It can then decrypt this information to extract this temporary session key.
>
> - The next step for the suer is to request a Service Ticket **ST** or **TGS ticket** with a **TGS-REQ** message. To do this, they will transmit three things to the KDC:
>>
>> 1. The name of the service they wish to access (SERVICE/HOST, which is the **Service Principal Name (SPN)** representation). 
>> 2. The TGT they previously received, containing their information and a copy of the session key. 
>> 3. An authenticator, which will be encrypted using the session key at this time.

![TGS Request](/Kerberos/images/TGS-request.png) 

### TGS Response (TGS-REP)

> - The KDC receives this TGS request, but Kerberos is a stateless protocol. 
>
> - Thus, the KDC has no idea what information has been exchanged before. 
>
> - It must still verify that the TGS request is valid. 
> - It must verify that the authenticator has been encrypted with the correct session key to do this. And how does the KDC know if the session key used is correct? Remember that there was a copy of the session key in the TGT. 
>
> - The KDC will decrypt the TGT (checking its authenticity along the way) and extract the session key. 
>
> - With this session key, it will be able to verify the authenticator's validity. 
>
> - If all this is done correctly, the KDC only has to read the requested service and respond to the user with a TGS-REP message. 
>
> - We saw earlier that a session key had been generated for the exchanges between the user and the KDC. Well, it's the same thing here. 
>
> - A new session key is generated for future exchanges between the user and the service. And as before, this session key will be present in two places in the response sent by the KDC to the user. Here are all the elements sent by the KDC:
>
> A service ticket or TGS ticket containing three elements:
>
> 1. The name of the requested service (its SPN)
> 2. A copy of the user information that was present in the TGT. The service will read this information to determine whether or not the user has the right to use it.
> 3. A coopy of the session key.  
>
> - All this information is encrypted with the user/KDC session key. Within this encrypted response, the user's information and the copy of the user/service session key are also encrypted with the service key. A diagram will help make this clearer.

![TGS Response](/Kerberos/images/TGS-response.png) 


## Application Request (AP) 

### Request (AP-REQ) 

> - The user can now decrypt this response to extract the user/service session key and the TGS ticket, but the TGS ticket is protected with the service key. The user can't modify this TGS ticket, so they can't modify their rights, just like with the TGT.
>
> - The user will only transmit this TGS ticket to the service, and just like with the TGS request,  an authenticator is added to it. What will the user encrypt this authenticator with? You guessed it, with the user/service session key just extracted. The process is very similar to the previous TGS request.

![AP Request](/Kerberos/images/AP-request.png) 

### Response (AP-REP)

> - The service finally receives the TGS ticket and an authenticator encrypted with the user/service session key generated by the KDC. This TGS ticket is protected with the service's key so that it can decrypt it. Remember that a copy of the user/service session key is embedded within the TGS ticket, so it can extract it and check the validity of the authenticator with this session key.
>
> - If everything goes correctly, the service can finally read the information about the user, including the groups to which they belong, and according to its access rules, grant or deny them access to the service. If authentication is successful, the service responds to the client with an **AS-REP** message by encrypting the timestamp with the extracted session key. The client can then verify that this message is coming from the service and can start issuing service requests.


## Conclusion
>
> - As you can see, the whole process relies on shared keys and is a three-entity job. It protects users and services against ticket stealing and replaying, as the attackers would not know the keys to issue valid authenticators. However, there are still weaknesses and misconfigurations that we can exploit to attack Kerberos, which we'll cover in the following sections.
>
> - If you want to explore further explanations of the Kerberos protocol, its operation, and its components, you can review [ATTL4S]'(https://twitter.com/DaniLJ94) posts on his [blog](https://attl4s.github.io/) and YouTube channel video: [English You Do (Not) Understand Kerberos](https://www.youtube.com/watch?v=4LDpb1R3Ghg&list=PLwb6et4T42wyb8dx-LQAA0PzLjw6ZlrXh). 

