# Network Security, Authentication, and Authorization Test

---

## A. Fill in the Blanks (20 Questions)

1. Generation of message authentication is implemented by __ or hash function.  
**Answer:** Message Authentication Code (MAC)

2. Digital signature is implemented by __.  
**Answer:** Asymmetric encryption using private key

3. __ encryption uses the same key for encryption and decryption.  
**Answer:** Symmetric

4. __ encryption uses a key pair consisting of a public key and a private key.  
**Answer:** Asymmetric

5. __ is used to ensure data integrity by detecting any modification of the message.  
**Answer:** Hash function

6. TLS protocol ensures __ between client and server.  
**Answer:** Confidentiality and integrity

7. OAuth 2.0 uses __ for authorization delegation.  
**Answer:** Access tokens

8. __ attack involves intercepting communication between two parties.  
**Answer:** Man-in-the-middle (MITM)

9. A __ verifies the identity of a user, device, or application.  
**Answer:** Authentication system

10. Role-Based Access Control (RBAC) assigns permissions based on __.  
**Answer:** User roles

11. __ is the process of ensuring that users can only perform actions they are authorized to do.  
**Answer:** Authorization

12. A __ provides non-repudiation of digital messages.  
**Answer:** Digital signature

13. __ encryption is generally faster than asymmetric encryption.  
**Answer:** Symmetric

14. __ is used to derive keys and provide randomness in cryptographic systems.  
**Answer:** Key derivation function (KDF)

15. __ ensures that sensitive data is transmitted securely over networks.  
**Answer:** Secure communication protocols (e.g., TLS/SSL)

16. Passwords stored in a database should always be __ before storage.  
**Answer:** Hashed with salt

17. __ is an attack that tries all possible keys to decrypt a message.  
**Answer:** Brute-force attack

18. A __ provides access control based on attributes rather than roles.  
**Answer:** Attribute-Based Access Control (ABAC)

19. __ protocol is commonly used for secure remote logins.  
**Answer:** SSH

20. Certificate Authority (CA) issues __ to verify identity of entities.  
**Answer:** Digital certificates

---

## B. Yes or No (20 Questions)

1. Symmetric encryption can be used for authentication. **Yes**  
2. Digital signatures verify the identity of a message creator. **Yes**  
3. Public key encryption is faster than symmetric encryption. **No**  
4. Hash functions provide confidentiality. **No**  
5. TLS uses both symmetric and asymmetric encryption. **Yes**  
6. OAuth 2.0 is an authentication protocol. **No**  
7. Brute-force attack exploits vulnerabilities in hash functions. **No**  
8. Certificate Authorities (CA) are trusted third parties. **Yes**  
9. Multi-factor authentication improves security. **Yes**  
10. Role-Based Access Control allows dynamic policies. **No**  
11. Man-in-the-middle attacks intercept communication between two parties. **Yes**  
12. MAC ensures integrity of a message. **Yes**  
13. RSA encryption requires a shared secret key. **No**  
14. Salt prevents precomputed hash attacks. **Yes**  
15. Single sign-on (SSO) allows multiple logins for each service. **No**  
16. Replay attacks involve resending valid data to gain unauthorized access. **Yes**  
17. Password hashing is reversible. **No**  
18. SSL is obsolete but still used in legacy systems. **Yes**  
19. X.509 certificates are used in PKI. **Yes**  
20. Token-based authentication does not require a server to store session state. **Yes**

---

## C. Multiple Choice (20 Questions)

1. Message Authentication Code (MAC) has:  
   - a) Various length unrelated to message length  
   - b) Fixed length  
   - c) Fixed value, no relation to message content  
**Answer:** b) Fixed length

2. Which protocol ensures secure communication over the Internet?  
   - a) HTTP  
   - b) TLS  
   - c) FTP  
**Answer:** b) TLS

3. In asymmetric encryption, data encrypted with the private key can be decrypted by:  
   - a) Same private key  
   - b) Corresponding public key  
   - c) Any other key  
**Answer:** b) Corresponding public key

4. The primary purpose of hashing is:  
   - a) Confidentiality  
   - b) Integrity  
   - c) Authentication  
**Answer:** b) Integrity

5. Which method prevents password reuse attacks?  
   - a) Salting  
   - b) Hashing  
   - c) Key exchange  
**Answer:** a) Salting

6. OAuth 2.0 mainly deals with:  
   - a) Authentication  
   - b) Authorization  
   - c) Encryption  
**Answer:** b) Authorization

7. Which attack tries all possible keys to decrypt data?  
   - a) Phishing  
   - b) Brute-force  
   - c) MITM  
**Answer:** b) Brute-force

8. Which is a property of digital signatures?  
   - a) Confidentiality  
   - b) Non-repudiation  
   - c) Integrity only  
**Answer:** b) Non-repudiation

9. SSH is used for:  
   - a) Secure file transfer  
   - b) Secure remote login  
   - c) Both  
**Answer:** c) Both

10. ABAC stands for:  
    - a) Attribute-Based Access Control  
    - b) Access-Based Authentication Control  
    - c) Attribute-Based Authorization Check  
**Answer:** a) Attribute-Based Access Control

11. Which TLS component provides server identity?  
    - a) MAC  
    - b) Digital Certificate  
    - c) Session Key  
**Answer:** b) Digital Certificate

12. Which hashing algorithm is considered secure today?  
    - a) MD5  
    - b) SHA-256  
    - c) SHA-1  
**Answer:** b) SHA-256

13. Token-based authentication typically uses:  
    - a) Passwords only  
    - b) JWT or opaque tokens  
    - c) Public/private keys only  
**Answer:** b) JWT or opaque tokens

14. Replay attacks can be prevented by:  
    - a) Nonces or timestamps  
    - b) Longer passwords  
    - c) SSL only  
**Answer:** a) Nonces or timestamps

15. Which encryption algorithm is symmetric?  
    - a) AES  
    - b) RSA  
    - c) ECC  
**Answer:** a) AES

16. Which key is used to sign a message digitally?  
    - a) Public key  
    - b) Private key  
    - c) Session key  
**Answer:** b) Private key

17. Access control based on user roles is called:  
    - a) ABAC  
    - b) RBAC  
    - c) MAC (Mandatory Access Control)  
**Answer:** b) RBAC

18. Which of the following is an authentication factor?  
    - a) Password  
    - b) Fingerprint  
    - c) Security token  
    - d) All of the above  
**Answer:** d) All of the above

19. A man-in-the-middle attack can be prevented by:  
    - a) Using TLS/SSL  
    - b) Strong passwords  
    - c) Salting  
**Answer:** a) Using TLS/SSL

20. Which of the following is NOT a property of cryptographic hash?  
    - a) Pre-image resistance  
    - b) Collision resistance  
    - c) Reversibility  
**Answer:** c) Reversibility

---

## D. Application / Diagram-Based Questions (20 Questions)

1. A network uses a 128-bit key and MAC length is 64-bit. How many steps are required to find the key using brute-force attack?  
**Answer:** 2^128 steps

2. Hash value of `0x3EF2CA88` using a simplified bit shift algorithm produces:  
**Answer:** `0xB76C`

3. Draw a diagram showing SSL/TLS handshake between client and server, labeling:  
   - ClientHello  
   - ServerHello  
   - Certificate exchange  
   - Key exchange  
   - Finished messages  
**Answer:** Standard TLS handshake flow diagram

4. Consider a diagram where a user accesses a web service via OAuth 2.0:  
   - Identify the role of Authorization Server  
   - Identify the role of Resource Server  
**Answer:** Authorization Server issues access tokens; Resource Server validates tokens and grants access

5. A scenario: Admin sets RBAC roles for users:  
   - Role: Editor → Read/Write Articles  
   - Role: Viewer → Read only  
   Question: Which access control type is being implemented?  
**Answer:** Role-Based Access Control (RBAC)

6. Draw a diagram illustrating Man-in-the-Middle attack in HTTPS connection. Explain how certificate validation prevents it.  
**Answer:** Diagram shows attacker intercepting messages; certificate validation ensures MITM cannot fake server identity.

7. In a system with salted password hashing, explain how storing salts in the database helps prevent rainbow table attacks.  
**Answer:** Each user’s salt makes precomputed hashes ineffective, forcing attackers to brute-force each password individually.

8. Show a sequence diagram of JWT authentication flow. Identify where access tokens are issued and validated.  
**Answer:** Client sends credentials → Auth server issues JWT → Client uses JWT for resource access → Server validates JWT.

9. Diagram a hybrid encryption system combining RSA and AES. Label which keys are used for data and session key.  
**Answer:** RSA encrypts AES session key; AES encrypts bulk data.

10. An attacker intercepts encrypted data but does not have the private key. Which property protects confidentiality?  
**Answer:** Asymmetric encryption ensures confidentiality; attacker cannot decrypt without private key.

11. Explain via diagram how multi-factor authentication improves security compared to password-only login.  
**Answer:** Password + OTP / Biometric; attacker needs both factors to succeed.

12. Given a network flow with VPN, TLS, and MAC, identify which layer provides integrity, confidentiality, and authentication.  
**Answer:** VPN/TLS → Confidentiality; MAC → Integrity; Certificates → Authentication.

13. Draw a diagram showing PKI certificate chain verification from leaf to root.  
**Answer:** End-entity certificate → Intermediate CA → Root CA → Trusted anchor

14. Show a diagram of OAuth 2.0 Authorization Code flow. Label the steps including client, authorization server, and resource server.  
**Answer:** Client requests code → Auth server issues code → Client exchanges code for access token → Resource server validates token

15. Create a flow diagram of SSO login across multiple services using SAML.  
**Answer:** Identity Provider issues SAML assertion → Service Providers validate assertion → User logged in without multiple credentials

16. Show an example of hash collision scenario in a diagram. Explain why modern hash functions avoid this.  
**Answer:** Two messages producing same hash; modern functions (SHA-256) are collision-resistant

17. Illustrate session hijacking attack and how HTTPS and secure cookies mitigate it.  
**Answer:** Diagram attacker stealing session cookie; mitigation via secure flags and TLS encryption

18. Show diagram of ABAC access control with user attributes, resource attributes, and policy rules.  
**Answer:** Attributes evaluated → Policy enforced → Access granted or denied

19. Diagram a brute-force attack against a 4-digit PIN. Explain exponential steps required.  
**Answer:** 10^4 = 10,000 attempts maximum; shows guessing sequence

20. Draw a simplified diagram of symmetric vs asymmetric encryption in secure email.  
**Answer:** Symmetric for message → Asymmetric for session key → Recipient decrypts session key → Decrypts message

---

**End of Test File**
