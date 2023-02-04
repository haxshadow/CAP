# CAPCertified AppSec Practitioner (CAP)

A website administrator forgot to renew the TLS certificate on time and as a result, the application is displaying a TLS error message. However, on closer inspection, it appears that the error is due to the TLS certificate expiry. <br>

 Which of the following is correct?
 --------------------------------------------

- [x] The communication between the browser and the server is now no longer over TLS
- [ ] The communication between the browser and the server is still over TLS

<br>

## Which of the following is NOT a symmetric key encryption algorithm?

- [ ] RC4
- [ ] AES
- [ ] DES
- [x] RSA

<br>

An application's forgot password functionality is described below: <br>
A user enters their email address and receives a message: <br>
"If the email exists, we will email you a link to reset the password" <br>
The user receives an email saying: <br>
Please use the link below to create a new password: <br>
http://example.com/reset_password?userid=5298 <br>

Which of the following is true?
------------------------------------------

- [ ] The reset link uses an insecure channel
- [x] The application is vulnerable to username enumeration
- [ ] The application will allow the user to reset an arbitrary user's password
- [ ] Both A and C

<br>

## Which of the following SSL/TLS protocols are considered to be insecure?

- [ ] SSLv2 and SSLv3
- [ ] TLSv1.0 and TLSv1.1
- [x] Both A and B
- [ ] SSLv2, SSLv3, TLSv1.0, TLSv1.1, TLSv1.2 and TLSv1.3

<br>

## Based on the below HTTP request, which of the following statements is correct?
<p align="center">
<img src="/media/mickey/New Volume3/Github/Certified AppSec Practitioner (CAP)/png/5.png" ></p>

- [x] The change password feature does not validate the user
- [ ] The change password feature uses basic authorization
- [ ] The change password feature is vulnerable to Cross-Site Request Forgery attack
- [ ] All of the above

<br>

A website administrator forgot to renew the TLS certificate on time and as a result, the application is now displaying a TLS error message, as shown below. However, on closer inspection, it appears that the error is due to the TLS certificate expiry.
In the scenario described above,
<br> 

which of the following is correct?
------------------------------------------

- [ ] There is no urgency to renew the certificate as the communication is still over TLS
- [x] There is an urgency to renew the certificate as the users of the website may get conditioned to ignore TLS warnings and therefore ignore a legitimate warning which could be a real Man-in-the-Middle attack