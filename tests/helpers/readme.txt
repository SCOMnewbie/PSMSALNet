Pfx password = "exportpassword"
Passphrase = "test"

-------------------------------------------------------------------------------------------------

https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/about/about_certificate_provider?view=powershell-7.2
Types exposed by this provider
The Certificate drive exposes the following types.

Store locations (Microsoft.PowerShell.Commands.X509StoreLocation), which are high-level containers that group the certificates for the current user and for all users. Each system has a CurrentUser and LocalMachine (all users) store location.
Certificates stores (System.Security.Cryptography.X509Certificates.X509Store), which are physical stores in which certificates are saved and managed.
X.509 System.Security.Cryptography.X509Certificates.X509Certificate2 certificates, each of which represent an X.509 certificate on the computer. Certificates are identified by their thumbprints.



Decrypt

pfx
pfx + password
	$PrivCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($(Get-Item -Path .\scomnewbie.pfx),"exportpassword")
	Unprotect-CmsMessage -Path .\secret.enc -To $PrivCert
pem (-nodes remove the privatekey need)
	openssl pkcs12 -in ./scomnewbie.pfx -out ./scomnewbie.pem -nodes # WARNING No more password anymore
	$PrivCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPemFile($(Get-Item -Path ./scomnewbie.pem))
pem + decrypted private key
	openssl pkcs12 -in ./scomnewbie.pfx -out ./scomnewbie2.pem  # Privatekey will be encrypted + no -nodes means passphrase required
	openssl rsa -in ./scomnewbie2.pem -out privatekey_rsa.key  #Enter passphrase
	$PrivCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPemFile($(Get-Item -Path ./scomnewbie.pem),$(Get-Item -Path ./privatekey_rsa.key))
