# PSMSALNet Module

This project wraps [MSAL.NET](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet) functionality into PowerShell-friendly cmdlets. 


# Introduction

[!IMPORTANT]  
Crucial information necessary for users to succeed.

This is a Powershel 7.2 module minimum


I've started to think about this module the day Microsoft decided to layoff a lot of Identity people specially (MSAL.PS dude). Since, this module has not received any udpates (even before in fact) but in parallel, the MSAL.net team did a lot of new release since.
This module is not a full implementation of MSAL.NET and won't be, but after several years of using the wonderfull MSAL.PS few limitations started to show up. I'e decided to expose only the flows that I'm interrested in and skip flows that I consider deprecated like ROPC, Windows Integrated flow and maybe few others. In addition, over the years, I've created several identity related scripts to be consumed in Azure or not.
Since, MSAL.net expose wonderfull features like managed identities (even for ARC) and WAM (Web account management) which is strong auth compatible (compared to Windows Integrated flow).

## What you can do with this module?

- You can create access/Id/Refresh tokens in severals using several MSAL OAuth flows:
    - list all flows
- You can generate a X509 certification from mulitple format (cer, pfx,...). This is useful is you plan to rely on certificate on Linux (containers). With one cmdlet, you generate a 509 obect you can pass in the Get-Entratoken cmdlet.
- This module should be compatible with Azure public but also Azure China and other govs environemnt
- This module will help you to generate tokens for "basic" audiences like storage account, ARM, KeyVault and so on ... But also custom APIs through the custom parameter under audiences.


## What you can't do with this module?

Like today with MSAL.PS, you can't validate tokens and it's normal, this is not the purpose of the library. But if you have this need, you can use this module that I've done called XXX and use it with from your backend Powershell APIs like this example(scmnewbie links) 

## How this module is working?

We're using a lot of both official and custom nuget packages. 
For the official ones, we're using the:
- Microsoft.Identity.Client -> Core
- Abstraction -> Core depandancy
- Broker > required for WAM
- interrpopt > required for WAM
- extension > to serialize tokens on the local disks

For the customs:
- Device code helper you can find here (link) -> Use to expose and catch the device code exposed my Microsoft. The code is a simple copy/paste from Microsoft documentation
- WAMHelper you can find here -> Because WAM does not work straight from Powershell (never succeed to make it work after 20 hours), I've decided to create a new library (with synchronous calls) and expose it as a Powershell cmdlet. Then I use it internally as a private function.

## How to contribute

This module is based on Sampler module. To contribute, clone the repo and run a .\build ...
