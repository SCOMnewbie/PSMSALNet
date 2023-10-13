FROM mcr.microsoft.com/powershell:lts-ubuntu-22.04

#Ubuntu require a -m to create the home
# RUN useradd -u 1001 nonroot -m

WORKDIR /usr/src/script

RUN pwsh -c Install-Module -Name PSMSALNet -Repository PSGallery -RequiredVersion '0.0.6' -Force -AcceptLicense -Verbose -Scope Allusers

COPY script.ps1 /usr/src/script

#USER 1001

CMD ["pwsh","-File","./script.ps1","-Verbose"]
