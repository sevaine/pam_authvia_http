# Pam HTTP Single Signon Module

A simple module that passes authentication requests back to an HTTP/S Single Signon service

## What this is:

* Unfinished :P
* A PAM module to enable authentication requests to be made against an HTTP service using FORM POST.

## What this is not:

* A PAM HTTP Digest authentication module. I'd like to add more functionality as time goes on, but for the moment I'm more concerned with being confident of security and reliability.

## Installation : 

I work in Ubuntu system most of the time, so this has only really been worked on thee.  The following steps will get you started.  Any and all feedback would be welcome; it's been a VERY long time since I've looked at anything C.

Install prerequisite packages:

```
sudo apt-get -y update
sudo apt-get -q -y install build-essential libpam0g-dev libcurl4-openssl-dev
```

Build the code:

```
gcc -fPIC -lcurl -c src/pam_authvia_http_formpost.c
ld -lcurl -x -shared -o /lib/security/pam_authvia_http_formpost.so
```

Linking on x86_64 is marginally different, but not too different:

```
ld -lcurl -x -shared -o /lib/x86_64-linux-gnu/security/pam_authvia_http_formpost.so
```


## Configuration:

Copy the pam.d/ftpserver.conf sample file to /etc/pam.d and update to refelct your backend HTTP Auth service.   The configuration line for pam_authvia_http_formpost.so should look something like:

```
auth        required        pam_authvia_http_formpost.so base_url='https://sso.example.linux.local/cgi-bin/authme.cgi api_key=THISISMYAUTHKEY
```


# Other notes.

This Module requires the base url an api_key be specified.   The api key is there to address a specific need I have and is not related to the users this module will authenticate other than as a preshared secret.

There is a 'mongoose' directory in this repo and a cgi/auth.cgi script there that can be run as a target for this pam module when testing it.  Mongoose is available at : https://code.google.com/p/mongoose/
