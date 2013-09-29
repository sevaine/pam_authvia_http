#!/usr/bin/python
import os, sys
import cgi
import cgitb
cgitb.enable()

authdb = {'testkey':{'testuser':'testpass'}}

def print_ok(mesg):
  print "Status: 200 OK", "\r\n"
  print "Content-type: text/plain\r\n\r\n"
  print mesg, "\n"

def print_forbidden(mesg):
  print "Status: 403 Forbidden", "\r\n"
  print "Content-type: text/plain\r\n"
  print mesg, "\r\n"

def print_unauthorized(mesg):
  print "Status: 401 Unauthorized", "\r\n"
  print "Content-type: text/plain\r\n"
  print mesg, "\r\n"

postdata = cgi.FormContent()
if os.environ['REQUEST_METHOD'] == 'POST':
  if not postdata.has_key('username'):
    print "Username not specified."
  if not postdata.has_key('password'):
    print "Password not specified"
  if not postdata.has_key('api_key'):
    print "Password not specified"

  api_key   = postdata['api_key'][0]
  user      = postdata['username'][0]
  passwd    = postdata['password'][0]

  if authdb.has_key(api_key):
    if authdb[api_key].has_key(user):
      if authdb[api_key][user] == passwd:
        print_ok("Authorized")
      else:
        print_unauthorized("Not Authorized")

    else:
      print_unauthorized("Invalid Username.")

  else:
    print_unauthorized("Incorrect API Key")

else:
  sys.stdout.write("Status: 501 Not Implemented\r\n")

sys.stdout.flush()
sys.exit(1)
