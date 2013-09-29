/*******************************************************************************
* pam_http_sso.c    - Pluggable Authentication Module
* author            - AJ ( andrew.johnson@envato.com )
* description       - PAM Module to authenticate with an HTTP SSO Backend
* notes             - Check README.md for instructions on build / use
* credits           - Based on 2ndfactor.c pam module for 2 factor auth from
*                     http://ben.akrin.com/2FA
*******************************************************************************/
#include <pwd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <curl/curl.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>

#ifndef _OPENPAM
static char password_prompt[] = "Password:";
#endif

#ifndef PAM_EXTERN
#define PAM_EXTERN
#endif

PAM_EXTERN int
pam_sm_authenticate( pam_handle_t *pamh, int flags,i int argc, const char *argv[] ) 
{
#ifndef _OPENPAM
  struct pam_conf *conv;
  struct pam_message msg;
  const struct pam_message *msgp;
  struct pam_response *resp;
#endif
  struct passwd *pwd;
  const char *username;
  char *crypt_password, *password;
  int pam_err, retry;

  if (( pam_err = pam_get_user(pamh,&user, NULL)) != PAM_SUCCESS)
  {
    return (pam_err);
  }

#ifndef _OPENPAM
  pam_err = pam_get_item(pamh, PAM_CONV, (const void **)&conv);
  if (pam_err != PAM_SUCCESS)
  {
    return(PAM_SYSTEM_ERR);
  }
  msg.msg_style = PAM_PROMPT_ECHO_OFF;
  msg.msg       = password_prompt;
  msgp          = &msg;
#endif
  for( retry = 0; retry < 3 ; ++retry )
  {
#ifdef _OPENPAM
    pam_err     = pam_get_authtok(pamh,PAM_AUTHTOK,(const char **)&password,NULL);
#else
    resp        = NULL;
    pam_err     = (*conv->conv)(1, &msgp, &resp, conv->appdata_ptr);
    if ( resp != NULL )
    {
      if ( pam_err == PAM_SUCCESS )
      {
        password = resp->resp;
      }
      else
      {
        free(resp->resp);
      }
      free(resp);
    }
#endif
    if ( pam_err == PAM_SUCCESS ) 
    {
      break;
    }
  }
  if ( pam_err == PAM_SUCCESS )
  {
    return pam_err;
  }
  if ( pam_err != PAM_SUCCESS )
  {
    return PAM_AUTH_ERR;
  }

  int got_base_url    = 0;
  int got_api_key     = 0;
  char base_url[256];
  char api_key[256];
  for( i=0 ; i<argc ; i++ ) {
    if( strncmp(argv[i], "base_url=", 9)==0 ) {
      strncpy( base_url, argv[i]+9, 256 ) ;
      got_base_url = 1 ;
    } else if( strncmp(argv[i], "api_key=", 8)==0 ) {
      strncpy( api_key, argv[i]+8, 256 ) ;
      got_api_key = 1 ;
    }
  }
  if( got_base_url==0 || got_api_key==0 ) {
    return PAM_AUTH_ERR;
  }

  char post_params[ strlen("username=") + strlen("?password=") + strlen(password) + strlen("?auth_key=") + strlen(auth_key) ];
  strcpy( post_params, "?username=" );
  strcpy( post_params, username );
  strcpy( post_params, "?password=" );
  strcpy( post_params, password );
  strcpy( post_params, "?auth_key=" );
  strcpy( post_params, auth_key );


