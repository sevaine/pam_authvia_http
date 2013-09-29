/*******************************************************************************
* pam_http_sso.c    - Pluggable Authentication Module
* author            - AJ ( andrew.johnson@envato.com )
* description       - PAM Module to authenticate with an HTTP SSO Backend
* notes             - Check README.md for instructions on build / use
* credits           - Based on 2ndfactor.c pam module for 2 factor auth from
*                     http://ben.akrin.com/2FA
*******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>

/* Expected hook */
PAM_EXTERN = int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
  return PAM_SUCCESS;
}

/* expected hook for our custom actions */
PAM_EXTERN int pam_sm_authenticate( pam_handle_t *pamh, int flags,int argc, const char **argv ) {
  int retval;
  int i;

  /* for converse() */
  char *input;
  struct pam_message msg[1],*pmsg[1];
  struct pam_response *resp;

  ./* parameters */
  int got_base_url = 0;
  int got_api_key = 0;
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

  /* username that was used in the previous authentication */
  const char *username;
  if( (retval = pam_get_user(pamh,&username,"login: "))!=PAM_SUCCESS ) {
    return retval ;
  }
        
  /* Build the url */
  char post_params[ strlen("username=") + strlen("?password=") + strlen(password) + strlen("?auth_key=") + strlen(auth_key) + strlen("?ip=") + strlen(ip) ];
  strcpy( post_params, base_url );
  strcpy( post_params, "?username=" );
  strcpy( post_params, username );
  strcpy( post_params, "?password=" );
  strcpy( post_params, password );
  strcpy( post_params, "?auth_key=" );
  strcpy( post_params, auth_key );
  strcpy( post_params, "?ip=" );
  strcpy( post_params, ip );

