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

/* From pam_unix/support.c - allows us to perform I/O */
int converse( pam_handle_t *pamh, int nargs, struct pam_message **message, struct pam_response **response ) {
  int retval;
  struct pam_conv *conv;

  retval = pam_get_item( pamh, PAM_CONV, (const void **) &conv );
  if( retval==PAM_SUCCESS ) {
    retval = conv->conv( nargs, (const struct pam_message **) message, response, conv->appdata_ptr );
  }

  return retval;
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
  int got_code_size = 0;
  unsigned int code_size = 0;
  char base_url[256];
  for( i=0 ; i<argc ; i++ ) {
    if( strncmp(argv[i], "base_url=", 9)==0 ) {
      strncpy( base_url, argv[i]+9, 256 ) ;
      got_base_url = 1 ;
    } else if( strncmp(argv[i], "code_size=", 10)==0 ) {
      char temp[256];
      strncpy( temp, argv[i]+10, 256 ) ;
      code_size = atoi( temp ) ;
      got_code_size = 1 ;
    }
  }
  if( got_base_url==0 || got_code_size==0 ) {
    return PAM_AUTH_ERR;
  }

  /* username that was used in the previous authentication */
  const char *username;
  if( (retval = pam_get_user(pamh,&username,"login: "))!=PAM_SUCCESS ) {
    return retval ;
  }
        
  /* Build the url */
  char url_with_params[ strlen(base_url) + strlen("?username=") + strlen("?password=") + strlen(password) + strlen("?auth_key=") + strlen(auth_key) + strlen("?ip=") + strlen(ip) ];
  strcpy( url_with_params, base_url );
  strcpy( url_with_params, "?username=" );
  strcpy( url_with_params, username );
  strcpy( url_with_params, "?password=" );
  strcpy( url_with_params, password );
  strcpy( url_with_params, "?auth_key=" );
  strcpy( url_with_params, auth_key );
  strcpy( url_with_params, "?ip=" );
  strcpy( url_with_params, ip );

