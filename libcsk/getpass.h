#ifndef _HAVE_CSK_GETPASS
#define _HAVE_CSK_GETPASS

/*
 * (unportable) functions to turn on/off terminal echo
 * using termios functions. might compile however on
 * most unices, tested on FreeBSD only.
 */


#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <termios.h>


void csk_echo_off();
void csk_echo_on();
char *csk_get_stdin();
char *csk_get_passphrase(char *prompt);

#endif // _HAVE_CSK_GETPASS
