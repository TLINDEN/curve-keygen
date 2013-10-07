#include "getpass.h"
  

/*
 * (unportable) functions to turn on/off terminal echo
 * using termios functions. might compile however on
 * most unices, tested on FreeBSD only.
 */

static struct termios stored_settings;

void csk_echo_off() {
  struct termios new_settings;
  tcgetattr(0,&stored_settings);
  new_settings = stored_settings;
  new_settings.c_lflag &= (~ECHO);
  tcsetattr(0,TCSANOW,&new_settings);
}

void csk_echo_on() {
  tcsetattr(0,TCSANOW,&stored_settings);
}


/*
 * read a line from stdin, return without
 * trailing \n or NULL if something went
 * wrong
 */
char *csk_get_stdin() {
  char *line = NULL;
  size_t linecap = 0;
  ssize_t linelen;
  linelen = getline(&line, &linecap, stdin);
  
  if (linelen < 0) {
    return NULL;
  }
  else {
    line[linelen - 1] = '\0'; // remove newline at end
    return line;
  }
}

/*
 * turn off terminal echo, ask for a passphrase
 * and turn it on again
 */
char * csk_get_passphrase(char *prompt) {
  printf("%s: ", prompt);
  csk_echo_off();
  char *line = csk_get_stdin();
  csk_echo_on();
  printf("\n");
  return line;
}

