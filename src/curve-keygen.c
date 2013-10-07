/*
    curve-genkey
    
    Certificate generator for ZeroMQ CURVE security. Produces two files:
    
    * id_curve25519        - public certificate
    * id_curve25519.secret - secret certificate
    
    Copyright (C) 2013 iMatix Corporation 
    Copyright (c) 2013 T.Linden

    Licensed under MIT/X11.
    
    Permission is hereby granted, free of charge, to any person obtaining 
    a copy of this software and associated documentation files (the 
    "Software"), to deal in the Software without restriction, including 
    without limitation the rights to use, copy, modify, merge, publish, 
    distribute, sublicense, and/or sell copies of the Software, and to 
    permit persons to whom the Software is furnished to do so, subject to
    the following conditions:

    The above copyright notice and this permission notice shall be 
    included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS 
    OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF 
    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY 
    CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, 
    TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE 
    SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include "curve-keygen.h"
#include "getpass.h"
#include "version.h"
  



void usage() {
  fprintf(stderr, "Usage: curve-genkey [options]\n");
  fprintf(stderr,  "Options:\n");
  fprintf(stderr,  "  -f <keyfile>    Filename for the key, default: 'id_curve25519'.\n");
  fprintf(stderr,  "  -n <name>       Your name\n");
  fprintf(stderr,  "  -m <mail>       Your email address\n");
  fprintf(stderr,  "  -o <org>        Your organization\n");
  fprintf(stderr,  "  -y              Read private key file and print public key, requires -s\n");
  fprintf(stderr,  "  -s <secretfile> File containing a secret key\n");
  fprintf(stderr,  "  -c              Don't encrypt the secret key (CZMQ default)\n");
  fprintf(stderr,  "  -h              print this help message\n");
  fprintf(stderr,  "  -v              print program version\n");
  exit(EXIT_FAILURE);
}

void version() {
  fprintf(stderr, "curve-keygen version %d.%d.%d\n", CSK_VERSION_MAJOR, CSK_VERSION_MINOR, CSK_VERSION_PATCH);
  exit(0);
}

int main (int argc, char **argv)  {
  int opt;
  char *filename = "id_curve25519";
  char *secretfile = "";
  char *name     = "";
  char *mail     = "";
  char *org      = "";
  int export     = 0;
  int unsecure   = 0;
  int filenamegiven = 0;

  while (1) {
    opt = getopt(argc, argv, "vf:n:m:o:hys:");

    if(opt == -1) {
      break;
    }

    switch (opt)  {
      case 'y':
	export = 1;
	break;
      case 'c':
	unsecure = 1;
	break;
      case 'f':
	filename = optarg;
	filenamegiven = 1;
	break;
      case 's':
	secretfile = optarg;
	break;	
      case 'n':
	name = optarg;
	break;
      case 'm':
	mail = optarg;
	break;
      case 'o':
	org = optarg;
	break;
      case 'h':
	usage();
      case 'v':
        version();
      default:
	usage();
    }
  }

  if(export) {
    // export the public key from a private one
    if(secretfile[0] != '\0' && filename[0] != '0' && filenamegiven) {
      if(! zfile_exists(secretfile)) {
	fprintf(stderr, "Private key file %s doesn't exist!\n", secretfile);
	return -1;
      }
      else {
	int ok = 0;
	size_t rawsize;
	unsigned char *privraw = csk_raw_load(secretfile, &rawsize);

	if(privraw != NULL) {
	  char *passphrase;

	  if(strncmp((char *)privraw, "# ", 2) == 0) {
	    // not encrypted
	    zcert_t *priv = zcert_load(secretfile);
	    zcert_save_public(priv, filename);
	    free(priv);
	  }
	  else {
	    passphrase = csk_get_passphrase("Enter passphrase");
	    if(passphrase == NULL || strlen(passphrase) <= 0) {
	      fprintf(stderr, "Sorry, you need to enter a passphrase in order to decrypt the secret key!\n");
	      ok = -1;
	    }
	    else {
	      zcert_t *privclear = csk_zcert_decrypt(privraw, passphrase, rawsize);
	      if (privclear != NULL) {
		zcert_save_public(privclear, filename);
		printf ("Public key from Curve25519 certificate %s exported to %s\n", secretfile, filename);
		free(privclear);
	      }
	      else {
		ok = -1;
	      }
	    }
	  }

	  free(privraw);
	  free(passphrase);
	}
	else {
	  ok = -1;
	}

	return ok;
      }
    }
    else {
      fprintf(stderr, "Parameter -s <secretkeyfile> (input) and -f <publickeyfile> (output) required for -y!\n");
      return -1;
    }
  }

  /* make sure we don't destroy something */
  if(zfile_exists(filename)) {
    printf("Key file %s already exists. Overwrite [Ny]? ", filename);
    char *c = csk_get_stdin();
    if(strncmp(c, "y", 80) != 0) {
      printf("abort\n");
      return 0;
    }
  }

  printf ("Creating new Curve25519 certificate %s\n", filename);

  zcert_t *cert = zcert_new ();

  if(name[0] == '\0') {
    if(s_get_meta (cert, "Enter your full name:", "name"))
      return -1;
  }
  else {
    zcert_set_meta(cert, "name", name);
  }

  if(mail[0] == '\0') {
    if(s_get_meta (cert, "Enter your email address:", "email"))
      return -1;
  }
  else {
    zcert_set_meta(cert, "email", mail);
  }

  if(org[0] == '\0'){
    if(s_get_meta (cert, "Enter your organization:", "org"))
      return -1;
  }
  else {
    zcert_set_meta(cert, "org", org);
  }
        
  char *timestr = zclock_timestr ();
  zcert_set_meta (cert, "created-by", "curve-genkey");
  zcert_set_meta (cert, "date-created", timestr);
  free (timestr);
  char *sec = "Unsecure";

  if (unsecure) {
    /* create an original CZMQ cert with unencrypted secret key */
    zcert_save (cert, filename);
  }
  else {
    char *pass1 = csk_get_passphrase("Enter a passphrase, leave empty for unprotected key");
    if(pass1 != NULL && strlen(pass1) > 0) {
      char *pass2 = csk_get_passphrase("                           Enter a passphrase again");
      if(strncmp(pass1, pass2, 80) == 0) {
	size_t clen;
	unsigned char *encrypted = csk_zcert_encrypt(cert, pass1, &clen);
	if(encrypted != NULL) {
	  char *sfile = ucmalloc(strlen(filename) + 8);
	  strncpy(sfile, filename, strlen(filename) + 7);
	  strcat(sfile, "_secret");
	  if((csk_raw_save (encrypted, sfile, clen)) == 0) {
	    zcert_save_public(cert, filename);
	    sec = "Encrypted";
	  }
	  else {
	    return -1;
	  }
	}
	else {
	  return -1;
	}
      }
      else {
	fprintf(stderr, "Passphrases were not identical, please repeat!\n");
	return -1;
      }
    }
    else {
      /* user just pressed enter, so make default CZMQ unencrypted cert */
      zcert_save (cert, filename);
    }
  }

  printf ("%s Curve25519 certificate created in %s and %s_secret\n", sec, filename, filename);
  
  zcert_destroy (&cert);

  return 0;
}
