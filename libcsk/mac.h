#ifndef _HAVE_CSK_MAC
#define _HAVE_CSK_MAC

#include <strings.h>
#include <stdlib.h>
#include <errno.h>
#include <sodium.h>
#include "pad.h"
#include "mem.h"


// how many times do we hash the passphrase
#define HCYCLES 128000

// encrypt some arbitrary cleartext using
// a curve25519 secret key  and a given nonce.
//
// expects a pointer to the target binary
// stream containing the encrypted data,
// the cleartext string, its size, the nonce
// (24 bytes) and the secret key (32 bytes).
//
// allocates memory for the returned cipher
// and it is up to the user to free it after use.
//
// returns the size of the returned cipherstream.
// in case of an error, the cipher will be set
// to NULL.
size_t csk_sodium_mac(unsigned char **cipher,
                      unsigned char *cleartext,
                      size_t clearsize,
                      unsigned char *nonce,
                      unsigned char *key);

// does the opposite of csk_sodium_mac and decrypts
// a given encrypted binary stream using a nonce and
// a secret key (sizes: see above).
//
// allocates memory for the returned cleartext and
// it is up to the user to free it after use.
//
// returns 0 if decryption and verification were
// successful, otherwise -1. 
int csk_sodium_verify_mac(unsigned char **cleartext,
                          unsigned char* message,
                          size_t messagesize,
                          unsigned char *nonce,
                          unsigned char *key);

// generate a nonce from random source arc4random().
// allocates memory for the returned nonce and
// it is up to the user to free it after use.
void csk_makenonce(unsigned char **nonce);

// proprietary key derivation function. derives an
// secure encryption key from the given passphrase by
// calculating a SALSA20 hash from it HCYCLES times.
// 
// turns the result into a proper CURVE25519 secret
// key. allocates memory for key and it is up to the
// user to free it after use.
// 
// deprecation warning: maybe removed once the libsodium
// developers incorporated some key derivation function
// into libsodium. so far, there's none but word goes
// that perhaps something like scrypt() from the star
// distribution may be added in the future.
void csk_makekey(char *passphrase, unsigned char **key);

#endif // _HAVE_CSK_MAC
