#ifndef _HAVE_CSK_ZCERT_CRYPT
#define _HAVE_CSK_ZCERT_CRYPT

#include <czmq.h>
#include "mac.h"
#include "getpass.h"

// encrypt a curve25529 secret key. 
//
// expects a pointer to an CZMQ zcert_t object, a passphrase
// and a pointer to an int.
// 
// returns a binary stream of the encrypted zcert_t of size *clen.
// the stream includes a randomly generated nonce. format:
// |32 bytes nonce|clen-32 bytes cipher|
//
// the returned stream is not null terminated.
//
// encryption scheme used: CURVE25519-SALSA20-POLY1305
//
// sample call:
// zcert_t *cert = zcert_new();
// unsigned char[] p = "topsecret";
// size_t resultlen;
// unsigned char *encrypted = csk_zcert_encrypt(cert, p, &resultlen); 
// [..] save 'encrypted' to disk or whatever
//
// returns NULL if an error occurs.
//
// it allocates apropriate memory for the returned binary
// stream and it is up to the user to free it after use.
unsigned char *csk_zcert_encrypt(zcert_t *cert, char *passphrase, size_t *clen);

// decrypt a curve25529 secret key.
//
// expects a pointer to a binary stream consisting of the nonce
// and the actual encrypted zcert (as has been created by csk_zcert_encrypt),
// a passphrase and the size of the binary stream.
//
// returns a pointer to a CZMQ zcert_t object if successful or NULL otherwise.
//
// it allocates apropriate memory for the returned zcert_t
// and it is up to the user to free it after use.
zcert_t *csk_zcert_decrypt(unsigned char *combined, char *passphrase, size_t clen);

// calculates the len of the zcert_t contents,
// required to allocate memory for the csk_zcert2raw()
// dump parameter. expects a CZMQ zcert_t object and
// returns the size of the raw keypair would be.
//
// use the result to allocate dump before calling
// csk_zcert2raw().
size_t csk_zcertlen(zcert_t *cert);

// converts the given CZMQ zcert_t keypair into an internal
// cleartext structure of the following form:
//
// name\0mail\0org\0nonce\0secret\0public\0
//
// so, metadata, public key and secret key get into it
// separated by \0.
//
// the memory for the first parameter, dump, must
// be allocated first. use csk_zcertlen to find out how
// much memory is required.
void csk_zcert2raw(unsigned char *dump, zcert_t *cert);

// does the opposite of csk_zcert2raw(). takes the raw
// stream of the keypair and converts it into a CZMQ zcert_t object.
//
// expects a properly formatted raw stream as created
// by csk_zcert2raw() and the size of that stream.
// returns a pointer to a zcert_t object or NULL in case
// of an error.
//
// it is up to the user to free the zcert_t object after use.
zcert_t *csk_raw2cert(unsigned char *raw, size_t rawlen);

// internal helper, appends a string to the raw stream.
int csk_append(unsigned char *buf, char *value, int pos);

// internal helper, shifts a string from the raw stream
char *csk_shift(unsigned char *dump, int pos, size_t csk_shift);

// convenience helper, stores a binary stream to a file.
// usually used to write the encrypted stream, but the
// function doesn't check what contents it writes, so
// it could be anything binary.
//
// FIXME: I wanted to use the zfile* API of CZMQ but
//        couldn't because it operates on textfiles
//        only and uses strlen() among other functions
//        which makes it unusable for me. perhaps a
//        future version supports binary files as well,
//        then those two functions will be removed, so
//        don't rely on them.
int csk_raw_save(unsigned char *raw, char *filename, size_t clen);

// convenience helper, read a binary stream from a file
// and returns it. the size of the stream will be returned
// in the pointer clen.
unsigned char *csk_raw_load(char *filename, size_t *clen);

// Get and store one header in certificate
int s_get_meta (zcert_t *cert, char *prompt, char *name);

#endif // _HAVE_CSK_ZCERT_CRYPT
