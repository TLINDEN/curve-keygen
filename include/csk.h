#ifndef _HAVE_CSK
#define _HAVE_CSK

#ifdef __cplusplus
extern "C" {
#endif

#include <czmq.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <termios.h>
#include <unistd.h>

// +++ from libcsk/getpass.h: +++


/*
 * (unportable) functions to turn on/off terminal echo
 * using termios functions. might compile however on
 * most unices, tested on FreeBSD only.
 */




void csk_echo_off();
void csk_echo_on();
char *csk_get_stdin();
char *csk_get_passphrase(char *prompt);


// +++ from libcsk/mac.h: +++




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


// +++ from libcsk/mem.h: +++



// simple malloc()  wrapper 
// behaves like calloc(), which
// I don't have here.
// 
// exits if there's no more memory
// available.
void *ucmalloc(size_t s);

// dito.
void *ucfree(void *ptr);



// +++ from libcsk/pad.h: +++




#ifdef DEBUG
#define ZPADCHAR 48
#else
#define ZPADCHAR 0
#endif

// prepends a binary stream with a number of
// \0's as required by the secret_box and
// secret_box_open functions of libsodium.
//
// parameters:
//
// padded:    destination array (ref)
// unpadded:  source array without padding
// padlen:    length of padding
// unpadlen:  length of source array
//
// turns "efa5" into "00000000efa5" with padlen 8
//
// if DEBUG is set, destination will be padded with
// the character '0', NOT the integer 0.
//
// allocates memory for padded and it is up to the
// user to free it after use.
//
// sample call:
//
// char unpadded[] = {0xef, 0xa5};
// unsigned char *padded;
// csk_pad_prepend(&padded, unpadded, 8, 2);
//
// the result, padded, would be 10 bytes long, 8
// bytes for the leading zeros and 2 for the content
// of the original unpadded.
void csk_pad_prepend(unsigned char **padded, unsigned char *unpadded,
		 size_t padlen, size_t unpadlen);

// removes zero's of a binary stream, which is
// the reverse of csk_pad_prepend().
//
// parameters:
// 
// unpadded:   destination array (ref), with padding removed
// padded:     source array with padding
// padlen:     length of padding
// unpadlen:   length of source array
//
// turns "00000000efa5" into "efa5" with padlen 8
//
// allocates memory for unpadded and it is up to the
// user to free it after use.
//
// sample call:
//
// char padded[] = {0x0, 0x0, 0x0, 0x0, 0xef, 0xa5};
// unsigned char *unpadded;
// csk_pad_remove(unpadded, padded, 4, 2);
//
// the result, unpadded would be 2 bytes long containing
// only the 2 bytes we want to have with zeros removed.
void csk_pad_remove(unsigned char **unpadded, unsigned char *padded,
		size_t padlen, size_t unpadlen);



// +++ from libcsk/version.h: +++


#define CSK_VERSION_MAJOR 0
#define CSK_VERSION_MINOR 0
#define CSK_VERSION_PATCH 1

#define CSK_MAKE_VERSION(major, minor, patch) \
    ((major) * 10000 + (minor) * 100 + (patch))
#define CSK_VERSION \
    CSK_MAKE_VERSION(CSK_VERSION_MAJOR, CSK_VERSION_MINOR, CSK_VERSION_PATCH)

int csk_version();


// +++ from libcsk/zcert_crypt.h: +++



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

// used for encrypted key files
#define CSK_KEYFILE_HEAD "-----BEGIN CURVE25519 SECRET KEY-----"
#define CSK_KEYFILE_FOOT "-----END CURVE25519 SECRET KEY-----"

// convert a binary stream to one which gets accepted by zmq_z85_encode
// we pad it with zeroes and put the number of zerores in front of it 
unsigned char *csk_unpadfour(unsigned char *src, size_t srclen, size_t *dstlen);

// the reverse of the above
unsigned char *csk_unpadfour(unsigned char *src, size_t srclen, size_t *dstlen);

// wrapper around zmq Z85 encoding function
unsigned char *csk_z85_decode(char *z85block, size_t *dstlen);

// the reverse of the above
char *csk_z85_encode(unsigned char *raw, size_t srclen, size_t *dstlen);

#ifdef __cplusplus
}
#endif


#endif
