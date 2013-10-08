#include "zcert_crypt.h"

void pr(unsigned char *k, int s) {
  int i;

  for (i = 0;i < s;++i) printf("%02x",(unsigned int) k[i]);

  printf("\n");
}

int csk_append(unsigned char *buf, char *value, int pos) {
  int i;
  for(i=0; i<strlen(value)+1; ++i) {
    buf[pos + i] = value[i];
  }
  return pos + i; 
}

char *csk_shift(unsigned char *dump, int pos, size_t dumplen) {
  char buffer[80];
  int i;
  size_t got = 0;

  for(i=0; i<dumplen; ++i) {
    if(dump[i + pos] != '\0') {
      buffer[i] = dump[i + pos];
      got++;
    }
    else {
      buffer[i] = '\0';
      got++;
      break;
    }
  }
  char *out = malloc(got+1);
  memcpy(out, buffer, got + 1);
  return out;
}


size_t csk_zcertlen(zcert_t *cert) {
  size_t d_len = strlen(zcert_meta(cert, "name"))
    + strlen(zcert_meta(cert, "email"))
    + strlen(zcert_meta(cert, "org"))
    + strlen(zcert_public_txt(cert))
    + strlen(zcert_secret_txt(cert));
  return d_len + 5; // 5 x \0
}

// convert zcert into a string, separated by \0
// product:
// name\0mail\0org\0nonce\0secret\0public\0
void csk_zcert2raw(unsigned char *dump, zcert_t *cert) {
  char *name = zcert_meta(cert, "name");
  char *mail = zcert_meta(cert, "email");
  char *org  = zcert_meta(cert, "org");
  char *public = zcert_public_txt(cert);
  char *secret = zcert_secret_txt(cert);

  unsigned char s[32];
  unsigned char p[32];
  zmq_z85_decode(s, secret);
  zmq_z85_decode(p, public);
  //pr(s, 32);
  //pr(p, 32);

  int pos = 0;
  pos = csk_append(dump, name, pos);
  pos = csk_append(dump, mail, pos);
  pos = csk_append(dump, org, pos);
  pos = csk_append(dump, secret, pos);
  pos = csk_append(dump, public, pos);
}

// revert the above, expect the unencrypted z85
// encoded rawstring
zcert_t *csk_raw2cert(unsigned char *raw, size_t rawlen) {
  char *name, *mail, *org, *secret_z85, *public_z85;
  unsigned char secret[32];
  unsigned char public[32];
  int pos = 0;

  name = csk_shift(raw, pos, rawlen);
  pos += strlen(name) + 1;

  mail = csk_shift(raw, pos, rawlen);
  pos += strlen(mail) + 1;

  org = csk_shift(raw, pos, rawlen);
  pos += strlen(org) + 1;

  secret_z85 = csk_shift(raw, pos, rawlen);
  pos += strlen(secret_z85) + 1;

  public_z85 = csk_shift(raw, pos, rawlen);
  pos += strlen(public_z85) + 1;

  zmq_z85_decode(secret, secret_z85);
  zmq_z85_decode(public, public_z85);

  //pr(secret, 32);
  //pr(public, 32);

  zcert_t *cert = zcert_new_from(public, secret);

  zcert_set_meta(cert, "name",  name);
  zcert_set_meta(cert, "email", mail);
  zcert_set_meta(cert, "org",   org);

  free(name);
  free(org);
  free(mail);
  free(secret_z85);
  free(public_z85);

  return cert;
}


unsigned char *csk_zcert_encrypt(zcert_t *cert, char *passphrase, size_t *clen) {
  unsigned char *nonce;
  unsigned char *key;
  int i;
  size_t encryptlen, rawlen, c_len;
  unsigned char *encrypted;
  unsigned char *combined;
  unsigned char *raw;

  // gen random nonce and derive encryption key from passphrase
  csk_makenonce(&nonce);
  csk_makekey(passphrase, &key);

  // make a raw string from the clear cert
  rawlen = csk_zcertlen(cert);
  raw = ucmalloc(rawlen);
  csk_zcert2raw(raw, cert);

  // encrypt that
  encryptlen = csk_sodium_mac(&encrypted, raw, rawlen, nonce, key);

  // put nonce and encrypted into one string
  c_len = crypto_secretbox_NONCEBYTES + encryptlen;

  combined = ucmalloc(c_len);
  memcpy(combined, nonce, crypto_secretbox_NONCEBYTES);
  for(i=0; i<encryptlen; ++i) {
    combined[crypto_secretbox_NONCEBYTES + i] = encrypted[i];
  }

  free(nonce);
  free(key);
  free(encrypted);
  free(raw);

  *clen = c_len;
  return combined;
}

zcert_t *csk_zcert_decrypt(unsigned char *combined, char *passphrase, size_t clen) {
  unsigned char *encrypted;
  unsigned char *raw;
  unsigned char *key;
  unsigned char *nonce;
  int i;
  int err = 0;
  zcert_t *cert;

  // fetch the nonce
  nonce = ucmalloc(crypto_secretbox_NONCEBYTES);
  memcpy(nonce, combined, crypto_secretbox_NONCEBYTES);

  // gen the key
  csk_makekey(passphrase, &key);

  // fetch encrypted
  size_t e_len = clen - crypto_secretbox_NONCEBYTES;
  encrypted = ucmalloc(e_len);
  for (i=0; i<e_len; ++i) {
    encrypted[i] = combined[crypto_secretbox_NONCEBYTES + i];
  }

  // decrypt the raw
  if(csk_sodium_verify_mac(&raw, encrypted, e_len, nonce, key) != 0) {
    printf("failed to decrypt secret key file!\n");
    err = -1;
  }

  if(err == 0) {
    cert = csk_raw2cert(raw, e_len - crypto_secretbox_BOXZEROBYTES);
  }

  free(encrypted);
  free(key);
  free(nonce);
  free(raw);
 
  if(err == 0) {
    return cert;
  }
  else {
    return NULL;
  }
}

unsigned char *csk_padfour(unsigned char *src, size_t srclen, size_t *dstlen) {
  int i;
  size_t outlen;
  unsigned char *dst;
 
  outlen = srclen + 1; // 1 for the pad flag
  while (outlen % 4 != 0) outlen++;

  dst = ucmalloc(outlen);

  dst[0] = outlen - (srclen + 1);              // add the number of zeros we add
  for(i=1; i<srclen+1; ++i) dst[i] = src[i -1];    // add the original
  for(i=srclen+1; i<outlen; ++i) dst[i] = '\0';  // pad with zeroes

  *dstlen = outlen;

  return dst;
}

unsigned char *csk_unpadfour(unsigned char *src, size_t srclen, size_t *dstlen) {
  int i;
  size_t outlen;
  size_t numzeroes;
  unsigned char *dst;

  numzeroes = src[0];  // first byte tells us how many zeroes we've got
  outlen = srclen - 1 - numzeroes;
  
  dst = malloc(outlen);

  for (i=1; i<outlen+1; ++i) dst[i-1] = src[i]; // copy the remainder without the zeroes

  *dstlen = outlen;

  return dst;
}

unsigned char *csk_z85_decode(char *z85block, size_t *dstlen) {
  unsigned char *bin;
  int i, pos;
  size_t zlen, binlen, outlen; 

  zlen = strlen(z85block);
  char *z85 = ucmalloc(zlen);

  // remove newlines
  pos = 0;
  for(i=0; i<zlen; ++i) {
    if(z85block[i] != '\r' && z85block[i] != '\n') {
      z85[pos] = z85block[i];
      pos++;
    }
  }

  binlen = strlen (z85) * 4 / 5; 
  bin = ucmalloc(binlen);
  bin = zmq_z85_decode(bin, z85);
  unsigned char *raw = csk_unpadfour(bin, binlen, &outlen);

  free(z85);
  free(bin); 

  *dstlen = outlen;
  return raw;
}

char *csk_z85_encode(unsigned char *raw, size_t srclen, size_t *dstlen) {
  int i, pos, b;
  size_t outlen, blocklen, zlen;

  // make z85 happy (size % 4)
  unsigned char *padded = csk_padfour(raw, srclen, &outlen);

  // encode to z85
  zlen = (outlen * 5 / 4) + 1;
  char *z85 = ucmalloc(zlen);
  z85 = zmq_z85_encode(z85, padded, outlen);

  // make it a 72 chars wide block
  blocklen = strlen(z85) + ((strlen(z85) / 72) * 2) + 1;
  char *z85block = ucmalloc(blocklen);
  pos = b = 0;
  for(i=0; i<zlen; ++i) {
    if(pos == 72) {
      z85block[b] = '\r';
      b++;
      z85block[b] = '\n';
      b++;
      pos = 0;
    }
    else {
      pos++;
    }
    z85block[b] = z85[i];
    b++;
  }

  *dstlen = blocklen;
  free(z85);
  free(padded);

  return z85block;
}

int csk_raw_save(unsigned char *raw, char *filename, size_t clen) {
  FILE *fd = fopen(filename,"wb");
  if(fd == NULL) {
    return -1;
  }

  // convert to z85 encoded block
  size_t blocklen;
  char *z85block = csk_z85_encode(raw, clen, &blocklen);

  fprintf(fd, "%s\r\n%s\r\n%s\r\n", CSK_KEYFILE_HEAD, z85block, CSK_KEYFILE_FOOT);

  fclose(fd);

  free(z85block);
  return 0;
}

unsigned char *csk_raw_load(char *filename, size_t *clen) {
  char *raw;
  size_t rawlen, zlen;

  FILE *fd = fopen(filename,"rb");
  if(fd == NULL) {
    return NULL; // fixme: print error
  }

  // read encoded block with headers
  fseek(fd, 0, SEEK_END);
  rawlen = ftell(fd);
  fseek(fd, 0, SEEK_SET);
  raw = ucmalloc(rawlen + 1);
  fread(raw, rawlen, 1, fd);

  if(rawlen > strlen(CSK_KEYFILE_HEAD) + strlen(CSK_KEYFILE_FOOT) + 48 &&
     strncmp(raw, CSK_KEYFILE_HEAD, strlen(CSK_KEYFILE_HEAD)) == 0) {
    zlen = rawlen - strlen(CSK_KEYFILE_HEAD) - strlen(CSK_KEYFILE_FOOT) - 3; // 3 = 2x2 newlines minus zero
    char *z85block = ucmalloc(zlen);
    strncpy(z85block, raw+strlen(CSK_KEYFILE_HEAD), zlen);
    size_t outlen;
    unsigned char *decoded = csk_z85_decode(z85block, &outlen);
    *clen = outlen;
    return decoded;
  }
  else {
    free(raw);
    fprintf(stderr, "Unable to parse secret key file, invalid format!\n");
    return NULL;
  }

  return NULL;
}

int s_get_meta (zcert_t *cert, char *prompt, char *name) {
    printf ("%s ", prompt);
    char *value = csk_get_stdin();

    if (value == NULL)
      return -1;
    else
      zcert_set_meta (cert, name, value);
    return 0;
}

