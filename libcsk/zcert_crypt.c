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
  pr(s, 32);
  pr(p, 32);

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

  pr(secret, 32);
  pr(public, 32);

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

int csk_raw_save(unsigned char *raw, char *filename, size_t clen) {
  FILE *fd = fopen(filename,"wb");
  if(fd == NULL) {
    return -1;
  }

  fwrite(raw, 1, clen, fd);

  fclose(fd);

  return 0;
}

unsigned char *csk_raw_load(char *filename, size_t *clen) {
  unsigned char *raw;

  FILE *fd = fopen(filename,"rb");
  if(fd == NULL) {
    return NULL;
  }

  fseek(fd, 0, SEEK_END);
  *clen = ftell(fd);
  fseek(fd, 0, SEEK_SET);
  
  raw = ucmalloc(*clen + 1);

  fread(raw, *clen, 1, fd);

  return raw;
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

