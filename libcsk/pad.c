#include "pad.h"

void csk_pad_prepend(unsigned char **padded, unsigned char *unpadded,
		 size_t padlen, size_t unpadlen) {
  *padded = ucmalloc(unpadlen + padlen);
  unsigned char *tmp = ucmalloc(unpadlen + padlen);

  // csk_append orig
  int i;
  for(i=0; i<unpadlen; ++i) {
    tmp[i + padlen] = unpadded[i];
  }

  memcpy(*padded, tmp, unpadlen + padlen);
  free(tmp);
}

void csk_pad_remove(unsigned char **unpadded, unsigned char *padded,
		size_t padlen, size_t unpadlen) {
  *unpadded = ucmalloc(unpadlen * sizeof(unsigned char));
  unsigned char *tmp = ucmalloc(unpadlen);

  int i;
  for(i=0; i<unpadlen; ++i) {
    tmp[i] = padded[padlen + i];
  }
  
  memcpy(*unpadded, tmp, unpadlen);
  free(tmp);
}

#ifdef _MK_ZPAD_MAIN
int main(int argc, char **argv) {
  if(argc >= 2) {
    size_t unpadlen;
    int padlen = strtol(argv[2], NULL, 0);
    unpadlen = strlen(argv[1]);
    unsigned char *dst;
    
    csk_pad_prepend(&dst, argv[1], padlen, unpadlen);
    //printf("   prev: %s\n  after: %s\n", argv[1], dst);
    
    unsigned char *reverse;
    csk_pad_remove(&reverse, dst, padlen, unpadlen);
    //printf("reverse: %s\n", reverse);
    
    return 0;
  }
  //fprintf(stderr, "Usage: pad <string> <padlen>\n");
  return -1;
}
#endif

