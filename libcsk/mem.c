#include "mem.h"


void *ucmalloc(size_t s) {
  size_t size = s * sizeof(unsigned char);
  void *value = malloc (size);

  if (value == NULL) {
    err(errno, "Cannot allocate memory");
    exit(-1);
  }

  bzero (value, size);
  return value;
}

void *ucfree(void *ptr) {
  if(ptr) free(ptr);
}
