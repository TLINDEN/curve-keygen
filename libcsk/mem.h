#ifndef _HAVE_CSK_MEM
#define _HAVE_CSK_MEM

#include <strings.h>
#include <stdlib.h>
#include <errno.h>
#include <err.h>

// simple malloc()  wrapper 
// behaves like calloc(), which
// I don't have here.
// 
// exits if there's no more memory
// available.
void *ucmalloc(size_t s);

// dito.
void *ucfree(void *ptr);


#endif // _HAVE_CSK_MEM
