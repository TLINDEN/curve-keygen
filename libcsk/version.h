#ifndef _HAVE_CSK_VERSION
#define _HAVE_CSK_VERSION

#define CSK_VERSION_MAJOR 0
#define CSK_VERSION_MINOR 0
#define CSK_VERSION_PATCH 1

#define CSK_MAKE_VERSION(major, minor, patch) \
    ((major) * 10000 + (minor) * 100 + (patch))
#define CSK_VERSION \
    CSK_MAKE_VERSION(CSK_VERSION_MAJOR, CSK_VERSION_MINOR, CSK_VERSION_PATCH)

int csk_version();

#endif // _HAVE_CSK_VERSION
