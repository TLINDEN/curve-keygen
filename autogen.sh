#!/bin/sh

# clear up the mess
set -x

find . -name Makefile -exec rm {} \;
find . -name Makefile.in -exec rm {} \;
find . -name "*~"     -exec rm {} \;
find . -name config.h -exec rm {} \;
find . -name stamp.h  -exec rm {} \;
find . -name .deps    -exec rm -rf {} \;
find . -name .libs    -exec rm -rf {} \;
find . -name .o    -exec rm -rf {} \;
find . -name .lo    -exec rm -rf {} \;

rm -rf configure config.* config autom4te.cache
set +x

# generate the install include file
(echo "#ifndef _HAVE_CSK"; echo "#define _HAVE_CSK"; echo) > include/csk.h
(echo "#ifdef __cplusplus"; echo "extern \"C\" {"; echo "#endif"; echo) >> include/csk.h
egrep -h "^#include" libcsk/*.h | grep -v '"' | sort -u >> include/csk.h
ls libcsk/*.h | while read include; do
  (echo; echo "// +++ from $include: +++"; echo) >> include/csk.h
  grep -h -v _HAVE $include | egrep -v "^#include" >> include/csk.h
done
(echo "#ifdef __cplusplus"; echo "}"; echo "#endif"; echo) >> include/csk.h
(echo; echo "#endif") >> include/csk.h


# generate the version file
maj=`egrep "#define CSK_VERSION_MAJOR" libcsk/version.h | awk '{print $3}'`
min=`egrep "#define CSK_VERSION_MINOR" libcsk/version.h | awk '{print $3}'`
pat=`egrep "#define CSK_VERSION_PATCH" libcsk/version.h | awk '{print $3}'`
echo "$maj.$min.$pat" > VERSION

# generate the manpage
pod2man -r "CURVE-KEYGEN `cat VERSION`" -c "USER CONTRIBUTED DOCUMENTATION" man/curve-keygen.pod > man/curve-keygen.1


clean=$1

if test -z "$clean"; then
  mkdir -p ./config
  
  if ! command -v libtool >/dev/null 2>&1; then
      echo "could not find libtool." 1>&2
      exit 1
  fi
  
  if ! command -v autoreconf >/dev/null 2>&1; then
      echo "could not find autoreconf." 1>&2
      exit 1
  fi
  
  autoreconf --install --force --verbose -I config
fi

