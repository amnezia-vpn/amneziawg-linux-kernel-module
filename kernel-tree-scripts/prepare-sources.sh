#!/bin/bash

KERNEL_VERSION=$1

is_modern_kernel() {
  local modern=$(echo $KERNEL_VERSION | awk 'BEGIN{ FS="."};
      { if ($1 < 5) { print "N"; }
        else if ($1 == 5) {
            if ($2 <= 5) { print "N"; }
            else { print "Y"; }
        }
        else { print "Y"; }
      }')

  if [ "$modern" = "N" ]; then
    return 1
  fi
}

if ! is_modern_kernel; then
  echo "Legacy kernel - using the compat sources"
  exit 0
fi

if [ -e kernel/drivers/net/wireguard/main.c ] && [ -e kernel/include/uapi/linux/wireguard.h ]; then
  echo "Kernel sources are already prepared, skipping"
  exit 0
fi


DISTRO_FLAVOR=$(cat /etc/*-release 2>/dev/null | grep -E ^ID_LIKE=  | sed 's/ID_LIKE=//' | sed 's/"//g')
DISTRO_FLAVOR=${DISTRO_FLAVOR:-$(cat /etc/*-release 2>/dev/null | grep -E ^ID=  | sed 's/ID=//' | sed 's/"//g')}

if [ "${AWG_TEMP_DIR}" != "" ]; then
  mkdir -p /var/lib/amnezia/amneziawg
  echo "${AWG_TEMP_DIR}" > /var/lib/amnezia/amneziawg/.tempdir
elif [ -f /var/lib/amnezia/amneziawg/.tempdir ]; then
  AWG_TEMP_DIR="$(cat /var/lib/amnezia/amneziawg/.tempdir)"
fi

PREFIX=${AWG_TEMP_DIR:-/tmp}
WORKDIR="${PREFIX}/amneziawg"

[ -d "${WORKDIR}" ] && rm -rf "${WORKDIR}"
mkdir -p "${WORKDIR}"
pushd "${WORKDIR}" > /dev/null 2>&1 || exit 1

echo "Downloading source for Linux kernel version ${KERNEL_VERSION}"

if [[ "${DISTRO_FLAVOR}" =~ debian ]]; then
  export DEBIAN_FRONTEND=noninteractive
  VERSION_MAIN="${KERNEL_VERSION%+*}"
  VERSION_SUFFIX="${KERNEL_VERSION#*+}"
  ac=$(apt-cache search --names-only linux-image "${VERSION_MAIN}" "${VERSION_SUFFIX}" unsigned 2>/dev/null|head -n 1)
  [ "${ac}" == "" ] && ac=$(apt-cache search --names-only linux-image "${VERSION_MAIN}" "${VERSION_SUFFIX}" 2>/dev/null|head -n 1)
  if [ "${ac}" == "" ]; then
    echo "Could not find suitable image for your Linux distribution!"
    exit 255
  fi

  PACKAGE_NAME="${ac% - *}"
  PACKAGE_VERSION=$(apt-cache madison "${PACKAGE_NAME}"|grep Sources|head -n 1|awk '{ print $3; }')
  echo "Downloading as $(whoami)"
  apt-get -yq -o APT::Sandbox::User="$(whoami)" source "${PACKAGE_NAME}=${PACKAGE_VERSION}"
  cd "$(ls -d */)" || exit 255
elif ! which dnf > /dev/null 2>&1 && \
   ! which yum > /dev/null 2>&1; then
  echo "Script will now try to download wireguard source code from kernel.org"
  echo "If this step fails you will need to download sources on your own and make a symbolic link to /usr/src/amneziawg-1.0.0/kernel:"
  echo ""
  echo "  ln -s /path/to/kernel/source /usr/src/amneziawg-1.0.0/kernel"
  echo ""
  VERSION="${KERNEL_VERSION%%[^0-9.]*}"
  VERSION_MAJOR="${KERNEL_VERSION%%[^0-9]*}"
  wget --no-verbose -O - "https://cdn.kernel.org/pub/linux/kernel/v${VERSION_MAJOR}.x/linux-${VERSION}.tar.xz" | tar -xvJf - "linux-${VERSION}/drivers/net/wireguard" "linux-${VERSION}/include/uapi/linux"
  cd "linux-${VERSION}" || exit 255
else
  yumdownloader --source kernel
  [ -f "${HOME}/.rpmmacros" ] && mv "${HOME}/.rpmmacros" "${HOME}/.rpmmacros.orig"
  echo "%_topdir $(pwd)" > "${HOME}/.rpmmacros"
  rpm -ivh "$(ls *.rpm)"
  cd SPECS || exit 255
  rpmbuild -bp --target="$(uname -m)" --nodeps kernel.spec
  rm -rf "${HOME}/.rpmmacros"
  [ -f "${HOME}/.rpmmacros.orig" ] && mv "${HOME}/.rpmmacros.orig" "${HOME}/.rpmmacros"
  cd ../BUILD || exit 255
  cd "$(ls -d */)" || exit 255
  cd "$(ls -d linux*/)" || exit 255
fi

KERNEL_PATH="$(pwd)"
popd > /dev/null 2>&1 || exit 1
[ -e kernel ] && rm -f kernel
ln -s "${KERNEL_PATH}" kernel
