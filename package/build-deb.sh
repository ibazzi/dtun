#!/bin/sh
set -e

VERSION="1.0.0"
KVER=$(uname -r)
ARCH=$(dpkg --print-architecture 2>/dev/null || uname -m)

if [ "$ARCH" = "x86_64" ]; then
    ARCH="amd64"
elif [ "$ARCH" = "aarch64" ]; then
    ARCH="arm64"
fi

PKG_DIR="build/pkg/dtun_${VERSION}_${ARCH}"
DEB_FILE="build/dtun_${VERSION}_${ARCH}.deb"

echo "[dtun deb] Building package for Architecture=${ARCH}, Kernel=${KVER}..."

rm -rf "$PKG_DIR"
mkdir -p "${PKG_DIR}/usr/bin"
mkdir -p "${PKG_DIR}/lib/modules/${KVER}/extra"
mkdir -p "${PKG_DIR}/etc/dtun"
mkdir -p "${PKG_DIR}/lib/systemd/system"
mkdir -p "${PKG_DIR}/DEBIAN"

cp -f build/dtund "${PKG_DIR}/usr/bin/"
cp -f build/dtunctl "${PKG_DIR}/usr/bin/"
cp -f build/dtun.ko "${PKG_DIR}/lib/modules/${KVER}/extra/"
cp -f samples/dtun-example.conf "${PKG_DIR}/etc/dtun/dtun-example.conf"
if [ ! -f "${PKG_DIR}/etc/dtun/dtun.conf" ]; then
    cp -f samples/dtun-example.conf "${PKG_DIR}/etc/dtun/dtun.conf"
fi
cp -f package/dtund.service "${PKG_DIR}/lib/systemd/system/dtund.service"

cat << CONTROL > "${PKG_DIR}/DEBIAN/control"
Package: dtun
Version: ${VERSION}
Architecture: ${ARCH}
Maintainer: dtun maintainer <info@dtun.local>
Section: net
Priority: optional
Description: Dual transport authenticated L3 tunnel daemon and kernel module
 dtun provides authenticated layer-3 mesh tunnels over dual UDP/Raw transports.
 Includes the dtun kernel module, control utilities, and background daemon.
CONTROL

cp -f package/postinst "${PKG_DIR}/DEBIAN/postinst"
cp -f package/postrm "${PKG_DIR}/DEBIAN/postrm"
chmod 0755 "${PKG_DIR}/DEBIAN/postinst" "${PKG_DIR}/DEBIAN/postrm"

dpkg-deb --build "$PKG_DIR" "$DEB_FILE"
echo "[dtun deb] Package built successfully: ${DEB_FILE}"
