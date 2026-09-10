#!/bin/sh
set -eu
mmdebstrap --mode=root --variant=minbase --architectures=amd64 \
    --skip=chroot/mount --format=directory \
    --include=ca-certificates \
    --aptopt='Acquire::Check-Valid-Until "false"' \
    --aptopt='Acquire::Languages "none"' \
    trixie /rootfs /etc/apt/sources.list
printf 'app:x:65532:65532:Application:/tmp:/usr/sbin/nologin\n' >> /rootfs/etc/passwd
printf 'app:x:65532:\n' >> /rootfs/etc/group
mkdir -p /rootfs/usr/share/sovereign-stack/base-container
cp /etc/apt/sources.list /rootfs/usr/share/sovereign-stack/base-container/sources.list
dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\n' \
    > /rootfs/usr/share/sovereign-stack/base-container/bootstrap-packages.tsv
chroot /rootfs dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\n' \
    > /rootfs/usr/share/sovereign-stack/base-container/runtime-packages.tsv
cp -a /usr/share/doc /rootfs/usr/share/sovereign-stack/base-container/bootstrap-doc
# Keep dpkg's database and Debian copyright texts. Only discard volatile logs.
find /rootfs/var/log -type f -exec truncate -s 0 {} +
find /rootfs -xdev -type f -perm /6000 -exec chmod a-s {} +
rm -f /rootfs/etc/hostname /rootfs/etc/resolv.conf /rootfs/etc/machine-id
