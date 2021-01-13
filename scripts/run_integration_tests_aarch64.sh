#!/bin/bash
set -x

source $HOME/.cargo/env
source $(dirname "$0")/test-util.sh

export BUILD_TARGET=${BUILD_TARGET-aarch64-unknown-linux-gnu}

WORKLOADS_DIR="$HOME/workloads"
WORKLOADS_LOCK="$WORKLOADS_DIR/integration_test.lock"

mkdir -p "$WORKLOADS_DIR"

update_workloads() {
    cp scripts/sha1sums-aarch64 $WORKLOADS_DIR

    BIONIC_OS_IMAGE_DOWNLOAD_NAME="bionic-server-cloudimg-arm64.img"
    BIONIC_OS_IMAGE_DOWNLOAD_URL="https://cloudhypervisorstorage.blob.core.windows.net/images/$BIONIC_OS_IMAGE_DOWNLOAD_NAME"
    BIONIC_OS_DOWNLOAD_IMAGE="$WORKLOADS_DIR/$BIONIC_OS_IMAGE_DOWNLOAD_NAME"
    if [ ! -f "$BIONIC_OS_DOWNLOAD_IMAGE" ]; then
        pushd $WORKLOADS_DIR
        time wget --quiet $BIONIC_OS_IMAGE_DOWNLOAD_URL || exit 1
        popd
    fi

    BIONIC_OS_RAW_IMAGE_NAME="bionic-server-cloudimg-arm64.raw"
    BIONIC_OS_RAW_IMAGE="$WORKLOADS_DIR/$BIONIC_OS_RAW_IMAGE_NAME"
    if [ ! -f "$BIONIC_OS_RAW_IMAGE" ]; then
        pushd $WORKLOADS_DIR
        time qemu-img convert -p -f qcow2 -O raw $BIONIC_OS_IMAGE_DOWNLOAD_NAME $BIONIC_OS_RAW_IMAGE_NAME || exit 1
        popd
    fi

    # Convert the raw image to qcow2 image to remove compressed blocks from the disk. Therefore letting the
    # qcow2 format image can be directly used in the integration test.
    BIONIC_OS_QCOW2_IMAGE_UNCOMPRESSED_NAME="bionic-server-cloudimg-arm64.qcow2"
    BIONIC_OS_QCOW2_UNCOMPRESSED_IMAGE="$WORKLOADS_DIR/$BIONIC_OS_QCOW2_IMAGE_UNCOMPRESSED_NAME"
    if [ ! -f "$BIONIC_OS_QCOW2_UNCOMPRESSED_IMAGE" ]; then
        pushd $WORKLOADS_DIR
        time qemu-img convert -p -f raw -O qcow2 $BIONIC_OS_RAW_IMAGE_NAME $BIONIC_OS_QCOW2_UNCOMPRESSED_IMAGE || exit 1
        popd
    fi

    FOCAL_OS_RAW_IMAGE_NAME="focal-server-cloudimg-arm64-custom.raw"
    FOCAL_OS_RAW_IMAGE_DOWNLOAD_URL="https://cloudhypervisorstorage.blob.core.windows.net/images/$FOCAL_OS_RAW_IMAGE_NAME"
    FOCAL_OS_RAW_IMAGE="$WORKLOADS_DIR/$FOCAL_OS_RAW_IMAGE_NAME"
    if [ ! -f "$FOCAL_OS_RAW_IMAGE" ]; then
        pushd $WORKLOADS_DIR
        time wget --quiet $FOCAL_OS_RAW_IMAGE_DOWNLOAD_URL || exit 1
        popd
    fi

    # Convert the raw image to qcow2 image to remove compressed blocks from the disk. Therefore letting the
    # qcow2 format image can be directly used in the integration test.
    FOCAL_OS_QCOW2_IMAGE_UNCOMPRESSED_NAME="focal-server-cloudimg-arm64-custom.qcow2"
    FOCAL_OS_QCOW2_IMAGE_UNCOMPRESSED_DOWNLOAD_URL="https://cloudhypervisorstorage.blob.core.windows.net/images/$FOCAL_OS_QCOW2_IMAGE_UNCOMPRESSED_NAME"
    FOCAL_OS_QCOW2_UNCOMPRESSED_IMAGE="$WORKLOADS_DIR/$FOCAL_OS_QCOW2_IMAGE_UNCOMPRESSED_NAME"
    if [ ! -f "$FOCAL_OS_QCOW2_UNCOMPRESSED_IMAGE" ]; then
        pushd $WORKLOADS_DIR
        time wget --quiet $FOCAL_OS_QCOW2_IMAGE_UNCOMPRESSED_DOWNLOAD_URL || exit 1
        popd
    fi

    ALPINE_MINIROOTFS_URL="http://dl-cdn.alpinelinux.org/alpine/v3.11/releases/aarch64/alpine-minirootfs-3.11.3-aarch64.tar.gz"
    ALPINE_MINIROOTFS_TARBALL="$WORKLOADS_DIR/alpine-minirootfs-aarch64.tar.gz"
    if [ ! -f "$ALPINE_MINIROOTFS_TARBALL" ]; then
        pushd $WORKLOADS_DIR
        time wget --quiet $ALPINE_MINIROOTFS_URL -O $ALPINE_MINIROOTFS_TARBALL || exit 1
        popd
    fi

    ALPINE_INITRAMFS_IMAGE="$WORKLOADS_DIR/alpine_initramfs.img"
    if [ ! -f "$ALPINE_INITRAMFS_IMAGE" ]; then
        pushd $WORKLOADS_DIR
        mkdir alpine-minirootfs
        tar xf "$ALPINE_MINIROOTFS_TARBALL" -C alpine-minirootfs
        cat > alpine-minirootfs/init <<-EOF
			#! /bin/sh
			mount -t devtmpfs dev /dev
			echo \$TEST_STRING > /dev/console
			poweroff -f
		EOF
        chmod +x alpine-minirootfs/init
        cd alpine-minirootfs
        find . -print0 |
            cpio --null --create --verbose --owner root:root --format=newc > "$ALPINE_INITRAMFS_IMAGE"
        popd
    fi

    pushd $WORKLOADS_DIR
    sha1sum sha1sums-aarch64 --check
    if [ $? -ne 0 ]; then
        echo "sha1sum validation of images failed, remove invalid images to fix the issue."
        exit 1
    fi
    popd

    # Build custom kernel based on virtio-pmem and virtio-fs upstream patches
    PE_IMAGE="$WORKLOADS_DIR/Image"
    LINUX_CUSTOM_DIR="$WORKLOADS_DIR/linux-custom"

    build_custom_linux_kernel() {
        pushd $LINUX_CUSTOM_DIR
        time make -j `nproc`
        cp arch/arm64/boot/Image $WORKLOADS_DIR/Image || exit 1
        popd
    }

    SRCDIR=$PWD
    LINUX_CUSTOM_BRANCH="ch-5.10.6"

    # Check whether the local HEAD commit same as the remote HEAD or not. Remove the folder if they are different.
    if [ -d "$LINUX_CUSTOM_DIR" ]; then
        pushd $LINUX_CUSTOM_DIR
        git fetch
        LINUX_CUSTOM_LOCAL_HEAD=$(git rev-parse HEAD)
        LINUX_CUSTOM_REMOTE_HEAD=$(git rev-parse remotes/origin/$LINUX_CUSTOM_BRANCH)
        popd
        if [ "$LINUX_CUSTOM_LOCAL_HEAD" != "$LINUX_CUSTOM_REMOTE_HEAD" ]; then
            rm -rf "$LINUX_CUSTOM_DIR"
        fi
    fi

    if [ ! -d "$LINUX_CUSTOM_DIR" ]; then
        time git clone --depth 1 "https://github.com/cloud-hypervisor/linux.git" -b $LINUX_CUSTOM_BRANCH $LINUX_CUSTOM_DIR
    fi

    cp $SRCDIR/resources/linux-config-aarch64 $LINUX_CUSTOM_DIR/.config
    build_custom_linux_kernel

    VIRTIOFSD="$WORKLOADS_DIR/virtiofsd"
    QEMU_DIR="qemu_build"

    if [ ! -f "$VIRTIOFSD" ]; then
        pushd $WORKLOADS_DIR
        git clone --depth 1 "https://gitlab.com/virtio-fs/qemu.git" -b "qemu5.0-virtiofs-dax" $QEMU_DIR
        pushd $QEMU_DIR
        time ./configure --prefix=$PWD --target-list=aarch64-softmmu
        time make virtiofsd -j `nproc`
        cp virtiofsd $VIRTIOFSD || exit 1
        popd
        rm -rf $QEMU_DIR
        popd
    fi

    VIRTIOFSD_RS="$WORKLOADS_DIR/virtiofsd-rs"
    VIRTIOFSD_RS_DIR="virtiofsd_rs_build"
    if [ ! -f "$VIRTIOFSD_RS" ]; then
        pushd $WORKLOADS_DIR
        git clone --depth 1 "https://gitlab.com/virtio-fs/virtiofsd-rs.git" $VIRTIOFSD_RS_DIR
        pushd $VIRTIOFSD_RS_DIR
        time cargo build --release
        cp target/release/virtiofsd-rs $VIRTIOFSD_RS || exit 1
        popd
        rm -rf $VIRTIOFSD_RS_DIR
        popd
    fi

    BLK_IMAGE="$WORKLOADS_DIR/blk.img"
    MNT_DIR="mount_image"
    if [ ! -f "$BLK_IMAGE" ]; then
        pushd $WORKLOADS_DIR
        fallocate -l 16M $BLK_IMAGE
        mkfs.ext4 -j $BLK_IMAGE
        mkdir $MNT_DIR
        sudo mount -t ext4 $BLK_IMAGE $MNT_DIR
        sudo bash -c "echo bar > $MNT_DIR/foo" || exit 1
        sudo umount $BLK_IMAGE
        rm -r $MNT_DIR
        popd
    fi

    SHARED_DIR="$WORKLOADS_DIR/shared_dir"
    if [ ! -d "$SHARED_DIR" ]; then
        mkdir -p $SHARED_DIR
        echo "foo" > "$SHARED_DIR/file1"
        echo "bar" > "$SHARED_DIR/file3" || exit 1
    fi
}

process_common_args "$@"
features_build="--no-default-features --features kvm "
features_test="--no-default-features --features integration_tests,kvm"

# lock the workloads folder to avoid parallel updating by different containers
(
    echo "try to lock $WORKLOADS_DIR folder and update"
    flock -x 12 && update_workloads
) 12>$WORKLOADS_LOCK

# Check if there is any error in the execution of `update_workloads`.
# If there is any error, then kill the shell. Otherwise the script will continue
# running even if the `update_workloads` function was failed.
RES=$?
if [ $RES -ne 0 ]; then
    exit 1
fi

# Create tap interface without multiple queues support for vhost_user_net test.
sudo ip tuntap add name vunet-tap0 mode tap
# Create tap interface with multiple queues support for vhost_user_net test.
sudo ip tuntap add name vunet-tap1 mode tap multi_queue

BUILD_TARGET="aarch64-unknown-linux-${CH_LIBC}"
CFLAGS=""
TARGET_CC=""
if [[ "${BUILD_TARGET}" == "aarch64-unknown-linux-musl" ]]; then
TARGET_CC="musl-gcc"
CFLAGS="-I /usr/include/aarch64-linux-musl/ -idirafter /usr/include/"
fi

# Use device mapper to create a snapshot of the Ubuntu Bionic image
bionic_img_blk_size=$(du -b -B 512 /root/workloads/bionic-server-cloudimg-arm64.raw | awk '{print $1;}')
bionic_loop_device=$(losetup --find --show --read-only /root/workloads/bionic-server-cloudimg-arm64.raw)
dmsetup create bionic-base --table "0 $bionic_img_blk_size linear $bionic_loop_device 0"
dmsetup mknodes
dmsetup create bionic-snapshot-base --table "0 $bionic_img_blk_size snapshot-origin /dev/mapper/bionic-base"
dmsetup mknodes
# Use device mapper to create a snapshot of the Ubuntu Focal image
focal_img_blk_size=$(du -b -B 512 /root/workloads/focal-server-cloudimg-arm64-custom.raw | awk '{print $1;}')
focal_loop_device=$(losetup --find --show --read-only /root/workloads/focal-server-cloudimg-arm64-custom.raw)
dmsetup create focal-base --table "0 $focal_img_blk_size linear $focal_loop_device 0"
dmsetup mknodes
dmsetup create focal-snapshot-base --table "0 $focal_img_blk_size snapshot-origin /dev/mapper/focal-base"
dmsetup mknodes

cargo build --all --release  $features_build --target $BUILD_TARGET
strip target/$BUILD_TARGET/release/cloud-hypervisor
strip target/$BUILD_TARGET/release/vhost_user_net
strip target/$BUILD_TARGET/release/ch-remote

# Enable KSM with some reasonable parameters so that it won't take too long
# for the memory to be merged between two processes.
sudo bash -c "echo 1000000 > /sys/kernel/mm/ksm/pages_to_scan"
sudo bash -c "echo 10 > /sys/kernel/mm/ksm/sleep_millisecs"
sudo bash -c "echo 1 > /sys/kernel/mm/ksm/run"

export RUST_BACKTRACE=1
time cargo test $features_test "tests::parallel::"
RES=$?

# Cleanup device mapper images
dmsetup remove -f focal-snapshot-base
dmsetup mknodes
dmsetup remove -f focal-base
losetup -d $focal_loop_device
dmsetup remove -f bionic-snapshot-base
dmsetup mknodes
dmsetup remove -f bionic-base
losetup -d $bionic_loop_device

# Tear vhost_user_net test network down
sudo ip link del vunet-tap0
sudo ip link del vunet-tap1

exit $RES
