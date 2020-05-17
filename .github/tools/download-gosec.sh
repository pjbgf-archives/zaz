#!/usr/bin/env bash
set -e
set -o pipefail

TARGET_FOLDER="$(pwd)/build/tools"
PACKAGE_FILENAME="gosec_2.2.0_linux_amd64.tar.gz"
PACKAGE_CHECKSUM="e56df18f4a7706b47088fe5652c699b3370884d6662ba304e62f57bb126b399c"
PACKAGE_FOLDER_NAME="gosec"
PACKAGE_EXECUTABLE="$TARGET_FOLDER/$PACKAGE_FOLDER_NAME/$PACKAGE_FOLDER_NAME"
PACKAGE_DOWNLOAD_URL=https://github.com/securego/gosec/releases/download/v2.2.0/$PACKAGE_FILENAME

if [ ! -f "$PACKAGE_EXECUTABLE" ]; then
    wget $PACKAGE_DOWNLOAD_URL -O "/tmp/$PACKAGE_FILENAME"
    echo "$PACKAGE_CHECKSUM /tmp/$PACKAGE_FILENAME" | sha256sum -c -

    TMP_DIR=$(mktemp -d -t tmp-XXXXXXXXXX)
    mkdir -p "$TARGET_FOLDER/$PACKAGE_FOLDER_NAME"

    tar -C "$TMP_DIR" -xzf "/tmp/$PACKAGE_FILENAME"
    mv "$TMP_DIR/$PACKAGE_FOLDER_NAME" "$TARGET_FOLDER/$PACKAGE_FOLDER_NAME/"
    rm -f -d -r "$TMP_DIR"
    rm "/tmp/$PACKAGE_FILENAME"
fi