#!/bin/bash

VERSION=$(git tag --sort=-version:refname | head -n1)
TARGET=$GOBIN
BINARY="xv"
if [[ x"${GOBIN}" == "x"  ]]; then
  TARGET='/usr/local/bin'
fi
echo "Installing $BINARY $VERSION into $TARGET"
FILE="$BINARY-darwin-$(go env GOARCH)-$VERSION.tar.gz"
URL="https://github.com/xitonix/$BINARY/releases/download/$VERSION/$FILE"
echo "Downloading $URL"
curl -sL "$URL" > "$FILE"
echo "Extracting $FILE"
tar -zxf "$FILE" -C "$TARGET/"
echo "Deleting $FILE"
rm -rf "$FILE"
chmod +x "$TARGET/$BINARY"
$BINARY --version