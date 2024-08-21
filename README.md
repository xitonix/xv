# xv
A CLI tool to encrypt & decrypt data using AES-256 algorithm with command piping support.

## Installation

`go get -u github.com/xitonix/xv`

OR

Download the binary from the [release](https://github.com/xitonix/xv/releases) page.

OR

Clone the repo and run `install.sh`
- If `GOBIN` is not set, the tool will be installed in `/usr/local/bin`

## Usage

### Setup key file (Optional)
```shell
xv init <Encryption Key> # Key MUST be at least 32 characters
```

#### Examples

Encryption using the key file

```shell
xv [enc] "plain text"
echo "plain text" | xv [enc]
xv [enc] "plain text"
xv [enc] "plain text" --encoder hex
echo "plain text" | xv [enc]
cat file.txt | xv [enc] > enc.txt
cat file.jpg | xv [enc] -e raw > enc.jpg
```

Encryption using a key

```shell
xv [enc] "plain text" --key "encryption key of at least 32 characters"
echo "plain text" | xv [enc] --key "encryption key of at least 32 characters"
```

Decryption using the key file

```shell

xv dec "Base 64 encoded text of AES-256 encrypted data"
echo "Base 64 encoded text of AES-256 encrypted data" | xv dec

echo "Hex encoded text of AES-256 encrypted data" | xv dec --decoder hex

cat base_64_encoded_encrypted.txt | xv dec > decrypted.txt
cat raw_encrypted.jpg | xv dec -d raw > decrypted.jpg
```

Decryption using a key

```shell
xv dec "Base 64 encoded text of AES-256 encrypted data" --key "encryption key of at least 32 characters"
echo "Base 64 encoded text of AES-256 encrypted data" | xv dec --key "encryption key of at least 32 characters"
```

**Notes**
> - `enc` command will be executed by default if not set explicitly.
> - If encoder/decoder is not specified explicitly, `base 64` will be selected by default.