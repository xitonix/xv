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
echo "plain text" | xv [enc]
cat file.txt | xv [enc] > enc.txt
cat file.jpg | xv [enc] -e raw > enc.jpg
```

Encryption using a key

```shell
xv [enc] "plain text" --key "encryption key of at least 32 characters"
echo "plain text" | xv [enc] --key "encryption key of at least 32 characters"
```

>NOTE: `enc` command will be executed by default if not set explicitly.

Decryption using the key file

```shell
xv dec "encrypted text"
echo "encrypted text" | xv dec
cat encrypted.txt | xv dec > decrypted.txt
cat encrypted.jpg | xv dec -e raw > decrypted.jpg
```

Decryption using a key

```shell
xv dec "encrypted text" --key "encryption key of at least 32 characters"
echo "encrypted text" | xv dec --key "encryption key of at least 32 characters"
```