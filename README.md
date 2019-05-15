# JUNOS $9$ secrets encrypt/decrypt script
A simple library to encrypt and decrypt JUNOS $9 encrypted secrets. It can also
be used as a standalone script.

The code is relatively PEP8 conformant and has a small test suite.

## Usage
```
$ python junosdecode.py
usage: junosdecode.py [-h] [-v] [-e PLAINTEXT | -d SECRET]

Junos $9$ password en/decrypt script

optional arguments:
  -h, --help            show this help message and exit
  -v, --version         show program's version number and exit
  -e PLAINTEXT, --encrypt PLAINTEXT
                        encrypt plaintext
  -d SECRET, --decrypt SECRET
                        decrypt secret

```

## Examples
```
$ python junosdecode.py -e 'hello'
$9$lateMXVb2JGi7-Dk

$ python junosdecode.py -d '$9$lateMXVb2JGi7-Dk'
decrypted version: hello
```


## Contributors
* Matt Hine, who originally ported this from Perl
* Minsuk Song, who added encryption functionality (in addition to the existing decryption functionality)
* Kristian Larsson, who cleaned it up a bit, added tests etc
