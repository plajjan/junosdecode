# Junos $9$ secrets encrypt/decrypt script

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
Junos $9$ secrets en/decrypter
python version by matt hite/min song
original perl version by kevin brintnall

plaintext version: hello
encrypted version: $9$lateMXVb2JGi7-Dk

$ python junosdecode.py -d '$9$lateMXVb2JGi7-Dk'
Junos $9$ secrets en/decrypter
python version by matt hite/min song
original perl version by kevin brintnall

encrypted version: $9$lateMXVb2JGi7-Dk
decrypted version: hello
```
