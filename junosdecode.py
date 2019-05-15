#!/usr/bin/python
"""JUNOS $9$ secrets encryption and decryption library

This lovely script was originally ported by matt hite (mhite@hotmail.com) from:
http://search.cpan.org/dist/Crypt-Juniper/lib/Crypt/Juniper.pm
"""
from __future__ import print_function

import sys
import argparse
import random

__author__ = 'Matt Hite, Minsuk Song, Kristian Larsson'
__credits__ = ['Matt Hite, Minsuk Song', 'Minsuk Song, Kristian Larsson']
__version__ = '1.0.1'
__maintainer__ = 'Kristian Larsson'
__email__ = 'kristian@spritelink.net'
__status__ = 'Development'


# globals
MAGIC = "$9$"
FAMILY = ["QzF3n6/9CAtpu0O", "B1IREhcSyrleKvMW8LXx", "7N-dVbwsY2g4oaJZGUDj", "iHkq.mPf5T"]

def _compute_extra(family):
    extra = dict()
    for x, item in enumerate(family):
        for c in item:
            extra[c] = 3 - x
    return extra

EXTRA = _compute_extra(FAMILY)

## forward and reverse dictionaries
NUM_ALPHA = [x for x in "".join(FAMILY)]
ALPHA_NUM = {NUM_ALPHA[x]: x for x in range(0, len(NUM_ALPHA))}

## encoding moduli by position
ENCODING = [[1, 4, 32], [1, 16, 32], [1, 8, 32], [1, 64], [1, 32], [1, 4, 16, 128], [1, 32, 64]]


def _nibble(cref, length):
    nib = cref[0:length]
    rest = cref[length:]
    if len(nib) != length:
        raise ValueError("Ran out of characters: hit '%s', expecting %s chars" % (nib, length))
    return nib, rest


def _gap(c1, c2):
    return (ALPHA_NUM[str(c2)] - ALPHA_NUM[str(c1)]) % (len(NUM_ALPHA)) - 1


def _gap_decode(gaps, dec):
    num = 0
    if len(gaps) != len(dec):
        raise ValueError("Nibble and decode size not the same!")
    for x in range(0, len(gaps)):
        num += gaps[x] * dec[x]
    return chr(num % 256)


def juniper_decrypt(crypt):
    chars = crypt.split("$9$", 1)[1]
    first, chars = _nibble(chars, 1)
    toss, chars = _nibble(chars, EXTRA[first])
    prev = first
    decrypt = ""
    while chars:
        decode = ENCODING[len(decrypt) % len(ENCODING)]
        nibble, chars = _nibble(chars, len(decode))
        gaps = []
        for i in nibble:
            g = _gap(prev, i)
            prev = i
            gaps += [g]
        decrypt += _gap_decode(gaps, decode)
    return decrypt

def _reverse(my_list):
    new_list = list(my_list)
    new_list.reverse()
    return new_list

def _gap_encode(pc, prev, encode):
    _ord = ord(pc)

    crypt = ''
    gaps = []
    for mod in _reverse(encode):
        gaps.insert(0, int(_ord/mod))
        _ord %= mod

    for gap in gaps:
        gap += ALPHA_NUM[prev] + 1
        prev = NUM_ALPHA[gap % len(NUM_ALPHA)]
        crypt += prev

    return crypt

def _randc(cnt=0):
    ret = ""
    for _ in range(cnt):
        ret += NUM_ALPHA[random.randrange(len(NUM_ALPHA))]
    return ret

def juniper_encrypt(plaintext, salt=None):
    if salt is None:
        salt = _randc(1)
    rand = _randc(EXTRA[salt])

    pos = 0
    prev = salt
    crypt = MAGIC + salt + rand

    for x in plaintext:
        encode = ENCODING[pos % len(ENCODING)]
        crypt += _gap_encode(x, prev, encode)
        prev = crypt[-1]
        pos += 1

    return crypt


def main():
    parser = argparse.ArgumentParser(description="Junos $9$ password en/decrypt script")
    parser.add_argument("-v", "--version", action="version", version="%(prog)s 1.01")

    group = parser.add_mutually_exclusive_group()
    group.add_argument("-e", "--encrypt", dest="plaintext", help="encrypt plaintext")
    group.add_argument("-d", "--decrypt", dest="secret", help="decrypt secret")

    args = parser.parse_args()

    if args.secret:
        print(juniper_decrypt(args.secret))
    elif args.plaintext:
        print(juniper_encrypt(args.plaintext))

if __name__ == "__main__":
    main()
