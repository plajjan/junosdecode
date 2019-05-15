#!/usr/bin/python
"""JUNOS $9$ secrets encryption and decryption library

This lovely script was originally ported by matt hite (mhite@hotmail.com) from:
http://search.cpan.org/dist/Crypt-Juniper/lib/Crypt/Juniper.pm
"""
from __future__ import print_function

import argparse
import random
import unittest

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


def decrypt(encrypted):
    """Decrypt a JUNOS $9 encrypted value

    :param encrypted: the encrypted value
    :returns decrypted: returns the decrypted value
    """
    chars = encrypted.replace("$9$", '')
    first, chars = _nibble(chars, 1)
    _, chars = _nibble(chars, EXTRA[first])
    prev = first
    decrypted = ""
    while chars:
        decode = ENCODING[len(decrypted) % len(ENCODING)]
        nibble, chars = _nibble(chars, len(decode))
        gaps = []
        for i in nibble:
            g = _gap(prev, i)
            prev = i
            gaps += [g]
        decrypted += _gap_decode(gaps, decode)
    return decrypted

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

def encrypt(plaintext, salt=None):
    """Encrypts a plaintext value into a JUNOS $9 encrypted value

    :param plaintext: the plaintext value
    :param salt: an optional single character salt, one is generated if one isn't provided
    :returns encrypted: returns the encrypted value
    """
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

class TestJunosdecode(unittest.TestCase):
    """Test encryption and decryption
    """
    test_pairs = [
        ('asdf', '$9$TzF/tu1cSeQF'),
        ('12345678900987654321', '$9$Tz/Cp0BESru07-bs4o/CAtIEM8Xx-VyrZUDHmPhSyeLxbs2JUjwsP5Qz6/'),
    ]
    def test_basic(self):
        """Basic test of functionality
        """
        for plain, exp_enc in self.test_pairs:
            salt = exp_enc[3:4]
            encrypted = encrypt(plain, salt)
            self.assertEqual(encrypted, exp_enc)
            decrypted = decrypt(encrypted)
            self.assertEqual(decrypted, plain)

    def test_no_prefix(self):
        """Test that we can decrypt values without the magic $9$ prefix
        """
        decrypted = decrypt('TzF/tu1cSeQF')
        self.assertEqual(decrypted, 'asdf')

    def test_salt_randomness(self):
        """Test that the randomness of the salt is okay
        This is rather naive. We run the encryption method twenty times and
        expect at least 15 unique results, which should give some indication
        that we have random salts.
        """
        output = []
        for i in range(20):
            encrypted = encrypt('asdf')
            output.append(encrypted)

        unique = 0
        for val in output:
            if output.count(val) == 1:
                unique += 1
        self.assertGreater(unique, 15)



def main():
    """Main function
    """
    parser = argparse.ArgumentParser(description="Junos $9$ password en/decrypt script")
    parser.add_argument('--version', action='version',
                        version='%(prog)s {version}'.format(version=__version__))

    group = parser.add_mutually_exclusive_group()
    group.add_argument("-e", "--encrypt", dest="plaintext", help="encrypt plaintext")
    group.add_argument("-d", "--decrypt", dest="secret", help="decrypt secret")

    args = parser.parse_args()

    if args.secret:
        print(decrypt(args.secret))
    elif args.plaintext:
        print(encrypt(args.plaintext))

if __name__ == "__main__":
    main()
