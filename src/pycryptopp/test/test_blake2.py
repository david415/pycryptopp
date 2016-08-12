import random, re

import unittest

from binascii import b2a_hex, a2b_hex

global VERBOSE
VERBOSE=False

from pycryptopp.hash import blake2

from pkg_resources import resource_string

def resource_string_lines(pkgname, resname):
    return split_on_newlines(resource_string(pkgname, resname))

from base64 import b32encode
def ab(x): # debuggery
    if len(x) >= 3:
        return "%s:%s" % (len(x), b32encode(x[-3:]),)
    elif len(x) == 2:
        return "%s:%s" % (len(x), b32encode(x[-2:]),)
    elif len(x) == 1:
        return "%s:%s" % (len(x), b32encode(x[-1:]),)
    elif len(x) == 0:
        return "%s:%s" % (len(x), "--empty--",)

def randstr(n):
    return ''.join(map(chr, map(random.randrange, [0]*n, [256]*n)))

h0 = a2b_hex("69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9")
h_bd = a2b_hex("b96648ba7aa4511ff31a4955b6954b01deafc334bf278b6d39a754b443b7c612")
h_5fd4 = a2b_hex("23e79edd66a570cefd1688d5705e8317064c0e5ffa583d5043a22d3d3ff1b7c2")

class BLAKE2(unittest.TestCase):
    def test_digest(self):
        empty_digest = blake2.BLAKE2().digest()
        self.failUnless(isinstance(empty_digest, str))
        self.failUnlessEqual(len(empty_digest), 32)
        self.failUnlessEqual(empty_digest, h0)

    def test_hexdigest(self):
        empty_hexdigest = blake2.BLAKE2().hexdigest()
        self.failUnlessEqual(a2b_hex(empty_hexdigest), h0)
    test_hexdigest.todo = "Not yet implemented: BLAKE2.hexdigest()."

    def test_onebyte_1(self):
        d = blake2.BLAKE2("\xbd").digest()
        self.failUnlessEqual(d, h_bd)

    def test_onebyte_2(self):
        s = blake2.BLAKE2()
        s.update("\xbd")
        d = s.digest()
        self.failUnlessEqual(d, h_bd)

    def test_update(self):
        s = blake2.BLAKE2("\x5f")
        s.update("\xd4")
        d = s.digest()
        self.failUnlessEqual(d, h_5fd4)

    def test_constructor_type_check(self):
        self.failUnlessRaises(TypeError, blake2.BLAKE2, None)

    def test_update_type_check(self):
        h = blake2.BLAKE2()
        self.failUnlessRaises(TypeError, h.update, None)

    def test_digest_twice(self):
        h = blake2.BLAKE2()
        d1 = h.digest()
        self.failUnless(isinstance(d1, str))
        d2 = h.digest()
        self.failUnlessEqual(d1, d2)

    def test_digest_then_update_fail(self):
        h = blake2.BLAKE2()
        h.digest()
        try:
            h.update("oops")
        except blake2.Error, le:
            self.failUnless("digest() has been called" in str(le), le)

    def test_chunksize(self):
        # hashes can be computed on arbitrarily-sized chunks
        problems = False
        for length in range(2, 140):
            s = "a"*length
            expected = blake2.BLAKE2(s).hexdigest()
            for a in range(0, length):
                h = blake2.BLAKE2()
                h.update(s[:a])
                h.update(s[a:])
                got = h.hexdigest()
                if got != expected:
                    problems = True
                    print len(s[:a]), len(s[a:]), len(s), got, expected
        self.failIf(problems)

    def test_recursive_different_chunksizes(self):
        """
        Test that updating a hasher with various sized inputs yields
        the expected answer. This is somewhat redundant with
        test_chunksize(), but that's okay. This one exercises some
        slightly different situations (such as finalizing a hash after
        different length inputs.) This one is recursive so that there
        is a single fixed result that we expect.
        """
        hx = blake2.BLAKE2()
        s = ''.join([ chr(c) for c in range(65) ])
        for i in range(0, 65):
            hy = blake2.BLAKE2(s[:i]).digest()
            hx.update(hy)
        for i in range(0, 65):
            hx.update(chr(0xFE))
            hx.update(s[:64])
        self.failUnlessEqual(hx.hexdigest().lower(), '05cbea97a1f5371754103a524ee0929651885abf36cb4b6e6908c4769f0f9556')


VECTS_RE=re.compile("\nLen = ([0-9]+)\nMsg = ([0-9a-f]+)\nMD = ([0-9a-f]+)")

# split_on_newlines() copied from pyutil.strutil
def split_on_newlines(s):
    """
    Splits s on all of the three newline sequences: "\r\n", "\r", or "\n".
    """
    res = []
    for x in s.split('\r\n'):
        for y in x.split('\r'):
           res.extend(y.split('\n'))
    return res

class BLAKE2Vectors(unittest.TestCase):
    def test_blake2s(self):
        return self._test_vect(resource_string('pycryptopp', 'testvectors/blake2s.txt'))

    def _test_vect(self, vects_str):
        for mo in VECTS_RE.finditer(vects_str):
            msglenbits = int(mo.group(1))
            assert msglenbits % 8 == 0
            msglen = msglenbits / 8
            msg = a2b_hex(mo.group(2))[:msglen] # The slice is necessary because NIST seems to think that "00" is a reasonable representation for the zero-length string.
            assert len(msg) == msglen, (len(msg), msglen)
            md = a2b_hex(mo.group(3))

            computed_md = blake2.BLAKE2(msg).digest()
            self.failUnlessEqual(computed_md, md)
