from pycryptopp import _import_my_names

# These initializations to None are just to pacify pyflakes, which
# doesn't understand that we have to do some funky import trickery
# below in _import_my_names() in order to get sensible namespaces.
BLAKE2=None
Error=None

_import_my_names(globals(), "blake2_")

del _import_my_names

def start_up_self_test():
    hx = BLAKE2()
    s = ''.join([ chr(c) for c in range(65) ])
    for i in range(0, 65):
        hy = BLAKE2(s[:i]).digest()
        hx.update(hy)
    for i in range(0, 65):
        hx.update(chr(0xFE))
        hx.update(s[:64])
    if hx.hexdigest().lower() != '05cbea97a1f5371754103a524ee0929651885abf36cb4b6e6908c4769f0f9556':
        raise Error("pycryptopp failed startup self-test. Please run pycryptopp unit tests.")

start_up_self_test()
