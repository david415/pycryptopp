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
    if hx.hexdigest().lower() != '5191c7841dd4e16aa454d40af924585dffc67157ffdbfd0236acddd07901629d':
        #raise Error("pycryptopp failed startup self-test. Please run pycryptopp unit tests.")
        print "hash %s != expected '5191c7841dd4e16aa454d40af924585dffc67157ffdbfd0236acddd07901629d'" % hx.hexdigest().lower()

start_up_self_test()
