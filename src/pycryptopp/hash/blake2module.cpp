/**
 * blake2module.cpp -- Python wrappers around Crypto++'s SHA-256
 */

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#if (PY_VERSION_HEX < 0x02050000)
typedef int Py_ssize_t;
#endif

#include <assert.h>

/* from Crypto++ */
#ifdef DISABLE_EMBEDDED_CRYPTOPP
#include <cryptopp/blake2.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#else
#include <src-cryptopp/blake2.h>
#include <src-cryptopp/hex.h>
#include <src-cryptopp/filters.h>
#endif

static const char*const blake2___doc__ = "_blake2 hash function";

static PyObject *blake2_error;

typedef struct {
    PyObject_HEAD

    /* internal */
    CryptoPP::BLAKE2* h;
    PyStringObject* digest;
} BLAKE2;

PyDoc_STRVAR(BLAKE2__doc__,
"a BLAKE2 hash object\n\
Its constructor takes an optional string, which has the same effect as\n\
calling .update() with that string.");

static PyObject *
BLAKE2_update(BLAKE2* self, PyObject* msgobj) {
    if (self->digest)
        return PyErr_Format(blake2_error, "Precondition violation: once .digest() has been called you are required to never call .update() again.");

    const char *msg;
    Py_ssize_t msgsize;
    if (PyString_AsStringAndSize(msgobj, const_cast<char**>(&msg), &msgsize))
        return NULL;
    self->h->Update(reinterpret_cast<const byte*>(msg), msgsize);
    Py_RETURN_NONE;
}

PyDoc_STRVAR(BLAKE2_update__doc__,
"Update the hash object with the string msg. Repeated calls are equivalent to\n\
a single call with the concatenation of all the messages.");

static PyObject *
BLAKE2_digest(BLAKE2* self, PyObject* dummy) {
    if (!self->digest) {
        assert (self->h);
        self->digest = reinterpret_cast<PyStringObject*>(PyString_FromStringAndSize(NULL, self->h->DigestSize()));
        if (!self->digest)
            return NULL;
        self->h->Final(reinterpret_cast<byte*>(PyString_AS_STRING(self->digest)));
    }

    Py_INCREF(self->digest);
    return reinterpret_cast<PyObject*>(self->digest);
}

PyDoc_STRVAR(BLAKE2_digest__doc__,
"Return the binary digest of the messages that were passed to the update()\n\
method (including the initial message if any).");

static PyObject *
BLAKE2_hexdigest(BLAKE2* self, PyObject* dummy) {
    PyObject* digest = BLAKE2_digest(self, NULL);
    if (!digest)
        return NULL;
    Py_ssize_t dsize = PyString_GET_SIZE(digest);
    PyStringObject* hexdigest = reinterpret_cast<PyStringObject*>(PyString_FromStringAndSize(NULL, dsize*2));
    CryptoPP::ArraySink* as = new CryptoPP::ArraySink(reinterpret_cast<byte*>(PyString_AS_STRING(hexdigest)), dsize*2);
    CryptoPP::HexEncoder enc;
    enc.Attach(as);
    enc.Put(reinterpret_cast<const byte*>(PyString_AS_STRING(digest)), static_cast<size_t>(dsize));
    Py_DECREF(digest); digest = NULL;

    return reinterpret_cast<PyObject*>(hexdigest);
}

PyDoc_STRVAR(BLAKE2_hexdigest__doc__,
"Return the hex-encoded digest of the messages that were passed to the update()\n\
method (including the initial message if any).");

static PyMethodDef BLAKE2_methods[] = {
    {"update", reinterpret_cast<PyCFunction>(BLAKE2_update), METH_O, BLAKE2_update__doc__},
    {"digest", reinterpret_cast<PyCFunction>(BLAKE2_digest), METH_NOARGS, BLAKE2_digest__doc__},
    {"hexdigest", reinterpret_cast<PyCFunction>(BLAKE2_hexdigest), METH_NOARGS, BLAKE2_hexdigest__doc__},
    {NULL},
};

static PyObject *
BLAKE2_new(PyTypeObject* type, PyObject *args, PyObject *kwdict) {
    BLAKE2* self = reinterpret_cast<BLAKE2*>(type->tp_alloc(type, 0));
    if (!self)
        return NULL;
    self->h = new CryptoPP::BLAKE2();
    if (!self->h)
        return PyErr_NoMemory();
    self->digest = NULL;
    return reinterpret_cast<PyObject*>(self);
}

static void
BLAKE2_dealloc(BLAKE2* self) {
    Py_XDECREF(self->digest);
    delete self->h;
    self->ob_type->tp_free((PyObject*)self);
}

static int
BLAKE2_init(PyObject* self, PyObject *args, PyObject *kwdict) {
    static const char *kwlist[] = { "msg", NULL };
    const char *msg = NULL;
    Py_ssize_t msgsize = 0;
    if (!PyArg_ParseTupleAndKeywords(args, kwdict, "|t#", const_cast<char**>(kwlist), &msg, &msgsize))
        return -1;

    if (msg)
        reinterpret_cast<BLAKE2*>(self)->h->Update(reinterpret_cast<const byte*>(msg), msgsize);
    return 0;
}

static PyTypeObject BLAKE2_type = {
    PyObject_HEAD_INIT(NULL)
    0,                         /*ob_size*/
    "_blake2.BLAKE2", /*tp_name*/
    sizeof(BLAKE2),             /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    reinterpret_cast<destructor>(BLAKE2_dealloc), /*tp_dealloc*/
    0,                         /*tp_print*/
    0,                         /*tp_getattr*/
    0,                         /*tp_setattr*/
    0,                         /*tp_compare*/
    0,                         /*tp_repr*/
    0,                         /*tp_as_number*/
    0,                         /*tp_as_sequence*/
    0,                         /*tp_as_mapping*/
    0,                         /*tp_hash */
    0,                         /*tp_call*/
    0,                         /*tp_str*/
    0,                         /*tp_getattro*/
    0,                         /*tp_setattro*/
    0,                         /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
    BLAKE2__doc__,           /* tp_doc */
    0,		               /* tp_traverse */
    0,		               /* tp_clear */
    0,		               /* tp_richcompare */
    0,		               /* tp_weaklistoffset */
    0,		               /* tp_iter */
    0,		               /* tp_iternext */
    BLAKE2_methods,      /* tp_methods */
    0,                         /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    //reinterpret_cast<initproc>(BLAKE2_init),               /* tp_init */
    BLAKE2_init,               /* tp_init */
    0,                         /* tp_alloc */
    BLAKE2_new,                /* tp_new */
};

void
init_blake2(PyObject* module) {
    if (PyType_Ready(&BLAKE2_type) < 0)
        return;
    Py_INCREF(&BLAKE2_type);
    PyModule_AddObject(module, "blake2_BLAKE2", (PyObject *)&BLAKE2_type);

    blake2_error = PyErr_NewException(const_cast<char*>("_blake2.Error"), NULL, NULL);
    PyModule_AddObject(module, "blake2_Error", blake2_error);

    PyModule_AddStringConstant(module, "blake2___doc__", const_cast<char*>(blake2___doc__));
}
