/*
 * Copyright (C) 2014 Björn Edström <be@bjrn.se>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

 /*
 * This product includes software developed by the OpenSSL Project for
 * use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 */

#define _VERSION "0.0.0"

#include "Python.h"
#include "structmember.h"
#include "aes-gcm-wrapper.h"

typedef struct {
	PyObject_HEAD
	PyObject *module;
	AES_GCM_CTX *enc_ctx;
} AES_GCM_Encrypt_object;


typedef struct {
	PyObject_HEAD
	PyObject *module;
	AES_GCM_CTX *dec_ctx;
} AES_GCM_Decrypt_object;


struct module_state {
	PyObject *AuthenticationError;
};


#if PY_MAJOR_VERSION >= 3
#define GETSTATE(m) ((struct module_state*)PyModule_GetState(m))
#else
#define GETSTATE(m) (&_state)
static struct module_state _state;
#endif


static int translate_error_code(PyObject *m, int code)
{
	struct module_state *st = GETSTATE(m);
	char tmp[16];

	switch (code) {

	case AES_GCM_ERR_INVALID_KEY_SIZE:
		PyErr_SetString(PyExc_ValueError, "key size must be 128, 192 or 256 bits");
		break;
	case AES_GCM_ERR_INVALID_KEY:
		PyErr_SetString(PyExc_ValueError, "invalid key");
		break;
	case AES_GCM_ERR_INVALID_IV:
		PyErr_SetString(PyExc_ValueError, "invalid iv");
		break;
	case AES_GCM_ERR_INVALID_TAG:
		PyErr_SetString(PyExc_ValueError, "invalid tag");
		break;
	case AES_GCM_ERR_INVALID_CTX:
		PyErr_SetString(PyExc_ValueError, "invalid context");
		break;

	case AES_GCM_ERR_ORDERING:
		PyErr_SetString(PyExc_AssertionError,
				"aes gcm functions called in the wrong order");
		break;

	case AES_GCM_ERR_ENCRYPT:
	case AES_GCM_ERR_DECRYPT:
	case AES_GCM_ERR_AAD:
		PyErr_SetString(PyExc_IOError, "internal crypto problem");
		break;

	case AES_GCM_ERR_AUTH:
		PyErr_SetString(st->AuthenticationError, "authentication failed");
		break;

	default:
		sprintf(tmp, "code: %d", code);
		PyErr_SetString(PyExc_Exception, tmp);
		break;
	}

	return 0;
}



/*
 * Encrypt context functions.
 */

PyDoc_STRVAR(AES_GCM_Encrypt_update_aad__doc__,
	     "Update Additional Authenticated Data (AAD).");

static PyObject *
AES_GCM_Encrypt_update_aad(AES_GCM_Encrypt_object *self, PyObject *args)
{
	unsigned char *aad = NULL;
	size_t aad_size = 0;

	if (!PyArg_ParseTuple(args, "s#", &aad, &aad_size))
		return NULL;

	int ret = aes_gcm_update_aad(self->enc_ctx, aad_size, aad);

	if (ret != 0) {
		translate_error_code(self->module, ret);
		return NULL;
	}

	Py_INCREF(Py_None);
	return Py_None;
}

PyDoc_STRVAR(AES_GCM_Encrypt_finalize__doc__,
	     "Finalize encryption and return tag.");

static PyObject *
AES_GCM_Encrypt_finalize(AES_GCM_Encrypt_object *self, PyObject *args)
{
	unsigned char tag[AES_GCM_MAX_TAG_SIZE];
	int tag_size = AES_GCM_MAX_TAG_SIZE;

	if (!PyArg_ParseTuple(args, "|i", &tag_size))
		return NULL;

	int ret = aes_gcm_encrypt_finalize(self->enc_ctx, tag_size, tag);

	if (ret != 0) {
		translate_error_code(self->module, ret);
		return NULL;
	}

	return PyBytes_FromStringAndSize((const char *)tag, tag_size);
}

PyDoc_STRVAR(AES_GCM_Encrypt_encrypt__doc__,
	     "Encrypt string.");

static PyObject *
AES_GCM_Encrypt_encrypt(AES_GCM_Encrypt_object *self, PyObject *args)
{
	unsigned char *pt = NULL, *ct = NULL;
	size_t pt_size = 0;

	if (!PyArg_ParseTuple(args, "s#", &pt, &pt_size))
		return NULL;

	ct = malloc(pt_size);

	int ret = aes_gcm_encrypt_update(self->enc_ctx, pt_size, pt, ct);
	if (ret != 0) {
		translate_error_code(self->module, ret);
		return NULL;
	}

	PyObject *py_ct = PyBytes_FromStringAndSize((const char *)ct, pt_size);

	free(ct);

	return py_ct;
}

PyDoc_STRVAR(AES_GCM_Encrypt_init__doc__,
	     "Init this object's state.");

static PyObject *
AES_GCM_Encrypt_init(AES_GCM_Encrypt_object *self, PyObject *args)
{
	int key_size_bits;
	unsigned char *key = NULL, *iv = NULL;
	size_t key_len = 0, iv_len = 0;

	if (!PyArg_ParseTuple(args, "s#s#", &key, &key_len, &iv, &iv_len))
		return NULL;

	key_size_bits = key_len * 8;

	int ret = aes_gcm_init_encrypt(self->enc_ctx, key_size_bits, key, iv_len, iv);
	if (ret != 0) {
		translate_error_code(self->module, ret);
		return NULL;
	}

	Py_INCREF(Py_None);
	return Py_None;
}


/*
 * Decrypt context functions.
 */

PyDoc_STRVAR(AES_GCM_Decrypt_update_aad__doc__,
	     "Update Additional Authenticated Data (AAD).");

static PyObject *
AES_GCM_Decrypt_update_aad(AES_GCM_Decrypt_object *self, PyObject *args)
{
	unsigned char *aad = NULL;
	size_t aad_size = 0;

	if (!PyArg_ParseTuple(args, "s#", &aad, &aad_size))
		return NULL;

	int ret = aes_gcm_update_aad(self->dec_ctx, aad_size, aad);

	if (ret != 0) {
		translate_error_code(self->module, ret);
		return NULL;
	}

	Py_INCREF(Py_None);
	return Py_None;
}

PyDoc_STRVAR(AES_GCM_Decrypt_finalize__doc__,
	     "Finalize decryption and verify tag.\n\nWill raise AuthenticationError if auth failed.");

static PyObject *
AES_GCM_Decrypt_finalize(AES_GCM_Decrypt_object *self, PyObject *args)
{
	int verified;
	int ret = aes_gcm_decrypt_finalize(self->dec_ctx, &verified);
	if (ret > 0) {
		translate_error_code(self->module, ret);
		return NULL;
	}

	// Lets be explicit with this.
	if (!verified) {
		translate_error_code(self->module, AES_GCM_ERR_AUTH);
		return NULL;
	}

	Py_INCREF(Py_True);
	return Py_True;
}

PyDoc_STRVAR(AES_GCM_Decrypt_decrypt__doc__,
	     "Decrypt string.");

static PyObject *
AES_GCM_Decrypt_decrypt(AES_GCM_Decrypt_object *self, PyObject *args)
{
	unsigned char *pt = NULL, *ct = NULL;
	size_t ct_size = 0;

	if (!PyArg_ParseTuple(args, "s#", &ct, &ct_size))
		return NULL;

	pt = malloc(ct_size);

	int ret = aes_gcm_decrypt_update(self->dec_ctx, ct_size, ct, pt);
	if (ret != 0) {
		translate_error_code(self->module, ret);
		return NULL;
	}

	PyObject *py_pt = PyBytes_FromStringAndSize((const char *)pt, ct_size);

	free(pt);

	return py_pt;
}

PyDoc_STRVAR(AES_GCM_Decrypt_init__doc__,
	     "Init this object's state.");

static PyObject *
AES_GCM_Decrypt_init(AES_GCM_Decrypt_object *self, PyObject *args)
{
	int key_size_bits;
	unsigned char *key = NULL, *iv = NULL, *tag = NULL;
	size_t key_len = 0, iv_len = 0, tag_len = 0;

	if (!PyArg_ParseTuple(args, "s#s#s#", &key, &key_len, &iv, &iv_len, &tag, &tag_len))
		return NULL;

	key_size_bits = key_len * 8;

	int ret = aes_gcm_init_decrypt(self->dec_ctx, key_size_bits, key, iv_len, iv, tag_len, tag);
	if (ret != 0) {
		translate_error_code(self->module, ret);
		return NULL;
	}

	Py_INCREF(Py_None);
	return Py_None;
}


/*
 *
 */


static void
AES_GCM_Encrypt_dealloc(PyObject *ptr)
{
	AES_GCM_Encrypt_object *obj = (AES_GCM_Encrypt_object *)ptr;
	aes_gcm_destroy(obj->enc_ctx);

	PyObject_Del(ptr);
}


static void
AES_GCM_Decrypt_dealloc(PyObject *ptr)
{
	AES_GCM_Decrypt_object *obj = (AES_GCM_Decrypt_object *)ptr;
	aes_gcm_destroy(obj->dec_ctx);

	PyObject_Del(ptr);
}

static PyMethodDef AES_GCM_Encrypt_methods[] = {
	{"init"  ,    (PyCFunction)AES_GCM_Encrypt_init,      METH_VARARGS, AES_GCM_Encrypt_init__doc__},
	{"update_aad", (PyCFunction)AES_GCM_Encrypt_update_aad,      METH_VARARGS, AES_GCM_Encrypt_update_aad__doc__},
	{"encrypt",   (PyCFunction)AES_GCM_Encrypt_encrypt,   METH_VARARGS, AES_GCM_Encrypt_encrypt__doc__},
	{"finalize",  (PyCFunction)AES_GCM_Encrypt_finalize,  METH_VARARGS, AES_GCM_Encrypt_finalize__doc__},
	{NULL,        NULL}         /* sentinel */
};


static PyGetSetDef AES_GCM_Encrypt_getseters[] = {
	{NULL}  /* Sentinel */
};


static PyMemberDef AES_GCM_Encrypt_members[] = {
	{NULL}  /* Sentinel */
};


static PyTypeObject AES_GCM_Encrypt_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"_aesgcm.AES_GCM_Encrypt",    /*tp_name*/
	sizeof(AES_GCM_Encrypt_object),  /*tp_size*/
	0,                  /*tp_itemsize*/
	/* methods */
	AES_GCM_Encrypt_dealloc,        /*tp_dealloc*/
	0,                  /*tp_print*/
	0,                  /*tp_getattr*/
	0,                  /*tp_setattr*/
	0,                  /*tp_compare*/
	0,                  /*tp_repr*/
	0,                  /*tp_as_number*/
	0,                  /*tp_as_sequence*/
	0,                  /*tp_as_mapping*/
	0,                  /*tp_hash*/
	0,                  /*tp_call*/
	0,                  /*tp_str*/
	0,                  /*tp_getattro*/
	0,                  /*tp_setattro*/
	0,                  /*tp_as_buffer*/
	Py_TPFLAGS_DEFAULT, /*tp_flags*/
	0,                  /*tp_doc*/
	0,                  /*tp_traverse*/
	0,                  /*tp_clear*/
	0,                  /*tp_richcompare*/
	0,                  /*tp_weaklistoffset*/
	0,                  /*tp_iter*/
	0,                  /*tp_iternext*/
	AES_GCM_Encrypt_methods,        /* tp_methods */
	AES_GCM_Encrypt_members,        /* tp_members */
	AES_GCM_Encrypt_getseters,      /* tp_getset */
};



static PyMethodDef AES_GCM_Decrypt_methods[] = {
	{"init"  ,    (PyCFunction)AES_GCM_Decrypt_init,      METH_VARARGS, AES_GCM_Decrypt_init__doc__},
	{"update_aad", (PyCFunction)AES_GCM_Decrypt_update_aad,METH_VARARGS, AES_GCM_Decrypt_update_aad__doc__},
	{"decrypt",   (PyCFunction)AES_GCM_Decrypt_decrypt,   METH_VARARGS, AES_GCM_Decrypt_decrypt__doc__},
	{"finalize",  (PyCFunction)AES_GCM_Decrypt_finalize,  METH_NOARGS, AES_GCM_Decrypt_finalize__doc__},
	{NULL,        NULL}         /* sentinel */
};


static PyGetSetDef AES_GCM_Decrypt_getseters[] = {
	{NULL}  /* Sentinel */
};


static PyMemberDef AES_GCM_Decrypt_members[] = {
	{NULL}  /* Sentinel */
};


static PyTypeObject AES_GCM_Decrypt_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"_aesgcm.AES_GCM_Decrypt",    /*tp_name*/
	sizeof(AES_GCM_Decrypt_object),  /*tp_size*/
	0,                  /*tp_itemsize*/
	/* methods */
	AES_GCM_Decrypt_dealloc,        /*tp_dealloc*/
	0,                  /*tp_print*/
	0,                  /*tp_getattr*/
	0,                  /*tp_setattr*/
	0,                  /*tp_compare*/
	0,                  /*tp_repr*/
	0,                  /*tp_as_number*/
	0,                  /*tp_as_sequence*/
	0,                  /*tp_as_mapping*/
	0,                  /*tp_hash*/
	0,                  /*tp_call*/
	0,                  /*tp_str*/
	0,                  /*tp_getattro*/
	0,                  /*tp_setattro*/
	0,                  /*tp_as_buffer*/
	Py_TPFLAGS_DEFAULT, /*tp_flags*/
	0,                  /*tp_doc*/
	0,                  /*tp_traverse*/
	0,                  /*tp_clear*/
	0,                  /*tp_richcompare*/
	0,                  /*tp_weaklistoffset*/
	0,                  /*tp_iter*/
	0,                  /*tp_iternext*/
	AES_GCM_Decrypt_methods,        /* tp_methods */
	AES_GCM_Decrypt_members,        /* tp_members */
	AES_GCM_Decrypt_getseters,      /* tp_getset */
};



static AES_GCM_Encrypt_object *
new_AES_GCM_Encrypt_object(PyObject *module)
{
	AES_GCM_Encrypt_object *obj = (AES_GCM_Encrypt_object *)
		PyObject_New(AES_GCM_Encrypt_object, &AES_GCM_Encrypt_type);

	if (!obj) {
		return NULL;
	}

	obj->module = module;
	obj->enc_ctx = aes_gcm_create();

	if (obj->enc_ctx == NULL) {
		return NULL;
	}

	return obj;
}


static AES_GCM_Decrypt_object *
new_AES_GCM_Decrypt_object(PyObject *module)
{
	AES_GCM_Decrypt_object *obj = (AES_GCM_Decrypt_object *)
		PyObject_New(AES_GCM_Decrypt_object, &AES_GCM_Decrypt_type);

	if (!obj) {
		return NULL;
	}

	obj->module = module;
	obj->dec_ctx = aes_gcm_create();

	if (obj->dec_ctx == NULL) {
		return NULL;
	}

	return obj;
}




/*
 * Create new objects...
 */

PyDoc_STRVAR(AES_GCM_Encrypt_new__doc__,
	     "Return a new encryption object.");

static PyObject *
AES_GCM_Encrypt_new(PyObject *self, PyObject *args, PyObject *kwdict)
{
	AES_GCM_Encrypt_object *new;

	if ((new = new_AES_GCM_Encrypt_object(self)) == NULL)
		return NULL;

	if (PyErr_Occurred()) {
		Py_DECREF(new);
		return NULL;
	}

	return (PyObject *)new;
}


PyDoc_STRVAR(AES_GCM_Decrypt_new__doc__,
	     "Return a new decryption object.");

static PyObject *
AES_GCM_Decrypt_new(PyObject *self, PyObject *args, PyObject *kwdict)
{
	AES_GCM_Decrypt_object *new;

	if ((new = new_AES_GCM_Decrypt_object(self)) == NULL)
		return NULL;

	if (PyErr_Occurred()) {
		Py_DECREF(new);
		return NULL;
	}

	return (PyObject *)new;
}


static struct PyMethodDef AES_GCM_functions[] = {
	{"AES_GCM_Encrypt", (PyCFunction)AES_GCM_Encrypt_new, METH_NOARGS, AES_GCM_Encrypt_new__doc__},
	{"AES_GCM_Decrypt", (PyCFunction)AES_GCM_Decrypt_new, METH_NOARGS, AES_GCM_Decrypt_new__doc__},
	{NULL,      NULL}            /* Sentinel */
};


//PyMODINIT_FUNC
//initaesgcm(void)
#if PY_MAJOR_VERSION >= 3

static int aesgcm_traverse(PyObject *m, visitproc visit, void *arg) {
    Py_VISIT(GETSTATE(m)->AuthenticationError);
    return 0;
}

static int aesgcm_clear(PyObject *m) {
    Py_CLEAR(GETSTATE(m)->AuthenticationError);
    return 0;
}


static struct PyModuleDef moduledef = {
        PyModuleDef_HEAD_INIT,
        "_aesgcm",
        NULL,
        sizeof(struct module_state),
        AES_GCM_functions,
        NULL,
        aesgcm_traverse,
        aesgcm_clear,
        NULL
};

#define INITERROR return NULL

PyObject *
PyInit__aesgcm(void)

#else
#define INITERROR return

void
init_aesgcm(void)
#endif
{
#if PY_MAJOR_VERSION >= 3
	PyObject *module = PyModule_Create(&moduledef);
#else
	PyObject *module = Py_InitModule3("_aesgcm", AES_GCM_functions, "Module for AES-GCM crypto.");
#endif

	if (module == NULL)
		INITERROR;
	struct module_state *st = GETSTATE(module);

	// TODO (bjorn): Do these have to go to state???
	Py_TYPE(&AES_GCM_Encrypt_type) = &PyType_Type;
	if (PyType_Ready(&AES_GCM_Encrypt_type) < 0) {
		INITERROR;
	}

	Py_TYPE(&AES_GCM_Decrypt_type) = &PyType_Type;
	if (PyType_Ready(&AES_GCM_Decrypt_type) < 0) {
		INITERROR;
	}

	st->AuthenticationError = PyErr_NewException("_aesgcm.AuthenticationError", NULL, NULL);
	if (st->AuthenticationError == NULL) {
		Py_DECREF(module);
		INITERROR;
	}
	Py_INCREF(st->AuthenticationError);
	PyModule_AddObject(module, "AuthenticationError", st->AuthenticationError);

	{
#if PY_MAJOR_VERSION < 3
		PyObject *s = PyString_FromString(_VERSION);
#else
		PyObject *s = PyUnicode_FromString(_VERSION);
#endif
		PyObject *dict = PyModule_GetDict(module);
		PyDict_SetItemString(dict, "__version__", s);
		Py_DECREF(s);
	}

#if PY_MAJOR_VERSION >= 3
	return module;
#endif
}
