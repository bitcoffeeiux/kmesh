/*
 * Copyright 2024 The Kmesh Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package mtlsproxy

// #cgo LDFLAGS: -lssl -lcrypto
// #include <openssl/ssl.h>
// #include <openssl/err.h>
// #include <openssl/evp.h>
/*

struct ssl_content {
	SSL_CTX *ctx;
	SSL *ssl;
};

SSL_CTX *openssl_create_ctx(int role)
{
	SSL_CTX *ctx;

	// init openssl library
	SSL_load_error_strings();
	SSL_library_init();
	OpenSSL_add_all_algorithms();

	// create openssl context
	if (role == 0) { // client
		ctx = SSL_CTX_new(SSLv23_client_method());
	} else { // server
		ctx = SSL_CTX_new(SSLv23_server_method());
	}
	if (ctx == NULL) {
		ERR_print_errors_fp(stderr);
		return NULL;
	}

	return ctx;
}

void openssl_destroy_ctx(SSL_CTX *ctx)
{
	SSL_CTX_free(ctx);
}

SSL *openssl_create_ssl(SSL_CTX *ctx)
{
	SSL *ssl;

	// create SSL object
	ssl = SSL_new(ctx);
	if (!ssl) {
		ERR_print_errors_fp(stderr);
		return NULL;
	}

	return ssl;
}

SSL *openssl_destroy_ssl(SSL *ssl)
{
	SSL_shutdown(ssl);
	SSL_free(ssl);
}

struct ssl_content * do_ssl(int socketfd, char *crt, char *privKey, int role)
{
	struct ssl_content *ssl_content = (struct ssl_content *)malloc(sizeof(struct ssl_content));
	ssl_content->ctx = openssl_create_ctx(role);
	if (!ssl_content->ctx) {
		return NULL;
	}

	// load crt and privkey
	if (SSL_CTX_use_certificate_file(ssl_content->ctx, crt, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		return NULL;
	}

	if (SSL_CTX_use_PrivateKey_file(ssl_content->ctx, privKey, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		return NULL;
	}

	ssl_content->ssl = openssl_create_ssl(ssl_content->ctx);
	if (!ssl_content->ssl) {
		return NULL;
	}

	SSL_set_options(ssl_content->ssl, SSL_OP_ENABLE_KTLS);
	SSL_set_fd(ssl_content->ssl, socketfd);

	return ssl_content;
}

int connect_ssl(struct ssl_content *ssl_content)
{
	if (SSL_connect(ssl_content->ssl) == -1) {
		ERR_print_errors_fp(stderr);
		return -1;
	}
	return 0;
}

int accept_ssl(struct ssl_content *ssl_content)
{
	if (SSL_accept(ssl_content->ssl) == -1) {
		ERR_print_errors_fp(stderr);
		return -1;
	}
	return 0;
}

int clean_ssl(struct ssl_content *ssl_content) {
	if (!ssl_content)
		return 0;
	SSL_shutdown(ssl_content->ssl);
	SSL_free(ssl_content->ssl);
	SSL_CTX_free(ssl_content->ctx);
	free(ssl_content);
	return 0;
}

*/
import "C"
import (
	"fmt"
	"unsafe"
)

func OpensslAccept(cert string, privKey string, socketfd int) error {
	cstringCert := C.CString(cert)
	defer C.free(unsafe.Pointer(cstringCert))
	cstringPriv := C.CString(privKey)
	defer C.free(unsafe.Pointer(cstringPriv))

	ret := C.do_ssl(C.int(socketfd), cstringCert, cstringPriv, C.int(ROLE_SERVER))
	if ret == nil {
		err := fmt.Errorf("do openssl init failed")
		return err
	}
	retnum := C.accept_ssl(ret)
	if retnum != 0 {
		err := fmt.Errorf("do openssl accept failed, retnum is %d", retnum)
		C.clean_ssl(ret)
		return err
	}

	return nil
}

func OpensslConnect(cert string, privKey string, socketfd int) error {
	cstringCert := C.CString(cert)
	defer C.free(unsafe.Pointer(cstringCert))
	cstringPriv := C.CString(privKey)
	defer C.free(unsafe.Pointer(cstringPriv))

	ret := C.do_ssl(C.int(socketfd), cstringCert, cstringPriv, C.int(ROLE_CLIENT))
	if ret == nil {
		err := fmt.Errorf("do openssl init failed")
		return err
	}
	retnum := C.connect_ssl(ret)
	if retnum != 0 {
		err := fmt.Errorf("do openssl connect failed, retnum is %d", retnum)
		C.clean_ssl(ret)
		return err
	}
	return nil
}
