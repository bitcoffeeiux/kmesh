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
// #include <sys/socket.h>
// #include <openssl/ssl.h>
// #include <openssl/err.h>
// #include <openssl/evp.h>
/*

struct ssl_content {
	SSL_CTX *ctx;
	SSL *ssl;
};

#define ROLE_CLIENT 0
#define ROLE_SERVER 0

SSL_CTX *openssl_create_ctx(int role)
{
	SSL_CTX *ctx;

	// init openssl library
	SSL_load_error_strings();
	SSL_library_init();
	OpenSSL_add_all_algorithms();

	// create openssl context
	if (role == ROLE_CLIENT) { // client
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

int handle_ssl(struct ssl_content *ssl_content, int role)
{
	int retry_num = 0;
	int rc;
Retry:
	if (role == ROLE_CLIENT) {
		// server connect to client in mtls
		rc = SSL_accept(ssl_content->ssl);
	} else if (role == ROLE_SERVER) {
		// server connect to client in mtls
		rc = SSL_connect(ssl_content->ssl);
	} else {
		// impossible
	}

	if ( rc == -1 && errno == 11 && retry_num <= 3) {
		retry_num++;
		goto Retry;
	}

	SSL_set_fd(ssl_content->ssl, -1);
	SSL_shutdown(ssl_content->ssl);
	SSL_free(ssl_content->ssl);
	SSL_CTX_free(ssl_content->ctx);

	if (rc == -1) {
		ERR_print_errors_fp(stderr);
		return -1;
	}
	return 0;
}

*/
import "C"
import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

func OpensslHandle(cert string, privKey string, socketfd, role int) error {
	cstringCert := C.CString(cert)
	defer C.free(unsafe.Pointer(cstringCert))
	cstringPriv := C.CString(privKey)
	defer C.free(unsafe.Pointer(cstringPriv))

	if err := unix.SetsockoptInt(socketfd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
		err = fmt.Errorf("socketfd set reuseport failed: %v\n", err)
		return err
	}

	fd_ptr := uintptr(socketfd)
	flags, err := unix.FcntlInt(fd_ptr, unix.F_GETFL, 0)
	if err != nil {
		err = fmt.Errorf("socketfd get fcntl failed: %v\n", err)
		return err
	}
	if _, err = unix.FcntlInt(fd_ptr, unix.FSETFL, flags & ^unix.O_NONBLOCK); err != nil {
		err = fmt.Errorf("socketfd set fcntl failed: %v\n", err)
		return err
	}

	ret := C.do_ssl(C.int(socketfd), cstringCert, cstringPriv, C.int(ROLE_SERVER))
	if ret == nil {
		err := fmt.Errorf("do openssl init failed")
		return err
	}
	retnum := C.handle_ssl(ret, C.int(role))
	if retnum != 0 {
		var err error
		if role == 0 {
			err = fmt.Errorf("do openssl accept failed, retnum is %d", retnum)
		} else {
			err = fmt.Errorf("do openssl connect failed, retnum is %d", retnum)
		}
		return err
	}
	if _, err = unix.FcntlInt(fd_ptr, unix.F_SETFL, flags); err != nil {
		err = fmt.Errorf("recover sockfd fcntl failed: %v\n", err)
		return err
	}

	return nil
}
