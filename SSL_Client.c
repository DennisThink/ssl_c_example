#include <stdio.h>
//#include <unistd.h>
#include <string.h>
#include <signal.h>
//#include <sys/socket.h>
//#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <winsock.h>

int bindAddr(const char* hostname, int port) {
    // bind address to socket
    struct hostent* host;
    struct sockaddr_in addr;
    if ((host = gethostbyname(hostname)) == NULL) exit(-1); // get host by name
    int sd = socket(PF_INET, SOCK_STREAM, 0); // create client descriptor
    memset(&addr, sizeof(addr),0); // memset address with 0
    addr.sin_family = AF_INET; // IPv4 address family
    addr.sin_port = htons(port); // convert to network short byte order
    addr.sin_addr.s_addr = *(long*)(host->h_addr); // set the IP of the socket; sin_addr is an union
    if (connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0) exit(-1); // connect to host
    return sd;
}

SSL_CTX* InitClientCTX(void) {
    // create server ssl context
    OpenSSL_add_all_algorithms(); // set cryptos
    SSL_load_error_strings(); // set error messages
    const SSL_METHOD* method = TLS_client_method(); // create client method
    SSL_CTX* ctx = SSL_CTX_new(method); // create client context
    if (ctx == NULL) ERR_print_errors_fp(stderr); // print error
    return ctx;
    exit(-1);
}

int main(int argc, char* argv[])
{
#if 1
    WORD wVersionRequested;
    WSADATA wsaData;
    int err;
    wVersionRequested = MAKEWORD(1, 1);
    err = WSAStartup(wVersionRequested, &wsaData);
    if (err != 0)
    {
        /* Tell the user that we couldn't find a useable */
        /* winsock.dll. */
        return;
    }
#endif
    SSL_library_init(); // init ssl lib
    SSL_CTX* ctx = InitClientCTX(); // create ssl context
    SSL* ssl = SSL_new(ctx); // hold data for the SSL cocnnection
    int sockFd = bindAddr("127.0.0.1", 4433);
    SSL_set_fd(ssl, sockFd); // assigns a socket to a SSL structure
    if (SSL_connect(ssl) == -1) exit(-1); // connect to server
    if (1)
    {
        SSL_write(ssl, "HELLO\r\n", 7);
        //close(sockFd); // close socket descriptor
        SSL_free(ssl); // close ssl
        SSL_CTX_free(ctx); // release context
    }
#if 1
    /* Confirm that the Windows Sockets DLL supports 1.1.*/
    /* Note that if the DLL supports versions greater */
    /* than 1.1 in addition to 1.1, it will still return */
    /* 1.1 in wVersion since that is the version we */
    /* requested. */
    if (LOBYTE(wsaData.wVersion) != 1 ||
        HIBYTE(wsaData.wVersion) != 1)
    {
        /* Tell the user that we couldn't find a useable */
        /* winsock.dll. */
        WSACleanup();
        return;
    }
#endif
	return 0;
}