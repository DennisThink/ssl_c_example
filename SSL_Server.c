#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#ifdef WINDOWS_OS
#include <winsock.h>
#endif

#ifdef LINUX_OS
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#define SOCKET int
#endif

struct SSL_Elem
{
    SSL_CTX* _ctx;
    SSL* _ssl;
};

SSL_CTX* InitClientCTX(void) 
{
    // create server ssl context
    OpenSSL_add_all_algorithms(); // set cryptos
    SSL_load_error_strings(); // set error messages
    const SSL_METHOD* method = TLS_client_method(); // create client method
    SSL_CTX* ctx = SSL_CTX_new(method); // create client context
    if (ctx == NULL) ERR_print_errors_fp(stderr); // print error
    return ctx;
    exit(-1);
}

struct SSL_Elem SSLCreateElem()
{
    SSL_library_init(); // init ssl lib
    SSL_CTX* ctx = InitClientCTX(); // create ssl context
    SSL* ssl = SSL_new(ctx); // hold data for the SSL cocnnection

    struct SSL_Elem elem;
    elem._ctx = ctx;
    elem._ssl = ssl;
    return elem;
}

void SSLFreeElem(const struct SSL_Elem elem)
{
    SSL_free(elem._ssl); // close ssl
    SSL_CTX_free(elem._ctx); // release context
}

/*
openssl req - nodes - new - x509 - keyout server.key - out server.cert
*/
SOCKET CreateServerSocket(const char * pAddr,const int port)
{
    SOCKET s;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Unable to bind ");
        printf("Error Code %d \n", errno);
        exit(EXIT_FAILURE);
    }

    if (listen(s, 1) < 0) {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }

    return s;
}

SSL_CTX *CreateContext()
{
    const SSL_METHOD *method=NULL;
    SSL_CTX *ctx=NULL;

    method = TLS_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void ConfigureContext(const char * pCertFile,const char * pKeyFile,SSL_CTX *ctx)
{
    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, pCertFile, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, pKeyFile, SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}


#ifdef WINDOWS_OS
WSADATA WinSockInit()
{
    WORD wVersionRequested;
    WSADATA wsaData;
    int err;
    wVersionRequested = MAKEWORD(1, 1);
    err = WSAStartup(wVersionRequested, &wsaData);
    if (err != 0)
    {
        /* Tell the user that we couldn't find a useable */
        /* winsock.dll. */
        return wsaData;
    }
    return wsaData;
}



void WinSockClean(const WSADATA wsaData)
{
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
}
#endif

struct SSL_NET_Elem
{
#ifdef WINDOWS_OS
    WSADATA _wsaData;
#endif
    SSL_CTX* _ctx;
};

struct SSL_NET_Elem Init_SSL_Net(const char * pCertFile,const char * pKeyFile)
{
    struct SSL_NET_Elem result;
    result._ctx = NULL;
    #ifdef WINDOWS_OS
    {
        WORD wVersionRequested;
        WSADATA wsaData;
        int err;
        wVersionRequested = MAKEWORD(1, 1);
        err = WSAStartup(wVersionRequested, &wsaData);
        if (err != 0)
        {
            result._ctx = NULL;
            return result;
        }
        else
        {
            result._wsaData = wsaData;
        }
    }
    #endif
    {
        SSL_library_init(); // init ssl lib
    }
    {
        const SSL_METHOD* method = NULL;
        SSL_CTX* ctx = NULL;

        method = TLS_server_method();

        ctx = SSL_CTX_new(method);
        if (!ctx) {
            perror("Unable to create SSL context");
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }

        result._ctx = ctx;
    }
    {
        /* Set the key and cert */
        if (SSL_CTX_use_certificate_file(result._ctx, pCertFile, SSL_FILETYPE_PEM) <= 0) {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }

        if (SSL_CTX_use_PrivateKey_file(result._ctx, pKeyFile, SSL_FILETYPE_PEM) <= 0) {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
    }
    return result;
}


SOCKET Create_SSL_Socket()
{
    SOCKET s;
    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    return s;
}

void Start_SSL_Listen(SOCKET s, const char* pAddr, const int port)
{
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Unable to bind ");
        printf("Error Code %d \n", errno);
        exit(EXIT_FAILURE);
    }

    if (listen(s, 1) < 0) {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }
}

struct SSL_Socket_Elem
{
    SSL* _ssl;
    SOCKET _sockFd;
};

struct SSL_Socket_Elem Accept1_SSL_Client(SOCKET s, SSL_CTX* ctx)
{
    struct SSL_Socket_Elem result;
    struct sockaddr_in addr;
    int len = sizeof(addr);
    SOCKET client = accept(s, (struct sockaddr*)&addr, &len);
    if (client < 0) {
        perror("Unable to accept");
        exit(EXIT_FAILURE);
    }

    result._ssl = SSL_new(ctx);
    SSL_set_fd(result._ssl, client);
    if (SSL_accept(result._ssl) <= 0)
    {
    } 
    return result;
}

int Write_SSL_Data(const struct SSL_Socket_Elem sock,const char * pBuff,const int len)
{
    return SSL_write(sock._ssl, pBuff, len);
}

int Read_SSL_Data(const struct SSL_Socket_Elem sock,char* pBuff, const int len)
{
    return SSL_read(sock._ssl, pBuff, len);
}

int Close_SSL_Connection(const struct SSL_Socket_Elem sock)
{
    #ifdef WINDOWS_OS
    closesocket(sock._sockFd);
    #endif 

    #ifdef LINUX_OS
    close(sock._sockFd);
    #endif
    SSL_shutdown(sock._ssl);
    SSL_free(sock._ssl);
    return 1;
}

void Clear_SSL_NET(struct SSL_NET_Elem elem)
{
    SSL_CTX_free(elem._ctx);
#ifdef WINDOWS_OS
    WinSockClean(elem._wsaData);
#endif
}

int NewSSLServer(int argc, char* argv[])
{
    struct SSL_NET_Elem sslElem;
    sslElem = Init_SSL_Net("./cert.pem","./key.pem");
    if (sslElem._ctx)
    {
        SOCKET serverSockFd = Create_SSL_Socket();
        {
            Start_SSL_Listen(serverSockFd, "127.0.0.1", 4433);
            for (int i = 0; i < 10; i++)
            {
                struct SSL_Socket_Elem sockElem = Accept1_SSL_Client(serverSockFd, sslElem._ctx);
                while (1)
                {
                    char buff[64] = { 0 };
                    memset(buff, 0, 64);
                    int ret = Read_SSL_Data(sockElem, buff, 63);
                    if (ret > 0)
                    {
                        printf("C: %s\r\n", buff);
                    }
                    else
                    {
                        goto CLOSE_CLIENT;
                    }
                    ret = Write_SSL_Data(sockElem, buff, strlen(buff));
                    if (ret > 0)
                    {
                        printf("S: %s \r\n", buff);
                    }
                    else
                    {
                        goto CLOSE_CLIENT;
                    }
                    if (0)
                    {
                    CLOSE_CLIENT:
                        Close_SSL_Connection(sockElem);
                        break;
                    }
                }
            }
        }
        #ifdef WINDOWS_OS
        closesocket(serverSockFd);
        #endif

        #ifdef LINUX_OS
        close(serverSockFd);
        #endif
    }
    else
    {

    }
    Clear_SSL_NET(sslElem);
    return 0;
}
int OldSSLServer(int argc, char **argv)
{
    #ifdef WINDOWS_OS
    WSADATA wsaData = WinSockInit();
    #endif
    {
        //1. SSL Init
        SSL_library_init(); // init ssl lib
        SSL_CTX *ctx;
        /* Ignore broken pipe signals */
        //signal(SIGPIPE, SIG_IGN);
        ctx = CreateContext();

        ConfigureContext("cert.pem", "key.pem", ctx);

        SOCKET serverSockFd = CreateServerSocket("127.0.0.1",4433);

        /* Handle connections */
        for(int i = 0 ; i < 10 ; i++) 
        {
            struct sockaddr_in addr;
            unsigned int len = sizeof(addr);
            SSL *ssl;
            const char reply[] = "test\n";

            SOCKET client = accept(serverSockFd, (struct sockaddr*)&addr, &len);
            if (client < 0) {
                perror("Unable to accept");
                exit(EXIT_FAILURE);
            }

            ssl = SSL_new(ctx);
            SSL_set_fd(ssl, client);


            if (SSL_accept(ssl) <= 0) {
                ERR_print_errors_fp(stderr);
            }
            else {
                for (int i = 0; i < 10; i++)
                {
                    char buff[32] = { 0 };
                    int ret = 0;
                    ret = SSL_read(ssl, buff, 32);
                    if (ret > 0)
                    {
                        printf("C: %s \n", buff);
                    }
                    else
                    {
                        break;
                    }
                    ret = SSL_write(ssl, buff, strlen(buff));
                    if (ret > 0)
                    {
                        printf("S: %s \n", buff);
                    }
                    else
                    {
                        break;
                    }
                }
                for (int i = 0; i < 10; i++)
                {
                    char buff[32] = { 0 };
                    int ret = 0;
                    ret = recv(client, buff, 32,0);
                    if (ret > 0)
                    {
                        printf("C: %s \n", buff);
                    }
                    else
                    {
                        break;
                    }
                    ret = send(client, buff, 32, 0);
                    if (ret > 0)
                    {
                        printf("S: %s \n", buff);
                    }
                    else
                    {
                        break;
                    }
                }
                //close(client);
                #ifdef WINDOWS_OS
                closesocket(client);
                #endif

                #ifdef LINUX_OS
                close(client);
                #endif

                SSL_shutdown(ssl);
                SSL_free(ssl);
            }
        }

        #ifdef WINDOWS_OS
        closesocket(serverSockFd);
        #endif

        #ifdef LINUX_OS
        close(serverSockFd);
        #endif
    
        SSL_CTX_free(ctx);
    }

    #ifdef WINDOWS_OS
    WinSockClean(wsaData);
    #endif
    return 0;
}


int main(int argc, char* argv[])
{
    //return NewSSLServer(argc, argv);
    return OldSSLServer(argc, argv);
}
