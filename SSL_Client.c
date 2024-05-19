#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#ifdef WINDOWS_OS
#include <winsock.h>
#include <Windows.h>
#endif

#ifdef LINUX_OS
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#define SOCKET int
#endif


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

struct SSL_Elem
{
    SSL_CTX* _ctx;
    SSL* _ssl;
};

struct SSL_SOCKET_Elem
{
    SSL* _ssl;
    SOCKET _sockfd;
};

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



int SocketConnect(const SOCKET sockFd,char* hostName, int port)
{
    struct hostent* host;
    struct sockaddr_in addr;
    #ifdef WINDOWS_OS
    if ((host = gethostbyname(hostName)) == NULL) exit(-1); // get host by name
    #endif
    
    #ifdef LINUX_OS

    if ((host = gethostbyname(hostName)) == NULL) exit(-1); // get host by name
    #endif
    memset(&addr, sizeof(addr), 0); // memset address with 0
    addr.sin_family = AF_INET; // IPv4 address family
    addr.sin_port = htons(port); // convert to network short byte order
    addr.sin_addr.s_addr = *(long*)(host->h_addr);  // set the IP of the socket; sin_addr is an union
    if (connect(sockFd, (struct sockaddr*)&addr, sizeof(addr)) != 0)
    {
        return -1;
    }
    return sockFd;
}

int main(int argc, char* argv[])
{

#ifdef WINDOWS_OS
    WSADATA wsaData = WinSockInit();
#endif

    {
        struct SSL_Elem sslElem = SSLCreateElem();
        {
            SOCKET sockFd = socket(PF_INET, SOCK_STREAM, 0); // create client descriptor
            int result = SocketConnect(sockFd, "127.0.0.1", 4433);
            if (sockFd == result)
            {
                int ret = SSL_set_fd(sslElem._ssl, sockFd); // assigns a socket to a SSL structure
                ret = SSL_connect(sslElem._ssl);
                if (1)
                {
                    char sendBuff[32] = { 0 };
                    char recvBuff[32] = { 0 };
                    {
                        int index = 0;
                        while (index < 10)
                        {
                            memset(sendBuff, 0, 32);
                            memset(recvBuff, 0, 32);
                            sprintf(sendBuff, "%d Time Value: %d \n", index, rand());
                            ret = SSL_write(sslElem._ssl, sendBuff, (int)(strlen(sendBuff)));
                            ret = SSL_read(sslElem._ssl, recvBuff, 32);
                            printf("Send: %s\r\n", sendBuff);
                            printf("Recv: %s\r\n", recvBuff);
                            #ifdef WINDOWS_OS
                            Sleep(1000);
                            #endif
                            
                            #ifdef LINUX_OS
                            sleep(1000);
                            #endif
                            index++;
                        }
                    }
                    {
                        int index = 0;
                        while (index < 10)
                        {
                            memset(sendBuff, 0, 32);
                            memset(recvBuff, 0, 32);
                            sprintf(sendBuff, "%d Time Value: %d \n", index, rand());
                            ret = send(sockFd, sendBuff, strlen(sendBuff), 0);
                            ret = recv(sockFd, recvBuff, 32,0);
                            printf("Send: %s\r\n", sendBuff);
                            printf("Recv: %s\r\n", recvBuff);
                            #ifdef WINDOWS_OS
                            Sleep(1000);
                            #endif 

                            #ifdef LINUX_OS
                            sleep(1000);
                            #endif
                            index++;
                        }
                    }
                }
                #ifdef WINDOWS_OS
                closesocket(sockFd);
                #endif

                #ifdef LINUX_OS
                close(sockFd);
                #endif
            }
            else
            {

            }
        }
        SSLFreeElem(sslElem);
    }

#ifdef WINDOWS_OS
    WinSockClean(wsaData);
#endif
	return 0;
}