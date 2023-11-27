#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>

int main(int argc, char** argv) {
    if (argc < 4) {
        printf("Usage: %s <serverHost> <serverPort> <RequestType (A, C, D, L) [<rule>]>\n", argv[0]);
        return 1;
    }

    const char* serverHost = argv[1];
    int serverPort = atoi(argv[2]);

    const char* request = argv[3];
    size_t requestSize = strlen(request);

    int clientSocket = socket(AF_INET6, SOCK_STREAM, 0);
    if (clientSocket == -1) {
        perror("Socket creation error");
        return 1;
    }

    struct addrinfo hints, *servinfo;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(serverHost, NULL, &hints, &servinfo) != 0) {
        perror("Invalid server host");
        close(clientSocket);
        return 1;
    }

    struct sockaddr_in6 serverAddr;
    memcpy(&serverAddr, servinfo->ai_addr, servinfo->ai_addrlen);
    serverAddr.sin6_port = htons(serverPort);

    if (connect(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == -1) {
        perror("Connection error");
        close(clientSocket);
        return 1;
    }

    if (send(clientSocket, request, requestSize, 0) == -1) {
        perror("Send error");
        close(clientSocket);
        return 1;
    }

    char* response = (char*)malloc(2048);
    if (response == NULL) {
        perror("Memory allocation error");
        close(clientSocket);
        return 1;
    }

    ssize_t bytesRead = recv(clientSocket, response, 2047, 0);
    if (bytesRead == -1) {
        perror("Receive error");
    } else {
        response[bytesRead] = '\0';
        printf("%s\n", response);
    }

    free(response);
    close(clientSocket);

    return 0;
}
