#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>
#include <ctype.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/types.h>

struct Rule {
    char rule[100];
    struct QueryNode* queries;
};

struct QueryNode {
    char query[20];
    struct QueryNode* next;
};

struct RuleNode {
    struct Rule rule;
    struct RuleNode* next;
};

struct RuleNode* firewall = NULL;
pthread_mutex_t lock;

int isIPMatch(const char* range, const char* ip);
int isPortMatch(const char* range, int port);
int isRuleValid(const char* rule);
void printRules(int client);
int isAllowed(const char* rule, const char* ip, int port);
void addRule(const char* rule);
void addQuery(struct RuleNode* ruleNode, const char* query);
int deleteRule(const char* rule);
void cleanupRules();
void* handleClient(void* clientSocket);

int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        return 1;
    }

    int PORT = atoi(argv[1]);

    int serverSocket, clientSocket;
    struct sockaddr_storage serverAddr, clientAddr;
    socklen_t addrLen = sizeof(clientAddr);

    serverSocket = socket(AF_INET6, SOCK_STREAM, 0);
    if (serverSocket == -1) {
        perror("Socket creation error");
        return 1;
    }

    ((struct sockaddr_in6*)&serverAddr)->sin6_family = AF_INET6;
    ((struct sockaddr_in6*)&serverAddr)->sin6_port = htons(PORT);
    ((struct sockaddr_in6*)&serverAddr)->sin6_addr = in6addr_any;

    if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == -1) {
        perror("Bind error");
        return 1;
    }

    if (listen(serverSocket, 5) == -1) {
        perror("Listen error");
        return 1;
    }

    if (pthread_mutex_init(&lock, NULL) != 0) {
        perror("Mutex init failed");
        return 1;
    }

    printf("Server listening on port %d...\n", PORT);

    while (1) {
        clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &addrLen);

        int* newClient = (int*)malloc(sizeof(int));
        *newClient = clientSocket;

        pthread_t clientThread;
        if (pthread_create(&clientThread, NULL, handleClient, newClient) != 0) {
            perror("Thread creation error");
            return 1;
        }
    }

    pthread_mutex_destroy(&lock);
    cleanupRules();
    return 0;
}

int isRuleValid(const char* rule) {
    char* token = strtok(strdup(rule), " ");
    if (!token) return 0;

    while (token != NULL) {
        if (strchr(token, '-') == NULL) {
            char* pEnd;
            long num = strtol(token, &pEnd, 10);
            if (pEnd == token || num < 0 || num > 255) {
                free(token);
                return 0;
            }
        } else {
            char* rangePart = strtok(token, "-");
            if (!rangePart) {
                free(token);
                return 0;
            }
            char* pEnd;
            long num = strtol(rangePart, &pEnd, 10);
            if (pEnd == rangePart || num < 0 || num > 255) {
                free(token);
                return 0;
            }
            rangePart = strtok(NULL, "-");
            if (!rangePart) {
                free(token);
                return 0;
            }
            num = strtol(rangePart, &pEnd, 10);
            if (pEnd == rangePart || num < 0 || num > 255) {
                free(token);
                return 0;
            }
        }
        free(token);
        token = strtok(NULL, " ");
    }
    return 1;
}

void addRule(const char* rule) {
    pthread_mutex_lock(&lock);

    struct RuleNode* newRuleNode = (struct RuleNode*)malloc(sizeof(struct RuleNode));
    strcpy(newRuleNode->rule.rule, rule);
    newRuleNode->rule.queries = NULL;
    newRuleNode->next = firewall;
    firewall = newRuleNode;

    pthread_mutex_unlock(&lock);
}

void addQuery(struct RuleNode* ruleNode, const char* query) {
    struct QueryNode* newQueryNode = (struct QueryNode*)malloc(sizeof(struct QueryNode));
    strcpy(newQueryNode->query, query);
    newQueryNode->next = NULL;

    if (ruleNode->rule.queries == NULL) {
        ruleNode->rule.queries = newQueryNode;
    } else {
        struct QueryNode* last = ruleNode->rule.queries;
        while (last->next != NULL) {
            last = last->next;
        }
        last->next = newQueryNode;
    }
}

int deleteRule(const char* rule) {
    pthread_mutex_lock(&lock);

    struct RuleNode* current = firewall;
    struct RuleNode* prev = NULL;

    while (current != NULL) {
        if (strcmp(current->rule.rule, rule) == 0) {
            if (prev != NULL) {
                prev->next = current->next;
            } else {
                firewall = current->next;
            }
            free(current);
            pthread_mutex_unlock(&lock);
            return 1; 
        }
        prev = current;
        current = current->next;
    }

    pthread_mutex_unlock(&lock);
    return 0; 
}

void cleanupRules() {
    while (firewall != NULL) {
        struct RuleNode* tempRuleNode = firewall;
        firewall = firewall->next;

        struct QueryNode* queries = tempRuleNode->rule.queries;
        while (queries != NULL) {
            struct QueryNode* tempQueryNode = queries;
            queries = queries->next;
            free(tempQueryNode);
        }

        free(tempRuleNode);
    }
}

void printRules(int client) {
    char response[2048];
    memset(response, 0, sizeof(response));
    int offset = 0;

    pthread_mutex_lock(&lock);
    struct RuleNode* current = firewall;

    while (current != NULL) {
        offset += snprintf(response + offset, sizeof(response) - offset, "Rule: %s\n", current->rule.rule);
        struct QueryNode* queries = current->rule.queries;

        while (queries != NULL) {
            offset += snprintf(response + offset, sizeof(response) - offset, "Query: %s\n", queries->query);
            queries = queries->next;
        }
        current = current->next;
    }
    pthread_mutex_unlock(&lock);

    send(client, response, strlen(response), 0);
}

int isAllowed(const char* rule, const char* ip, int port) {
    char ruleCpy[100];
    strcpy(ruleCpy, rule);

    char* token = strtok(strdup(ruleCpy), " ");
    while (token != NULL) {
        char* ipRange = strtok(token, " ");
        char* portRange = strtok(NULL, " ");

        if (isIPMatch(ipRange, ip) && isPortMatch(portRange, port)) {
            free(token);
            return 1;
        }
        free(token);
        token = strtok(NULL, " ");
    }
    return 0;
}

int isIPMatch(const char* range, const char* ip) {
    char* token = strtok(strdup(range), "-");
    char* ip1 = token;
    char* ip2 = strtok(NULL, "-");

    struct in6_addr addr1, addr2, checkIP;
    if (inet_pton(AF_INET6, ip1, &addr1) == 1 && inet_pton(AF_INET6, ip2, &addr2) == 1 && inet_pton(AF_INET6, ip, &checkIP) == 1) {
        if (memcmp(&checkIP, &addr1, sizeof(struct in6_addr)) >= 0 && memcmp(&checkIP, &addr2, sizeof(struct in6_addr)) <= 0) {
            return 1;
        }
    }

    return 0;
}

int isPortMatch(const char* range, int port) {
    char* token = strtok(strdup(range), "-");
    int port1 = atoi(token);
    int port2 = atoi(strtok(NULL, "-"));

    if (port >= port1 && port <= port2) {
        return 1;
    }

    return 0;
}

void* handleClient(void* clientSocket) {
    int client = *((int*)clientSocket);
    free(clientSocket);

    char buffer[1024];
    ssize_t bytesRead = recv(client, buffer, sizeof(buffer) - 1, 0);
    buffer[bytesRead] = '\0';

    if (bytesRead <= 0) {
        close(client);
        return NULL;
    }

    if (buffer[0] == 'A') {
        char rule[100];
        strncpy(rule, &buffer[2], sizeof(rule));
        send(client, "Rule added", 10, 0);
        if (isRuleValid(rule)) {
            addRule(rule);
        } else {
            send(client, "Invalid rule", 12, 0);
        }
    } else if (buffer[0] == 'C') {
        char ip[46];
        int port;
        if (sscanf(&buffer[2], "%45s %d", ip, &port) == 2) {
            struct RuleNode* ruleNode = NULL;

            pthread_mutex_lock(&lock);
            struct RuleNode* current = firewall;
            while (current != NULL) {
                if (isAllowed(current->rule.rule, ip, port)) {
                    ruleNode = current;
                    break;
                }
                current = current->next;
            }
            pthread_mutex_unlock(&lock);

            if (ruleNode != NULL) {
                addQuery(ruleNode, ip);
                send(client, "Connection accepted", 18, 0);
            } else {
                send(client, "Connection rejected", 18, 0);
            }
        } else {
            send(client, "Invalid request format", 22, 0);
        }
    } else if (buffer[0] == 'D') {
        char rule[100];
        strncpy(rule, &buffer[2], sizeof(rule));
        if (deleteRule(rule)) {
            send(client, "Rule deleted", 12, 0);
        } else {
            send(client, "Rule not found", 14, 0);
        }
    } else if (buffer[0] == 'L') {
        printRules(client);
    } else {
        send(client, "Illegal request", 15, 0);
    }

    close(client);
    return NULL;
}
