#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#define BUFF_SIZE 4096

void handle(int sockfd);

int main()
{
    char buf[BUFF_SIZE];
    char serverInetAddr[] = "107.170.199.202";
    int serverPort = 8080;
    int fd;
    struct sockaddr_in serveraddr;

    fd = socket(AF_INET, SOCK_STREAM, 0);

    bzero(&serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(serverPort);
    inet_pton(AF_INET, serverInetAddr, &serveraddr.sin_addr);

    if (connect(fd, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0)
    {
	perror("connect error!");
	exit(1);
    }

    printf("connect success!\n");
    handle(fd);
    close(fd);
    return 0;
}

void handle(int sockfd)
{
    char sendline[BUFF_SIZE], recvline[BUFF_SIZE];
    int n;
    while(1)
    {
	memset(sendline, 0, BUFF_SIZE);
	if (read(STDIN_FILENO, sendline, BUFF_SIZE) == 0)
	    break;
	n = write(sockfd, sendline, strlen(sendline));
	n = read(sockfd, recvline, BUFF_SIZE);
	if (n == 0)
	{
	    printf("echoclient:\n");
	    break;
	}
	write(STDOUT_FILENO, recvline, n);
    }
}
