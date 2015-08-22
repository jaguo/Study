#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/in.h> 	// sockaddr_in htons(),htonl(),ntohs(),ntohl()
#include <sys/types.h>  	// socket
#include <sys/socket.h> 	// socket
#include <string.h>			// bzero
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

#define BUFF_SIZE 4096

//htons()"host to net short",htonl()"host to net long"

/*
   int socket(int domain, int type,int protocol)
   int bind(int sockfd, struct sockaddr *my_addr, int addrlen)
   int listen(int sockfd,int backlog)
   int accept(int sockfd, struct sockaddr *addr,int *addrlen)
 */

 
void handle(int connfd);
void change(char *buf);

/*start listen */
int start(int port)
{
    struct sockaddr_in server_addr;
    int servername;

    if((servername = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
	fprintf(stderr, "Socked Error: %s\n", strerror(errno));
	exit(1);
    }

    bzero(&server_addr,sizeof(struct sockaddr_in));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(port);

    if(bind(servername, (struct sockaddr *)(&server_addr), sizeof(struct sockaddr)) == -1)
    {
	fprintf(stderr, "Bind Error: %s\n", strerror(errno));
	exit(1);
    }
    if(listen(servername, 5) == -1)
    {
	fprintf(stderr, "Listen Error: %s\n", strerror(errno));
	exit(1);
    }

    return servername;
}

int main(int argc, char const *argv[])
{
    int server_fd,client;
    int portnumber, sin_size;
    struct sockaddr_in client_addr;
    char hello[] = "Hello World!";
    char data[BUFF_SIZE] = {0};

    if(argc == 1)
    {
	fprintf(stdout, "Port Number: 8080\n");
	portnumber = 8080;
    } else if(argc == 2) {
	if((portnumber = atoi(argv[1])) < 0)
	{
	    fprintf(stderr, "Prot Error: %s\n", argv[1]);
	    exit(1);
	}
    } else {
	fprintf(stderr, "Port Error: %s\n", argv[1]);
	exit(1);
    }

    server_fd = start(portnumber);
    while(1)
    {
	sin_size = sizeof(struct sockaddr_in);
	if((client = accept(server_fd, (struct sockaddr *)(&client_addr), &sin_size)) == -1)
	{
	    fprintf(stderr, "Accept Error: %s\n", strerror(errno));
	    exit(1);
	}

	fprintf(stdout,"Server get connection from %s\n",inet_ntoa(client_addr.sin_addr));

	handle(client);
	close(client);
    }

    close(server_fd);

    return 0;
}

void handle(int connfd)
{
    size_t n;
    char buf[BUFF_SIZE];

    while(1)
    {
	memset(buf, 0, BUFF_SIZE);
	n = read(connfd, buf, BUFF_SIZE);
	if (n < 0)
	{
	    if(errno != EINTR)
	    {
		perrno("read error");
		break;
	    }
	}
	if (n == 0)
	{
	    close(connfd);
	    printf("client exit\n");
	    break;
	}

	if (strncmp("exit", buf, 4) == 0)
	{
	    close(connfd);
	    printf("client exit\n");
	    break;
	}
	change(buf);
	write(connfd, buf, n);
	write(STDOUT_FILENO, buf, n);
    }
}

void change(char *buf)
{
    int n = strlen(buf);
    int i = 0;
    for (i = 0; i < n; i++)
	if(buf[i] <= 'z' && buf[i] >= 'a')
	    buf[i] -= 0x20;
}

