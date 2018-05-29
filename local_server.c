#include <stdio.h> /* for printf() and fprintf() */
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <time.h>
#include <arpa/inet.h> /* for sockaddr_in and inet_addr() */
#include <stdlib.h> /* for atoi() and exit() */
#include <string.h> /* for memset() */
#include <unistd.h> /* for close() */
#define SERVER_PORT 3000
#define BUF_SIZE 1024 
#define BACKLOG 10 /* 最大同时连接请求数 */
int main(int argc, char const *argv[]) {
  char* serverIP = "127.1.1.1";
  int sockfd,client_fd; /*sock_fd：监听socket；client_fd：数据传输socket */
  struct sockaddr_in my_addr; /* 本机地址信息 */ 
  struct sockaddr_in remote_addr; /* 客户端地址信息 */ 
  char* buf;
  if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) { 
    printf("Something wrong with socket creation\n"); 
    exit(1); 
  }
  my_addr.sin_family = AF_INET; 
  my_addr.sin_port = htons(SERVER_PORT); 
  my_addr.sin_addr.s_addr = INADDR_ANY; 
  if (bind(sockfd, (struct sockaddr *)&my_addr, sizeof(struct sockaddr)) == -1) { 
    printf("Something wrong with socket binding\n");
    exit(1); 
  }
  if (listen(sockfd, BACKLOG) == -1) { 
    printf("Something wrong with socket listening\n"); 
    exit(1); 
  } 
  while (1) {
    unsigned int sin_size = sizeof(struct sockaddr_in);
    if ((client_fd = (accept(sockfd, (struct sockaddr *)&remote_addr,&sin_size)))== -1) { 
      printf("Something wrong with socket accepting\n");  
      continue; 
    }
    int nbytes;
    printf("received a connection from %s\n", inet_ntoa(remote_addr.sin_addr));
    if ((nbytes = recv(client_fd, buf, BUF_SIZE, 0)) == -1) {
      printf("Something wrong with socket receving\n");
    }  
  }
  return 0;
}
