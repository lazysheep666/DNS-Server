#include <stdio.h> /* for printf() and fprintf() */
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <arpa/inet.h> /* for sockaddr_in and inet_addr() */
#include <stdlib.h> /* for atoi() and exit() */
#include <string.h> /* for memset() */
#include <unistd.h> /* for close() */
#define SERVER_PORT 53 
int getType(char* type);
int main(int argc, char const *argv[])
{
  /* code */
  //The struct of the header
  struct dnsHeader {
    unsigned short id;
    unsigned short tag; 
    unsigned short queryNum;
    unsigned short answerNum;
    unsigned short authorNum;
    unsigned short addNum;
  };
  //The struct of the Query Section
  struct dnsQuery {
    unsigned char *qName;
    unsigned short qType;
    unsigned short qClass;
  };
  //The struct of the Answer Section
  struct dnsRR {
    unsigned char *dname;
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short rDataLen;
    unsigned char *rData;
  };
  //The struct of the dns packt

  //consist of the header, Query Section, and Answer Section
  struct packet {
    struct dnsHeader header;
    struct dnsQuery qSection;
    struct dnsRR aSection;
  };
  int sockfd;
  char* type;
  int _type;
  char* queryMsg;
  struct sockaddr_in localServAddr;
  struct packet queryPacket;
  const char *serverIP = "127.1.1.1";
  if (argc < 2 || argc > 3) { 
    printf("Usage: ./client domain_name type\n"); 
    exit(1); 
  }
  if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1){ 
    printf("Something wrong with socket creation\n"); 
    exit(1); 
  }
  localServAddr.sin_family = AF_INET;
  // Convert host sequence to network sequence.
  localServAddr.sin_port=htons(SERVER_PORT);
  localServAddr.sin_addr.s_addr = inet_addr(serverIP);
  // establish connection
  if (connect(sockfd, 
  (struct sockaddr *)&localServAddr,  
  sizeof(struct sockaddr)) == -1) { 
    printf("Something wrong with socket connecting\n");
    exit(1); 
  } 
  // construct query packet

  // send query packet
  if (send(sockfd, "Hello, you are connected!\n", 26, 0) == -1) {
    printf("Something wrong with socket sending packet\n");
    exit(0); 
  }
  return 0;
}

//get the query type
int getType(char* type) {
  if () {
    /* code */
  }
  
}