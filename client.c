#include <stdio.h> /* for printf() and fprintf() */
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <time.h>
#include <arpa/inet.h> /* for sockaddr_in and inet_addr() */
#include <stdlib.h> /* for atoi() and exit() */
#include <string.h> /* for memset() */
#include <unistd.h> /* for close() */
#define SERVER_PORT 53 
int getType(char *type);
/**
 * Tag Types
*/
enum tag_type {
  standard_query_NRD = 0x0000, //standard query with no-recursive 
  standard_query_RD = 0x0100, //standard query with recursive 
  inverse_query_NRD = 0x0800, //inverse query with no-recursive
  inverse_query_RD = 0x0900, //inverse query with recursive
  standard_res_NAA_NRA = 0x8000, //standard response with not-authoritive and not-recursive
  standard_res_AA_NRA = 0x8400,  //standard response with authoritive and not-recursive
  name_wrong_res = 0x8403,
  //don't have such domian name
  format_wrong_res = 0x8401
  //the format is wrong
} tag;
/**
 * Resource Record Types 
 */
enum RR_type {
  A = 0x0001,
  CNAME = 0x0005,
  MX = 0x000F
};
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
  char *qName;
  unsigned short qType;
  unsigned short qClass;
};
 //The struct of the Resource Record
struct dnsRR {
  char *dname;
  unsigned short type;
  unsigned short _class;
  unsigned int ttl;
  unsigned short rDataLen;
  char *rData;
  struct dnsRR* next;// for link list 
};
 //The struct of the dns packt
 //consist of the header, Query Section, and Answer Section
struct packet {
  struct dnsHeader* header;
  struct dnsQuery* querySection;
  struct dnsRR* answerSection;
  struct dnsRR* authoritiySection;
  struct dnsRR* additionalSection;
} qPacket, aPacket;
int main(int argc, char *argv[])
{
  /* code */
  int sockfd;
  struct sockaddr_in localServAddr;
  struct packet queryPacket;
  char* send_buf;
  char* serverIP = "127.1.1.1";
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
  (struct sockaddr*)&localServAddr,  
  sizeof(struct sockaddr)) == -1) { 
    printf("Something wrong with socket connecting\n");
    exit(1); 
  }
  // construct query packet
  memset(&qPacket, 0, sizeof(struct packet));
  srand((unsigned int)(time(NULL)));
  qPacket.header->id = rand();
  tag = standard_query_NRD;
  qPacket.header->tag = tag;
  qPacket.header->queryNum = 0x0001;
  qPacket.header->answerNum = 0x0000;
  qPacket.header->authorNum = 0x0000;
  qPacket.header->addNum = 0x0000;
  qPacket.querySection->qName = argv[1];
  qPacket.querySection->qType = getType(argv[2]);
  qPacket.querySection->qClass = 0x0001;

  // send query packet
  memcpy(send_buf, &qPacket, sizeof(qPacket));
  memset(send_buf, '\0', 1024);
  if (send(sockfd, send_buf, sizeof(send_buf), 0) == -1) {
    printf("Something wrong with socket sending packet\n");
    exit(0); 
  }
  return 0;
}

//get the query type
int getType(char *type) {
  enum RR_type type_code;
  if (strcmp(type, "A") == 0) {
    type_code = A;
    return type_code;
  } 
  else if (strcmp(type, "MX"))
  {
    type_code = MX;
    return type_code;
  } else if (strcmp(type, "CNAME")) {
    type_code = CNAME;
    return type_code;
  } else {
    printf("No such query type, [A | MX | CNAME] is considered\n");
    exit(0);
  }
}