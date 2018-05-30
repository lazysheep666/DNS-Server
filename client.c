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
};

/**
 * method
 */
void strreverse(char* begin, char* end);
void itoa(int value, char* str, int base);
int getType(char *type);
void put16bits(char** buffer, unsigned short value);
size_t get16bits(const char** buffer);
void put32bits(char** buffer, unsigned short value);
size_t get32bits(const char** buffer);
void encode_header(struct dnsHeader* hd, char** buffer);
void encode_domain_name(char** buff, char* domain);
void encode_resource_records(struct dnsRR* rr, char** buffer);
void encode_packet(struct packet* packet, char** buffer);
/**
 * main
 */ 
int main(int argc, char *argv[])
{
  /* code */
  int sockfd;
  struct sockaddr_in localServAddr;
  struct packet qPacket;
  char* send_buf;
  char* buf;
  char* serverIP = "127.0.0.1";
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
  qPacket.header = (struct dnsHeader*)malloc(sizeof(struct dnsHeader));
  memset(qPacket.header, 0, sizeof(struct dnsHeader));
  qPacket.querySection = (struct dnsQuery*)malloc(sizeof(struct dnsQuery));
  memset(qPacket.querySection, 0, sizeof(struct dnsQuery));
  srand((unsigned int)(time(NULL)));
  qPacket.header->id = rand();
  tag = standard_query_NRD;
  qPacket.header->tag = tag;
  qPacket.header->queryNum = 0x0001;
  qPacket.header->authorNum = 0x0000;
  qPacket.header->addNum = 0x0000;
  qPacket.querySection->qName = argv[1];
  qPacket.querySection->qType = getType(argv[2]);
  qPacket.querySection->qClass = 0x0001;
  qPacket.answerSection = NULL;
  qPacket.authoritiySection = NULL;
  qPacket.additionalSection = NULL;
  // send query packet
  send_buf = (char*) malloc(sizeof(char) * BUF_SIZE);
  memset(send_buf, '\0', BUF_SIZE);
  buf = send_buf;
  encode_packet(&qPacket, &send_buf);
  buf = buf + 12;
  printf("%s", buf);
  if (send(sockfd, buf, BUF_SIZE, 0) == -1) {
    printf("Something wrong with socket sending packet\n");
    exit(0); 
  }
  return 0;
}
void strreverse(char* begin, char* end) {
	char aux;
	while(end>begin)
		aux=*end, *end--=*begin, *begin++=aux;
}
	
void itoa(int value, char* str, int base) {
	
	static char num[] = "0123456789abcdefghijklmnopqrstuvwxyz";
	char* wstr=str;
	int sign;
	// Validate base
	if (base<2 || base>35){ *wstr='\0'; return; }
	// Take care of sign	
	if ((sign=value) < 0) value = -value;
	// Conversion. Number is reversed.
	do *wstr++ = num[value%base]; while(value/=base);
	if(sign<0) *wstr++='-';
	*wstr='\0';
	// Reverse string
	strreverse(str,wstr-1);
}
// memory operation
void put16bits(char** buffer, unsigned short value) {
  value = htons(value);
  memcpy(*buffer, &value, 2);
  *buffer += 2;
}
size_t get16bits(const char** buffer) {
  unsigned short value;
  memcpy(&value, *buffer, 2);
  *buffer += 2;
  return ntohs(value);
}
void put32bits(char** buffer, unsigned short value) {
  value = htons(value);
  memcpy(*buffer, &value, 4);
  *buffer += 4;
}
size_t get32bits(const char** buffer) {
  unsigned int value;
  memcpy(&value, *buffer, 4);
  *buffer += 4;
  return ntohs(value);
}

//encode header
void encode_header(struct dnsHeader* hd, char** buffer) {
  put16bits(buffer, hd->id);
  put16bits(buffer, hd->tag);
  put16bits(buffer, hd->queryNum);
  put16bits(buffer, hd->answerNum);
  put16bits(buffer, hd->authorNum);
  put16bits(buffer, hd->addNum);
}

// www.baidu.com => 3www5baidu3com0
void encode_domain_name(char** buffer, char* domain) {
  int j = -1;
  do {
    j++;
    if (domain[j] == '.' || domain[j] == '\0') {
      itoa(j / 3, *buffer, 10);
      *buffer += 1;
      memcpy(*buffer, domain, j);
      *buffer += j;
      domain = domain + j + 1;
      j = -1;
    }
  } while (domain[j] != '\0');
  itoa(0, *buffer, 10);
  *buffer += 1;
}
/* @return 0 upon failure, 1 upon success */
void encode_resource_records(struct dnsRR* rr, char** buffer) {
  if (rr) {
    encode_domain_name(buffer, rr->dname);
    put16bits(buffer, rr->type);
    put16bits(buffer, rr->_class);
    put32bits(buffer, rr->ttl);
    put16bits(buffer, rr->rDataLen);
    memcpy(*buffer, rr->rData, strlen(rr->rData));
    *buffer += strlen(rr->rData);
  }
}

//endcode packet
void encode_packet(struct packet* packet, char** buffer) {
  encode_header(packet->header, buffer);
  encode_domain_name(buffer, packet->querySection->qName);
  put16bits(buffer, packet->querySection->qType);
  put16bits(buffer, packet->querySection->qClass);
  encode_resource_records(packet->answerSection, buffer);
  encode_resource_records(packet->authoritiySection, buffer);
  encode_resource_records(packet->additionalSection, buffer);
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