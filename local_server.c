#include <stdio.h> /* for printf() and fprintf() */
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <time.h>
#include <arpa/inet.h> /* for sockaddr_in and inet_addr() */
#include <stdlib.h> /* for atoi() and exit() */
#include <string.h> /* for memset() */
#include <unistd.h> /* for close() */
#define SERVER_PORT 53
#define UDP_PORT 53
#define BUF_SIZE 1024 
#define BACKLOG 10 /* 最大同时连接请求数 */

unsigned short length = 0;
unsigned short query_domain_length = 0;
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
  struct dnsRR* authoritySection;
  struct dnsRR* additionalSection;
};

/**
 * method
 */
void strreverse(char* begin, char* end);
void itoa(int value, char* str, int base);
unsigned short getType(char *type);
void printPacket(struct packet packet);
void initializeQueryPacket(struct packet* qPacket);
void initializeAnswerPacket(struct packet* qPacket);
void put16bits(char** buffer, unsigned short value);
unsigned short get16bits(char** buffer);
void put32bits(char** buffer, unsigned int value);
unsigned int get32bits(char** buffer);
void encode_header(struct dnsHeader* hd, char** buffer);
void encode_domain_name(char** buff, char* domain);
void parse_A_rData(struct dnsRR* rr, char* buffer, unsigned short prfrc);
void parse_MX_rData(struct dnsRR* rr, char* buffer, unsigned short prfrc);
void parse_CNAME_rData(struct dnsRR* rr, char* buffer, unsigned short prfrc);
void encode_A_CNAME_resource_records(struct dnsRR* rr, char** buffer);
void encode_MX_resource_records(struct dnsRR* rr, char** buffer);
void encode_packet(struct packet* packet, char** buffer);
void decode_header(struct dnsHeader* hd, char** buffer);
char* decode_domain_name(char** buffer);
void decode_resource_records(struct dnsRR* rr, char** buffer);
void decode_packet(struct packet* packet, char** buffer);
void getRR (struct dnsRR *head, char* fpath);
void add_A_RR(struct packet packet, char* fpath);
void add_CNAME_RR (struct packet packet, char* fpath);
void add_MX_RR (struct packet packet, char* fpath);
struct dnsRR* findRR(char* qName, unsigned short qType, struct dnsRR* head);
/**
 * main
 */ 
int main(int argc, char *argv[]) {
  char* serverIP = "127.0.0.2";
  int sockfd,client_fd; /*sock_fd：监听socket；client_fd：数据传输socket */
  struct sockaddr_in my_addr; /* 本机地址信息 */ 
  struct sockaddr_in remote_addr; /* 客户端地址信息 */ 
  if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) { 
    printf("Something wrong with socket creation\n"); 
    exit(1); 
  }
  my_addr.sin_family = AF_INET; 
  my_addr.sin_port = htons(SERVER_PORT); 
  my_addr.sin_addr.s_addr = inet_addr(serverIP); 
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

    char* buf;
    buf = (char*)malloc(sizeof(char) * BUF_SIZE);
    buf = memset(buf, 0, BUF_SIZE);
    int nbytes;

    printf("received a query from %s\n", inet_ntoa(remote_addr.sin_addr));
    if ((nbytes = recv(client_fd, buf, BUF_SIZE, 0)) == -1) {
      printf("Something wrong with socket receving\n");
    }

    struct packet qPacket;
    initializeQueryPacket(&qPacket);

    buf += 2;
    decode_packet(&qPacket, &buf);
    printf("query domain name: %s\n", qPacket.querySection->qName);
    printf("query type: %d\n", qPacket.querySection->qType);
    struct dnsRR* head = (struct dnsRR*)malloc(sizeof(struct dnsRR));
    memset(head, 0, sizeof(struct dnsRR));
    //get the resource record from cache
    getRR(head, "./cache");
    //answer rr
    struct dnsRR* rr;
    //addtional rr
    struct dnsRR* add_rr;
    if (qPacket.querySection->qType == 1 || qPacket.querySection->qType == 5) {
      rr = findRR(qPacket.querySection->qName, qPacket.querySection->qType, head);
    } else {
      rr = findRR(qPacket.querySection->qName, qPacket.querySection->qType, head);
      //addtional rr
      if (rr != NULL) {
        char* temp_rr_rData = rr->rData;
        temp_rr_rData += 2;
        char* temp_mx_query_name = (char*)malloc(sizeof(char) * BUF_SIZE);
        memset(temp_mx_query_name, 0, BUF_SIZE);
        char* mx_query_name = temp_mx_query_name;
        printf("%d\n", *temp_rr_rData);
        unsigned short length = *temp_rr_rData;
        temp_rr_rData++;
        memcpy(temp_mx_query_name, temp_rr_rData, length);
        temp_mx_query_name += length;
        *temp_mx_query_name = '.';
        temp_mx_query_name++;
        memcpy(temp_mx_query_name, rr->dname, strlen(rr->dname));
        printf("%s\n", mx_query_name);
        add_rr = findRR(mx_query_name, 1, head);
      }
    }
    //header
    //send the answer from the cache
    if (rr != NULL) {
      struct packet aPacket;
      initializeAnswerPacket(&aPacket);
      aPacket.header = qPacket.header;
      aPacket.header->answerNum = 1;
      aPacket.header->tag = standard_res_NAA_NRA;
      //query section
      aPacket.querySection = qPacket.querySection;
      //answer section
      aPacket.answerSection = rr;
      //authority section
      aPacket.authoritySection = NULL;
      //addtional section 
      if (qPacket.querySection->qType == 1 || qPacket.querySection->qType == 5) {
        aPacket.additionalSection = NULL;
      } else {
        //if the query type is MX, there is additional section
        aPacket.additionalSection = add_rr;
        aPacket.header->addNum = 1;
      }
      //send answer packet
      char* temp_buf = (char*) malloc(sizeof(char) * BUF_SIZE);
      memset(temp_buf, '\0', BUF_SIZE);
      char* send_buf = temp_buf;
      temp_buf += 2;
      encode_packet(&aPacket, &temp_buf);
      printf("send packet to %s\n", inet_ntoa(remote_addr.sin_addr));
      printf("-------------------\n");
      printf("-------------------\n");
      printf("-------------------\n");
      length = htons(length);
      memcpy(send_buf, &length, sizeof(length));
      length = ntohs(length);
      if (send(client_fd, send_buf, length + 2, 0) == -1) {
        printf("Something wrong with socket sending packet\n");
        exit(1); 
      }
      length = 0;
      query_domain_length = 0;
    } 
    //query the answer to server
    else {
      int sock; /* Socket descriptor */
      struct sockaddr_in udp_server_add; /* Echo server address */
      unsigned short rootServPort; /* Echo server port */
      // char *udp_server_ip = "127.0.0.3"; /* IP address of root server */
      char *temp_udp_send_buf = (char*)malloc(sizeof(char) * BUF_SIZE);
      memset(temp_udp_send_buf, 0, BUF_SIZE);
      if ((sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
        printf("Something wrong with socket creation\n"); 
        exit(1); 
      }
      memset(&udp_server_add, 0, sizeof(udp_server_add));
      udp_server_add.sin_family = AF_INET; /* Internet addr family */
      udp_server_add.sin_addr.s_addr = inet_addr(udp_server_ip);/*Server IP address*/
      udp_server_add.sin_port = htons(UDP_PORT); /* Server port */

      struct packet localQueryPacket;
      initializeQueryPacket(&localQueryPacket);
      localQueryPacket.header = qPacket.header;
      localQueryPacket.querySection = qPacket.querySection;
      char* udp_send_buf = temp_udp_send_buf;
      encode_packet(&localQueryPacket, &temp_udp_send_buf);
      printf("send packet to root: %s\n", udp_server_ip);
      if ((sendto(sock, 
                udp_send_buf,
                length,
                0,
                (struct sockaddr *) &udp_server_add, 
                sizeof(udp_server_add))) == -1
       ) {
        printf("Something wrong with socket sending packet\n");
        exit(1); 
      }

      //answer from server
      char *udp_rec_buf = (char*)malloc(sizeof(char) * BUF_SIZE);
      memset(udp_rec_buf, 0, BUF_SIZE);
      char* h_udp_rec_buf = udp_rec_buf;

      unsigned int remAddrLen = sizeof(udp_server_add);
      if ((recvfrom(sock, udp_rec_buf, BUF_SIZE,0,(struct sockaddr *) &udp_server_add, &remAddrLen)) == -1) {
        printf("Something wrong with socket receving\n");
      }

      struct packet localAnwserPacket;
      initializeAnswerPacket(&localAnwserPacket);
      decode_packet(&localAnwserPacket, &udp_rec_buf);
      if(localAnwserPacket.header->tag != name_wrong_res) {
        printf("receive packet from root: .%d\n", localAnwserPacket.additionalSection->rData[3]);
      } else {
        printf("receive packet from root: no such domain name\n");
      }
      //reset
      udp_rec_buf = h_udp_rec_buf;
      memset(udp_rec_buf, 0, BUF_SIZE);
      
      while (localAnwserPacket.header->answerNum == 0 && localAnwserPacket.header->tag != name_wrong_res) {
        //初始化
        udp_server_ip = (char*)malloc(sizeof(char) * BUF_SIZE);
        memset(udp_server_ip, 0, BUF_SIZE);
        // localAnwserPacket.additionalSection->rData += 3;
        char* ip = "127.0.0.";
        memcpy(udp_server_ip, ip, 8);
        // udp_server_ip += 8;
        *udp_server_ip = *localAnwserPacket.additionalSection->rData + '0';
        // udp_server_ip -= 8;
        udp_server_add.sin_addr.s_addr = inet_addr(udp_server_ip);
        printf("send packet to %s\n", udp_server_ip);
        if ((sendto(sock, 
                udp_send_buf,
                length,
                0,
                (struct sockaddr *) &udp_server_add, 
                sizeof(udp_server_add))) == -1
        ) {
          printf("Something wrong with socket sending packet\n");
          exit(1); 
        }
        initializeAnswerPacket(&localAnwserPacket);
        memset(udp_rec_buf, 0, BUF_SIZE);
        if ((recvfrom(sock, udp_rec_buf, BUF_SIZE,0,(struct sockaddr *) &udp_server_add, &remAddrLen)) == -1) {
          printf("Something wrong with socket receving\n");
        }
        decode_packet(&localAnwserPacket, &udp_rec_buf);
        if(localAnwserPacket.header->tag != name_wrong_res) {
          printf("receive packet from %s\n", udp_server_ip);
        } else {
          printf("receive packet from %s: no such domain name\n", udp_server_ip);
        }        
        //reset
        udp_rec_buf = h_udp_rec_buf;
        memset(udp_rec_buf, 0, BUF_SIZE);
      }
      //add to cache
      if (localAnwserPacket.header->tag != name_wrong_res) {
        if (localAnwserPacket.querySection->qType == 1) {
          add_A_RR(localAnwserPacket, "./cache");
        } else if (localAnwserPacket.querySection->qType == 5) {
          add_CNAME_RR(localAnwserPacket, "./cache");
        } else {
          add_MX_RR(localAnwserPacket, "./cache");
        }
      }
      //send answer packet
      char* temp_buf = (char*) malloc(sizeof(char) * BUF_SIZE);
      memset(temp_buf, '\0', BUF_SIZE);
      char* send_buf = temp_buf;
      temp_buf += 2;
      encode_packet(&localAnwserPacket, &temp_buf);
      printf("send packet to %s\n", inet_ntoa(remote_addr.sin_addr));
      printf("-------------------\n");
      printf("-------------------\n");
      printf("-------------------\n");
      length = htons(length);
      memcpy(send_buf, &length, sizeof(length));
      length = ntohs(length);
      if (send(client_fd, send_buf, length + 2, 0) == -1) {
        printf("Something wrong with socket sending packet\n");
        exit(1); 
      }
      length = 0;
      query_domain_length = 0;
    }
    close(client_fd);
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
  length += 2;
}
unsigned short get16bits(char** buffer) {
  unsigned short value;
  memcpy(&value, *buffer, 2);
  *buffer += 2;
  return ntohs(value);
}
void put32bits(char** buffer, unsigned int value) {
  value = htonl(value);
  memcpy(*buffer, &value, 4);
  *buffer += 4;
  length += 4;
}
unsigned int get32bits(char** buffer) {
  unsigned int value;
  memcpy(&value, *buffer, 4);
  *buffer += 4;
  return ntohl(value);
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
  query_domain_length = 0;
  int j = -1;
  do {
    j++;
    if (domain[j] == '.' || domain[j] == '\0') {
      **buffer = j;
      *buffer += 1;
      length += 1;
      query_domain_length += 1;
      memcpy(*buffer, domain, j);
      *buffer += j;
      length += j;
      query_domain_length += j;
      domain = domain + j + 1;
      j = -1;
    }
  } while (domain[j] != '\0');
  **buffer = 0;
  *buffer += 1;
  length += 1;
  query_domain_length += 1;
}
/* @return 0 upon failure, 1 upon success */
void encode_A_CNAME_resource_records(struct dnsRR* rr, char** buffer) {
  if (rr) {
    unsigned short h = 192;
    **buffer = h;
    *buffer += 1;
    **buffer = 12;
    *buffer += 1;
    length += 2;
    put16bits(buffer, rr->type);
    put16bits(buffer, rr->_class);
    put32bits(buffer, rr->ttl);
    put16bits(buffer, rr->rDataLen);
    memcpy(*buffer, rr->rData, rr->rDataLen);
    length += rr->rDataLen;
    *buffer += rr->rDataLen;
  }
}

void encode_MX_resource_records(struct dnsRR* rr, char** buffer) {
    if (rr) {
    unsigned short h = 192;
    **buffer = h;
    *buffer += 1;
    **buffer = 30 + query_domain_length;
    *buffer += 1;
    length += 2;
    put16bits(buffer, rr->type);
    put16bits(buffer, rr->_class);
    put32bits(buffer, rr->ttl);
    put16bits(buffer, rr->rDataLen);
    memcpy(*buffer, rr->rData, rr->rDataLen);
    length += rr->rDataLen;
    *buffer += rr->rDataLen;
  }
}

void parse_A_rData(struct dnsRR* rr, char* buffer, unsigned short prfrc) {
  char* r = rr->rData;
  int j = -1;
  unsigned short temp;
  char *q = (char*)malloc(sizeof(char)*1000);
  memset(q, 0, 1000);
  do {
    j++;
    if (buffer[j] == '.' || buffer[j] == '\0') {
      memcpy(q, buffer, j);
      temp = atoi(q);
      *rr->rData = temp;
      rr->rData += 1;
      memset(q, 0, 1000);
      buffer= buffer + j + 1;
      j = -1;
    }
  } while (buffer[j] != '\0');
  rr->rData = r;
  rr->rDataLen = 4;
}
void parse_MX_rData(struct dnsRR* rr, char* buffer, unsigned short prfrc) {
  char* r = rr->rData;
  put16bits(&rr->rData, prfrc);
  int i = 0;
  while (buffer[i] != '.') {
    i++;
  }
  *rr->rData = i;
  rr->rData ++;
  memcpy(rr->rData, buffer, i);
  rr->rData += i;
  unsigned short x = 192;
  *rr->rData = x;
  rr->rData ++;
  *rr->rData = 12;
  rr->rData = r;
  rr->rDataLen = 4 + i + 1;
}
void parse_CNAME_rData(struct dnsRR* rr, char* buffer, unsigned short prfrc) {
  int length = 0;
  int j = -1;
  char* r = rr->rData;
  do {
    j++;
    if (buffer[j] == '.' || buffer[j] == '\0') {
      *r = j;
      r += 1;
      length += 1;
      memcpy(r, buffer, j);
      r += j;
      length += j;
      buffer = buffer + j + 1;
      j = -1;
    }
  } while (buffer[j] != '\0');
  *r = 0;
  r += 1;
  length += 1;
  rr->rDataLen = length;
}
//endcode packet
void encode_packet(struct packet* packet, char** buffer) {
  length = 0;
  encode_header(packet->header, buffer);
  encode_domain_name(buffer, packet->querySection->qName);
  put16bits(buffer, packet->querySection->qType);
  put16bits(buffer, packet->querySection->qClass);
  encode_A_CNAME_resource_records(packet->answerSection, buffer);
  encode_A_CNAME_resource_records(packet->authoritySection, buffer);
  encode_MX_resource_records(packet->additionalSection, buffer);
}

void decode_header(struct dnsHeader* hd, char** buffer) {
  hd->id = get16bits(buffer);
  hd->tag = get16bits(buffer);
  hd->queryNum = get16bits(buffer);
  hd->answerNum = get16bits(buffer);
  hd->authorNum = get16bits(buffer);
  hd->addNum = get16bits(buffer);
}

char* decode_domain_name(char** buffer) {
  char* pareseDomain = (char *)malloc((sizeof(char) * 1024));
  char* temp = pareseDomain;
  memset(pareseDomain, 0, 1024);
  while(**buffer != 0) {
    int len = (int)**buffer;
    *buffer += 1;
    memcpy(pareseDomain, *buffer, len);
    *buffer += len;
    pareseDomain += len;
    *pareseDomain = '.';
    pareseDomain += 1;
  }
  *buffer += 1;
  pareseDomain -= 1;
  *pareseDomain = '\0';
  return temp;
}

void decode_resource_records(struct dnsRR* rr, char** buffer) {
  memcpy(rr->dname, *buffer, 2);
  *buffer += 2;
  rr->type = get16bits(buffer);
  rr->_class = get16bits(buffer);
  rr->ttl = get32bits(buffer);
  rr->rDataLen = get16bits(buffer);
  memcpy(rr->rData, *buffer, rr->rDataLen);
  *buffer += rr->rDataLen;
}

void decode_packet(struct packet* packet, char** buffer) {
  decode_header(packet->header, buffer);
  packet->querySection->qName = decode_domain_name(buffer);
  packet->querySection->qType = get16bits(buffer);
  packet->querySection->qClass = get16bits(buffer);
  if (packet->header->answerNum != 0) {
    decode_resource_records(packet->answerSection, buffer);
  } else {
    packet->answerSection = NULL;
  }
  if (packet->header->authorNum != 0) {
    decode_resource_records(packet->authoritySection, buffer);
  } else {
    packet->authoritySection = NULL;
  }
  if (packet->header->addNum != 0) {
    decode_resource_records(packet->additionalSection, buffer);
  } else {
    packet->additionalSection = NULL;
  }
}

//get the query type
unsigned short getType(char *type) {
  enum RR_type type_code;
  if (!strcmp(type, "A")) {
    type_code = A;
    return type_code;
  } 
  else if (!strcmp(type, "MX"))
  {
    type_code = MX;
    return type_code;
  } else if (!strcmp(type, "CNAME")) {
    type_code = CNAME;
    return type_code;
  } else {
    printf("No such query type, [A | MX | CNAME] is considered\n");
    exit(0);
  }
}
// get resource record from txt
void getRR (struct dnsRR *head, char* fpath) {
  char* buf = (char *)malloc(sizeof(char) * BUF_SIZE);
  memset(buf, 0, BUF_SIZE); 
  FILE * fp = fopen(fpath, "r");
  struct dnsRR *p = head;
  if (fp == NULL) {
    printf("can not read the resource record");
    exit(0);
  }
  while (fgets(buf, BUFSIZ, fp) != NULL) {
    //get a  resource record
    int len = strlen(buf);
    //replace /n to \0
    buf[len-1] = '\0';
    len = strlen(buf);
    struct dnsRR *q = (struct dnsRR*)malloc(sizeof(struct dnsRR));
    q->dname = (char *)malloc(sizeof(char) * BUF_SIZE);
    q->rData = (char *)malloc(sizeof(char) * BUF_SIZE);
    memset(q->dname, 0, BUF_SIZE);
    memset(q->rData, 0, BUF_SIZE);
    //get the domain name
    for (int i = 0; i < len; i++) {
      if (buf[i] == ' ') {
        memcpy(q->dname, buf, i);
        buf = buf + i + 1;
        break;
      }
    }
    //move the buf
    len = strlen(buf);
    char* temp_type = (char *)malloc(sizeof(char) * BUF_SIZE);
    memset(temp_type, 0, BUF_SIZE);
    //get the type
    for (int i = 0; i < len; i++) {
      if (buf[i] == ' ') {
        q->type = getType(temp_type);
        buf += i + 1;
        break;
      }
      temp_type[i] = buf[i];
    }
    //move the buf
    len = strlen(buf);
    //get the preference
    unsigned short prfrc;
    char* tempPrfrc = (char*)malloc(sizeof(char) * BUF_SIZE);
    memset(tempPrfrc, 0, BUF_SIZE);
    for (int i = 0; i < len; i++) {
      if (buf[i] == ' ') {
        prfrc = atoi(tempPrfrc);
        buf += i + 1;
        break;
      }
      tempPrfrc[i] = buf[i];
    }
    // memcpy(q->rData, buf, len);
    if (q->type == 1) {
      parse_A_rData(q, buf, prfrc);
    } else if (q->type == 5) {
      parse_CNAME_rData(q, buf, prfrc);
    } else {
      parse_MX_rData(q, buf, prfrc);
    }
    q->_class = 0x1;
    q->ttl = 100;
    q->next = NULL;
    p->next = q;
    p = p->next;
  }
  fclose(fp);
}
// add A resource record to txt
void add_A_RR (struct packet packet, char* fpath) {
  FILE * fp = fopen(fpath, "a");
  if (fp == NULL) {
    printf("can not add the resource record to cache");
    exit(0);
  }
  fwrite(packet.querySection->qName, strlen(packet.querySection->qName), 1, fp);
  fwrite(" ", 1, 1, fp);
  fwrite("A", 1, 1, fp);
  fwrite(" ", 1, 1, fp);
  fwrite("0", 1, 1, fp);
  fwrite(" ", 1, 1, fp);
  char* char1 = (char *)malloc(sizeof(char) * BUF_SIZE);
  memset(char1, 0, BUF_SIZE);
  char* data = packet.answerSection->rData;

  itoa(*data, char1, 10);
  fwrite(char1, strlen(char1), 1, fp);
  fwrite(".", 1, 1, fp);
  data++;
  char* char2 = (char *)malloc(sizeof(char) * BUF_SIZE);
  memset(char2, 0, BUF_SIZE);
  itoa(*data, char2, 10);
  fwrite(char2, strlen(char2), 1, fp);
  fwrite(".", 1, 1, fp);
  data++;
  char* char3 = (char *)malloc(sizeof(char) * BUF_SIZE);
  memset(char3, 0, BUF_SIZE);
  itoa(*data, char3, 10);
  fwrite(char3, strlen(char1), 1, fp);
  fwrite(".", 1, 1, fp);
  data++;
  char* char4 = (char *)malloc(sizeof(char) * BUF_SIZE);
  memset(char4, 0, BUF_SIZE);
  itoa(*data, char4, 10);
  fwrite(char4, strlen(char4), 1, fp);
  fwrite("\n", 1, 1, fp);
  fclose(fp);
}
// add CNAME resource record to txt
void add_CNAME_RR (struct packet packet, char* fpath) {
  FILE * fp = fopen(fpath, "a");
  if (fp == NULL) {
    printf("can not add the resource record to cache");
    exit(0);
  }
  fwrite(packet.querySection->qName, strlen(packet.querySection->qName), 1, fp);
  fwrite(" ", 1, 1, fp);
  fwrite("CNAME", 5, 1, fp);
  fwrite(" ", 1, 1, fp);
  fwrite("0", 1, 1, fp);
  fwrite(" ", 1, 1, fp);
  char* data = (char *)malloc(sizeof(char) * BUF_SIZE);
  memset(data, 0, BUF_SIZE);
  char* tempData = packet.answerSection->rData;
  data = decode_domain_name(&tempData);
  fwrite(data, strlen(data), 1, fp);
  fwrite("\n", 1, 1, fp);
  fclose(fp);
}
// add MX resource record to txt
void add_MX_RR (struct packet packet, char* fpath) {
  FILE * fp = fopen(fpath, "a");
  if (fp == NULL) {
    printf("can not add the resource record to cache");
    exit(0);
  }
  fwrite(packet.querySection->qName, strlen(packet.querySection->qName), 1, fp);
  fwrite(" ", 1, 1, fp);
  fwrite("MX", 2, 1, fp);
  fwrite(" ", 1, 1, fp);
  fwrite("5", 1, 1, fp);
  fwrite(" ", 1, 1, fp);
  char* data = (char *)malloc(sizeof(char) * BUF_SIZE);
  memset(data, 0, BUF_SIZE);
  char* tempData = packet.answerSection->rData;
  tempData += 2;
  int len = (int)*tempData;
  tempData++;
  memcpy(data, tempData, len);
  fwrite(data, strlen(data), 1, fp);
  fwrite(".", 1, 1, fp);
  fwrite(packet.querySection->qName, strlen(packet.querySection->qName), 1, fp);
  fwrite("\n", 1, 1, fp);

  fwrite(data, strlen(data), 1, fp);
  fwrite(".", 1, 1, fp);
  fwrite(packet.querySection->qName, strlen(packet.querySection->qName), 1, fp);
  fwrite(" ", 1, 1, fp);
  fwrite("A", 1, 1, fp);
  fwrite(" ", 1, 1, fp);
  fwrite("0", 1, 1, fp);
  fwrite(" ", 1, 1, fp);
  char* char1 = (char *)malloc(sizeof(char) * BUF_SIZE);
  memset(char1, 0, BUF_SIZE);
  char* tempData2 = packet.additionalSection->rData;
  itoa(*tempData2, char1, 10);
  fwrite(char1, strlen(char1), 1, fp);
  fwrite(".", 1, 1, fp);
  tempData2++;
  char* char2 = (char *)malloc(sizeof(char) * BUF_SIZE);
  memset(char2, 0, BUF_SIZE);
  itoa(*tempData2, char2, 10);
  fwrite(char2, strlen(char2), 1, fp);
  fwrite(".", 1, 1, fp);
  tempData2++;
  char* char3 = (char *)malloc(sizeof(char) * BUF_SIZE);
  memset(char3, 0, BUF_SIZE);
  itoa(*tempData2, char3, 10);
  fwrite(char3, strlen(char1), 1, fp);
  fwrite(".", 1, 1, fp);
  tempData2++;
  char* char4 = (char *)malloc(sizeof(char) * BUF_SIZE);
  memset(char4, 0, BUF_SIZE);
  itoa(*tempData2, char4, 10);
  fwrite(char4, strlen(char4), 1, fp);
  fwrite("\n", 1, 1, fp);
  fclose(fp);
}
//find resource record
struct dnsRR* findRR(char* qName, unsigned short qType, struct dnsRR* head) {
  struct dnsRR* q = head ->next;
  while (q != NULL) {
    if(q->type == qType && !strcmp(qName, q->dname)) {
      printf("find in the cache\n");
      return q;
    }
    q = q->next;
  }
  return q;
}
// initialize query packet
void initializeQueryPacket(struct packet* qPacket) {
    qPacket->header = (struct dnsHeader*)malloc(sizeof(struct dnsHeader));
    memset(qPacket->header, 0, sizeof(struct dnsHeader));
    qPacket->querySection = (struct dnsQuery*)malloc(sizeof(struct dnsQuery));
    memset(qPacket->querySection, 0, sizeof(struct dnsQuery));
    qPacket->querySection->qName = (char *)malloc(sizeof(char) * BUF_SIZE);
    memset(qPacket->querySection->qName, 0, BUF_SIZE);
    qPacket->answerSection = NULL;
    qPacket->authoritySection = NULL;
    qPacket->additionalSection = NULL;
}
//initialize answer packet
void initializeAnswerPacket(struct packet* aPacket) {
    aPacket->header = (struct dnsHeader*)malloc(sizeof(struct dnsHeader));
    memset(aPacket->header, 0, sizeof(struct dnsHeader));
    aPacket->querySection = (struct dnsQuery*)malloc(sizeof(struct dnsQuery));
    memset(aPacket->querySection, 0, sizeof(struct dnsQuery));
    aPacket->querySection->qName = (char *)malloc(sizeof(char) * BUF_SIZE);
    memset(aPacket->querySection->qName, 0, BUF_SIZE);

    aPacket->answerSection = (struct dnsRR*)malloc(sizeof(struct dnsRR));
    memset(aPacket->answerSection, 0, sizeof(struct dnsRR));
    aPacket->answerSection->dname = (char *)malloc(sizeof(char) * BUF_SIZE);
    memset(aPacket->answerSection->dname, 0, BUF_SIZE);
    aPacket->answerSection->rData = (char *)malloc(sizeof(char) * BUF_SIZE);
    memset(aPacket->answerSection->rData, 0, BUF_SIZE);

    aPacket->authoritySection = (struct dnsRR*)malloc(sizeof(struct dnsRR));
    memset(aPacket->authoritySection, 0, sizeof(struct dnsRR));
    aPacket->authoritySection->dname = (char *)malloc(sizeof(char) * BUF_SIZE);
    memset(aPacket->authoritySection->dname, 0, BUF_SIZE);
    aPacket->authoritySection->rData = (char *)malloc(sizeof(char) * BUF_SIZE);
    memset(aPacket->authoritySection->rData, 0, BUF_SIZE);

    aPacket->additionalSection = (struct dnsRR*)malloc(sizeof(struct dnsRR));
    memset(aPacket->additionalSection, 0, sizeof(struct dnsRR));
    aPacket->additionalSection->dname = (char *)malloc(sizeof(char) * BUF_SIZE);
    memset(aPacket->additionalSection->dname, 0, BUF_SIZE);
    aPacket->additionalSection->rData = (char *)malloc(sizeof(char) * BUF_SIZE);
    memset(aPacket->additionalSection->rData, 0, BUF_SIZE);
}
//print packet
void printPacket(struct packet packet) {
  printf("Header:\n");
  printf("id: %d\n", packet.header->id);
  printf("tag: %d\n", packet.header->tag);
  printf("query number: %d\n", packet.header->queryNum);
  printf("answer number: %d\n", packet.header->answerNum);
  printf("authority number: %d\n", packet.header->authorNum);
  printf("additional number: %d\n", packet.header->addNum);
  printf("Query Section:\n");
  printf("query name : %s\n", packet.querySection->qName);
  printf("query type : %d\n", packet.querySection->qType);
  printf("query class : %d\n", packet.querySection->qClass);
  printf("Answer Section:\n");
  if (packet.header->answerNum != 0) {
    printf("name: %s\n", packet.querySection->qName);
    printf("type: %d\n", packet.answerSection->type);
    printf("class: %d\n", packet.answerSection->_class);
    printf("time to left: %d\n", packet.answerSection->ttl);
    printf("data length: %d\n", packet.answerSection->rDataLen);
    if (packet.querySection->qType == 1) {
      printf("data: %d", *packet.answerSection->rData);
      packet.answerSection->rData++;
      printf(".");
      printf("%d", *packet.answerSection->rData);
      packet.answerSection->rData++;
      printf(".");
      printf("%d", *packet.answerSection->rData);
      packet.answerSection->rData++;
      printf(".");
      printf("%d", *packet.answerSection->rData);
      printf("\n");
    } else if (packet.querySection->qType == 5) {
      printf("data: %s\n", decode_domain_name(&packet.answerSection->rData));
    }
  }
  printf("Autority Section:\n");
  if (packet.header->authorNum != 0) {
    printf("name: %s\n", packet.authoritySection->dname);
    printf("type: %d\n", packet.authoritySection->type);
    printf("class: %d\n", packet.authoritySection->_class);
    printf("time to left: %d\n", packet.authoritySection->ttl);
    printf("data length: %d\n", packet.authoritySection->rDataLen);
    printf("data: %s\n", packet.answerSection->rData);
  }
  printf("Addtional Section:\n");
  if (packet.header->addNum != 0) {
    printf("name: %s\n", packet.additionalSection->dname);
    printf("type: %d\n", packet.additionalSection->type);
    printf("class: %d\n", packet.additionalSection->_class);
    printf("time to left: %d\n", packet.additionalSection->ttl);
    printf("data length: %d\n", packet.additionalSection->rDataLen);
    printf("data: %d", *packet.additionalSection->rData);
    packet.additionalSection->rData++;
    printf(".");
    printf("%d", *packet.additionalSection->rData);
    packet.additionalSection->rData++;
    printf(".");
    printf("%d", *packet.additionalSection->rData);
    packet.additionalSection->rData++;
    printf(".");
    printf("%d", *packet.additionalSection->rData);
    printf("\n");
  }
  printf("End\n");
  printf("---------------------------------\n");
  printf("---------------------------------\n");
  printf("---------------------------------\n");
}
