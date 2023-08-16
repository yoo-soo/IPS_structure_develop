#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <dirent.h>
#include <pcap/pcap.h>
#include <string.h>
#include <netinet/in.h>
#include <stdbool.h>

#define PCAP_ERRBUF_SIZE  256
#define ETH_ADDR_LEN      6
#define IP_ADDR_LEN       4
#define SIZE_ETH         (sizeof(eth_hdr))
#define SIZE_IP          (sizeof(ip_hdr))
#define SIZE_TCP         (sizeof(tcp_hdr))
#define PROTO_ICMP      1
#define PROTO_TCP       6
#define PROTO_UDP       17

#define FILE_NAME_LEN 256
#define FILE_LEN  1000
#define PAYLOAD_MAX_LEN 1518
#define DIR_NAME_LEN 20
#define PATTERN_BUF_LEN 1518-(sizeof(eth_hdr))-(sizeof(ip_hdr))-(sizeof(tcp_hdr))
#define PATTERN_LINE_LEN 1024 

#define TCP_FIN  0x01
#define TCP_SYN  0x02
#define TCP_RST  0x04
#define TCP_PUSH 0x08
#define TCP_ACK  0x10
#define TCP_URG  0x20

#define QUEUE_MAX_SIZE 1024
#define TIME_DATA_LEN 256

typedef struct _PKTDATA{
  unsigned char log_file_name[TIME_DATA_LEN];
  unsigned char time[TIME_DATA_LEN];
  unsigned int protocol;
  unsigned char payload[PAYLOAD_MAX_LEN];
  unsigned int payload_len;
  unsigned char file_name[FILE_NAME_LEN];
} PKTDATA;

typedef struct _circular_queue {
  PKTDATA items[QUEUE_MAX_SIZE];
  int front, rear;
  pthread_mutex_t mutex;
} circular_queue;

typedef struct _eth_hdr{
  unsigned char dst[ETH_ADDR_LEN];
  unsigned char src[ETH_ADDR_LEN];
  unsigned short type;
} eth_hdr;

typedef struct _ip_hdr{
  unsigned char hd_len:4;              // header length
  unsigned char version:4;             // version
  unsigned char tos;                   // type of service
  unsigned short total_len;            // total length
  unsigned short id;                   // identification
  unsigned short frag_off;             // fragment offset field
  unsigned char ttl;                   // time to live
  unsigned char protocol;              // protocol
  unsigned short checksum;             // check sum
  unsigned char src_ip[IP_ADDR_LEN];   // source address
  unsigned char dst_ip[IP_ADDR_LEN];   // destination address
} ip_hdr;

typedef struct _tcp_hdr{
  unsigned short src_port;  // source port
  unsigned short dst_port;  // destination port
  unsigned int sequence;    // sequece number
  unsigned int acknowledge; // acknowledgement number
  unsigned short doff:4;
  unsigned short reserved:4;
  unsigned char flags;      // flags
  unsigned short window;    // window size
  unsigned short check;     // checksum
  unsigned short urgent;    // urgent pointer
} tcp_hdr;

typedef struct _udp_hdr{
  unsigned short src_port;  // source port
  unsigned short dst_port;  // destination port
  unsigned short len;       // length
  unsigned short checksum;  // checksum
} udp_hdr;

typedef struct _icmp_hdr{
  unsigned char type;       // type
  unsigned char code;       // code
  unsigned short checksum;  // checksum
  unsigned short id;        // identifier
  unsigned short seq;       // sequence number
} icmp_hdr;

typedef struct _PATTERN{
  char ptrn_target[PATTERN_LINE_LEN][PATTERN_BUF_LEN];
} PATTERN;

void parse_pkt(unsigned char *user, struct pcap_pkthdr *phrd, unsigned char *pdata, PKTDATA *pkt_data);

void initQueue(circular_queue *q);

int isEmpty(circular_queue *q);

int isFull(circular_queue *q);

int enqueue(circular_queue *q, PKTDATA *pkdt);

int dequeue(circular_queue *q, PKTDATA *pkdt);
