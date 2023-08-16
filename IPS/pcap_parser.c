#include "pcap_parser.h"
  
void view_ether_addr(const char *pre, unsigned char *ethaddr){
  int i = 0;

  for(i=0; i<ETH_ADDR_LEN; i++){
    if(i == 0){
      printf("%s%02x", pre, ethaddr[i]);
    } else {
      printf(":%02x", ethaddr[i]);
    }
  }
  printf("\n");
}

void view_ip_addr(unsigned char *ipaddr){
  int i = 0;

  for(i=0; i<IP_ADDR_LEN; i++){
    if(i == 0){
      printf("%1d", ipaddr[i]);
    } else {
      printf(".%1d", ipaddr[i]);
    }
  }
  printf("\n");
}

void decode_eth(unsigned char *ethaddr){
  eth_hdr *ethhd = (eth_hdr *)ethaddr;
/*
  printf("\n=============ETH=============\n");
  view_ether_addr("dst MAC Addr | ", ethhd->dst);
  view_ether_addr("src MAC Addr | ", ethhd->src);
  //printf("type | %04x\n", ntohs(ethhd->type)); // byte ordering
  switch(ntohs(ethhd->type)){
    case 2048:
      printf("type | IPv4\n");
      break;
  }
  printf("=============================\n");
*/
}

unsigned char decode_ip(unsigned char *ipaddr){
  ip_hdr *header = (ip_hdr *)ipaddr;
  /*
  printf("\n==============IP=============\n");
  printf("Version : %x\n", header->version);
  printf("Header Length : %x\n", header->hd_len);
  printf("Differentiated Services Field : 0x%02x\n", ntohs(header->tos));
  printf("Total Length : %d\n", ntohs(header->total_len));
  printf("Identification : %x\n", ntohs(header->id));
  printf("Fragment Offset : %x\n", ntohs(header->frag_off));
  printf("Time to Live : %d\n", header->ttl);
  
  switch((int)(header->protocol)){
    case 1 :  // ICMP
      printf("Protocol : ICMP (%x)\n", header->protocol);
      break;
    case 6 :  // TCP
      printf("Protocol : TCP (%x)\n", header->protocol);
      break;
    case 17 : // UDP
      printf("Protocol : UDP (%x)\n", header->protocol);
      break;
  }
  
  printf("Header Checksum : 0x%x\n", ntohs(header->checksum));
  printf("dst IP Addr : ");
  view_ip_addr(header->dst_ip);
  printf("src IP Addr : ");
  view_ip_addr(header->src_ip);
  printf("=============================\n");
  */
  return header->protocol;
}

int decode_tcp(unsigned char *tcp){
  tcp_hdr *header = (tcp_hdr *)tcp;
/*
  printf("\n=============TCP=============\n");
  printf("Src Port : %d\n", ntohs(header->src_port));
  printf("Dst Port : %d\n", ntohs(header->dst_port)); 
    
  printf("Sequence Number : %x\n", ntohs(header->sequence));
  printf("Acknowledgment : %x\n", ntohs(header->acknowledge));
  printf("Header Length : %d\n", header->reserved);
  printf("Flags : 0x%03x\n", header->flags);
  printf("Window : %x\n", ntohs(header->window));
  printf("Checksum : 0x%x\n", ntohs(header->check));
  printf("Urgent Pointer : %x\n", ntohs(header->urgent));
  printf("=============================\n");
*/
  return sizeof(header);
}

int decode_udp(unsigned char *udp){
  udp_hdr *header = (udp_hdr *)udp;
/*
  printf("\n=============UDP=============\n");
  printf("Src Port : %d\n", ntohs(header->src_port));
  printf("Dst Port : %x\n", ntohs(header->dst_port));
  printf("header len : %u\n", ntohs(header->len));
  printf("Checksum : 0x%x\n", ntohs(header->checksum));
  printf("=============================\n");
*/
  return sizeof(header);
}
//
int decode_icmp(unsigned char *icmp){
  icmp_hdr *header = (icmp_hdr *)icmp;
/*
  printf("\n=============ICMP=============\n");
  printf("TYPE : %x\n", header->type);
  printf("CODE : %x\n", header->code);
  printf("Checksum : 0x%x\n", ntohs(header->checksum));
  printf("Identifier : %x\n", ntohs(header->id));
  printf("Sequence Number : %x\n", ntohs(header->seq));
  printf("================================\n");
  */
  return sizeof(header);
}

void parse_pkt(unsigned char *user, struct pcap_pkthdr *phrd, unsigned char *pdata, PKTDATA *pkt_data){
  uint32_t len = phrd->caplen;
  unsigned char *pkt = pdata;
  int proto_type = 0;

  //printf("######## TOTAL LEN : [%u] ########\n", len);
  decode_eth(pkt);
  len -= SIZE_ETH;
  pkt += SIZE_ETH;
  //printf("eth : %d\n", *pkt);
  //printf("Ether size : [%d] len : [%d]\n", SIZE_ETH, len);

  proto_type = decode_ip(pkt);
  len -= SIZE_IP;
  pkt += SIZE_IP;
  //printf("ip : %d\n", *pkt);
  //printf("IP size : [%d] len : [%d]\n", SIZE_IP, len);

  pkt_data->protocol = proto_type;
  if(proto_type == PROTO_TCP){
    int tcphd_len = 0;
    //printf("\nprotocol : tcp\n");
    tcphd_len = decode_tcp(pkt);
    pkt += tcphd_len;
    len -= tcphd_len;
    //printf("TCP hdr size : [%d] len : [%d]\n", tcphd_len, len);
  } else if(proto_type == PROTO_UDP){
    int udphd_len = 0;
    //printf("\nprotocol : udp\n");
    udphd_len = decode_udp(pkt);
    pkt += udphd_len;
    len -= udphd_len;
    //printf("UDP hdr size : [%d] len : [%d]\n", udphd_len, len);
  } else if(proto_type == PROTO_ICMP){
    int icmphd_len = 0;
    //printf("\nprotocol : icmp!!\n");
    icmphd_len = decode_icmp(pkt);
    pkt += icmphd_len;
    len -= icmphd_len;
    //printf("ICMP hdr size : [%d] len : [%d]\n", icmphd_len, len);
  }

  if(len>0){
    pkt_data->payload_len = len;
    memcpy(pkt_data->payload, pkt, len);

    // printf 함수로 읽지 못하는 payload 문자열 isprint 함수로 읽기
    for(i=0; pkt_data->payload_len>i; i++){               
      if(isprint(pkt_data->payload[i])){                  
        printf("%c", pkt_data->payload[i]);               
      } else {                                            
        printf(" ");
      }
    }   
  }
}
