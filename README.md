# IPS_structure_develop

### 개발 일정
```
* 개발 구성도 설계
  * 2023.07.31 ~ 2023.08.03
* 개발 코드 작성
  * 2023.08.04 ~ 2023.08.11
```
## 개요
* IPS 구조를 단순화 하여 개발한다.
* pcap read - pattern match - logging

> ## 요구사항
> > 1. 프로그램 실행시 cfg 파일에서 패턴을 읽는다. 
> >    + 패턴은 단순 문자열
> > 2. 특정 디렉토리에서 *.pcap 또는 *.cap 파일을 주기적으로 읽는다.
> >     + 읽은 파일은 다른 디렉토리로 이동해야 한다.
> > 3. 읽은 파일에 패턴이 존재하는지 검사한다.
> > 4. 패턴이 존재한다면 log 디렉토리에 로깅한다.
> >     + 매치 시간, 패턴, pcap파일 이름
> > 5. 멀티스레드로 동작한다.
> >     + 패킷 파일 읽는 스레드
> >     +  패턴 매치 및 로깅 스레드

## 동작 구조
### ▶ main()
+ 프로그램 실행 시 main 함수에서 *.cfg 파일을 읽어옴
+ Thread를 동작 시킴
+ CircularQueue index (rear/front)와 Mutex (lock/unlock) 을 초기화 시킴

![main](https://github.com/yoo-soo/IPS_structure_develop/assets/80819675/04de1e63-bb5c-4570-b768-623aab5e03c4)

### ▶ MultiThread

![image](https://github.com/yoo-soo/IPS_structure_develop/assets/80819675/e8f1ac44-9ef0-4f99-b28c-3dbe6e6f5e75)

+ ReadThread
  + 디렉토리(../upload_pcap)에서 *.pcap 또는 *.cap 파일을 주기적으로 읽는다.
    + *.pcap 또는 *.cap 파일이 아니면 무시하도록 한다.
  + 읽은 파일은 Queue로 Enqueue 된다.
  + 스레드에서 패킷 파일을 읽은 후에 pthread_mutex_lock 함수를 사용한다.
    + 스레드에서 패킷 파일을 Enqueue하면 pthread_mutex_unlock 한다.
  + 스레드에서 읽힌 파일은 다른 디렉토리(../read_pcap)로 이동한다. ( 하나의 파일이 반복적으로 읽히는 것에 대한 방지 )
  + 만약, 스레드에서 큐에 enque할 때, 큐가 포화 상태일 경우, 해당 패킷은 대기하지 않고 버려진다.
    + 버러진 파일이 발생하면, 파일이 버려진 시간과 버려진 파일 명을 남긴다.

+ DetectThread
  + enque할 때와 동일하게 deque할 때도 마찬가지로 pthread_mutex_lock 한다.
  + deque 동작이 끝나면 pthread_mutex_unlock 한다.
  + Dequeue 된 데이터(파일 값)를 패턴 일치 여부에 따라 로그에 남기거나 아무 동작도 하지 않도록 한다.
  + cfg 파일의 패턴과 읽은 파일 값의 패턴이 일치한 경우에는 [현재 날짜].log 의 형태로 디렉토리(../log_pcap)에 로깅한다.

+ 패킷 수 제한(QUE_LEN)
  + 1024 로 제한한다.
    + 일단 현재 개발 요구사항에 맞게 구현한다면 자동화가 아닌 패킷 파일을 디렉토리에 수동으로 넣어주기 때문에 1024로 정했다.
    + 해당 부분에서는 얼마나 많은 패킷 파일을 디렉토리에 전달하게 되느냐에 따라 유동적으로 변경할 수 있도록 한다.

+ 큐의 종류
  + 원형큐 로 구현한다.
    + 주어진 공간 내에서 메모리 자원을 낭비하지 않도록 하기 위해 사용한다.

### ▶ Matching Method

![image](https://github.com/yoo-soo/IPS_structure_develop/assets/80819675/373b5543-b1e8-4401-8034-f3ee9f2336ca)

+ 패턴 매칭 방법
  + *.cfg 파일의 문자열과 읽어온 패킷 파일의 내용(문자열)을 fgets 함수를 사용해 2차원 배열로 읽어온 후 비교하여 매칭한다.
+ cfg 파일 구조는 단순 문자열 패턴 구조 ( ex 'aaaa' )로 하고, 여러 줄을 읽혀 매칭하도록 한다.
  + n줄 중에서 하나의 줄에서라도 패턴 탐지가 되면, 패턴 파일 읽는 것을 멈추고 log 한다.
+ 패턴 매칭 시 생성되는 log 파일은 <time.h> 함수를 사용해 탐지 시간을 파일명으로 가지게 한다. (ex. 2023-08-09.log)
+ *.cfg 파일 내 입력할 수 있는 패턴의 개수는 1024개로 결정하였다. 이 또한 탐지하게 될 패턴의 개수에 따라 유동적이게 변경할 수 있도록 한다.
  + 입력할 수 있는 패턴의 길이는 payload에서 문자열을 읽어올 것이기 때문에 전체 캡처 패킷 길이에서 ETH, IP, PROTOCOL 헤더를 뺀 나머지 payload 공간에 맞추어 결정한다.
    + 1518 - (eth_hdr - ip_hdr - protocol(TCP(20)/UDP(8)/ICMP(8))_hdr)

### ▶ Queue Struct

![image](https://github.com/yoo-soo/IPS_structure_develop/assets/80819675/541d59ac-1d2e-4199-9c2c-5fc6c92b9ed9)

## ▶ Protocol Stack Structure
### ▶ ETH
![image](https://github.com/yoo-soo/IPS_structure_develop/assets/80819675/c0d675f4-1ffd-47bf-a579-288a11acdcc6)

```C
typedef struct _eth_hdr{                                                
  unsigned char dst[ETH_ADDR_LEN];                                      
  unsigned char src[ETH_ADDR_LEN];                                      
  unsigned short type;                                                  
} eth_hdr;  
```
### ▶ IP
![image](https://github.com/yoo-soo/IPS_structure_develop/assets/80819675/c706ab49-5626-4264-acdf-208bcace444b)

```C
typedef struct _ip_hdr{
  unsigned char hd_len:4;    // header length
  unsigned char version:4;    // version
  unsigned char tos;         // type of service
  unsigned short total_len;  // total length
  unsigned short id;         // identification
  unsigned short frag_off;   // fragment offset field
  unsigned char ttl;         // time to live
  unsigned char protocol;    // protocol
  unsigned short checksum;   // check sum
  unsigned char src_ip[IP_ADDR_LEN];         // source address
  unsigned char dst_ip[IP_ADDR_LEN];         // destination address
} ip_hdr;
```
### ▶ TCP
![image](https://github.com/yoo-soo/IPS_structure_develop/assets/80819675/f4d42c5d-baf0-4f27-86ad-3363f2a06578)

```C
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
```
### ▶ UDP
![image](https://github.com/yoo-soo/IPS_structure_develop/assets/80819675/7b695337-dd77-447b-8994-f974d54f7009)

```C
typedef struct _udp_hdr{
  unsigned short src_port;  // source port
  unsigned short dst_port;  // destination port
  unsigned short len;       // length
  unsigned short checksum;  // checksum
} udp_hdr;
```
### ▶ ICMP
![image](https://github.com/yoo-soo/IPS_structure_develop/assets/80819675/cccf5cf5-2078-4be4-861e-ab6d07299015)

```C
typedef struct _icmp_hdr{
  unsigned char type;       // type
  unsigned char code;       // code
  unsigned short checksum;  // checksum
  unsigned short id;        // identifier
  unsigned short seq;       // sequence number
} icmp_hdr;
```
