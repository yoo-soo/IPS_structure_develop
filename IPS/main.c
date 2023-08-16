#include "pcap_parser.h"

circular_queue *q;

void* user_routine(unsigned char *user, struct pcap_pkthdr *phrd, unsigned char *pdata){
  PKTDATA *pkt_data = (PKTDATA *)malloc(sizeof(PKTDATA));
  int i;
  strcpy(pkt_data->file_name, user);
  char read_dir_path[FILE_NAME_LEN] = {0, };
  char upload_dir_file[FILE_NAME_LEN] = {0, };

  snprintf(read_dir_path, sizeof(read_dir_path), "/home3/soo0103/IPS_structure_develop/read_pcap/%s", pkt_data->file_name);

  snprintf(upload_dir_file, sizeof(upload_dir_file), "/home3/soo0103/IPS_structure_develop/upload_pcap/%s", pkt_data->file_name);

  memset(pkt_data, 0x00, sizeof(pkt_data));
  parse_pkt(user, phrd, pdata, pkt_data);

  if(enqueue_r(q, pkt_data) == 0){
    printf("Failed to enqueue file [%s]. Queue is full\n", pkt_data->file_name);
    //continue;
  } else {  // enqueue 성공 시
    printf("\n***********Enqueue***********\nFile name : [%s]\n", pkt_data->file_name);
    // 읽은 파일은 다른 디렉토리로 이동
    if( rename(upload_dir_file, read_dir_path) != 0){
      printf("\n********디렉토리 이동 실패********\nfile name : [%s]\n", pkt_data->file_name);
    } else {
      printf("\n********디렉토리 이동 성공********\nfile name : [%s]\n", pkt_data->file_name);
    }
  }
  free(pkt_data);
  return NULL;
}

void *read_thread_run(){
  DIR *dir = NULL;
  struct dirent* entry = NULL;
  char errbuf[PCAP_ERRBUF_SIZE];
  char str[PCAP_ERRBUF_SIZE];
  pcap_t *p;
  char packet_dir[FILE_NAME_LEN] = {0, };
  char file_path[FILE_NAME_LEN] = {0, };
  snprintf(packet_dir, sizeof(packet_dir),
      "/home3/soo0103/IPS_structure_develop/upload_pcap");

  while(1){
    dir = opendir(packet_dir);

    if (dir == NULL){
      printf("디렉토리를 열 수 없습니다.\n");
      return NULL;
    }

    while((entry = readdir(dir)) != NULL) {
      if ((strstr(entry->d_name, ".pcap") != NULL) ||
          (strstr(entry->d_name, ".cap")  != NULL)) {
        snprintf(file_path, sizeof(file_path), "%s/%s", packet_dir, entry->d_name);
        p = pcap_open_offline(file_path, errbuf);

        if (p != NULL) {
          pcap_loop(p, 3, (void *)user_routine, entry->d_name);
        }
      }
    }
    closedir(dir);
  }
  return NULL;
}

void *detect_thread_run(void *ptrn){
  PKTDATA pkt_d;
  PATTERN *ptrn_f = (PATTERN *)ptrn;
  int i, row_cnt;
  char* ptrn_check;
  FILE *log;
  char log_dir_path[FILE_NAME_LEN] = {0, };
  char log_file_path[FILE_NAME_LEN] = {0, };

  struct tm* time_info;
  time_t t = time(NULL);
  time_info = localtime(&t);

  snprintf(pkt_d.log_file_name, sizeof(PKTDATA), "%d-%.2d-%.2d", time_info->tm_year + 1900, time_info->tm_mon + 1, time_info->tm_mday);
  snprintf(log_dir_path, sizeof(log_dir_path), "/home3/soo0103/IPS_structure_develop/log_pcap");
  snprintf(log_file_path, sizeof(log_file_path), "%s/%s.txt", log_dir_path, pkt_d.log_file_name);

  while(1) {
    if(dequeue(q, &pkt_d) == 0) {
      continue;
    } else {
      printf("\n***********Dequeue***********\nFile name : [%s]\n", pkt_d.file_name);
    }

    for (i=0; i<ptrn_f->ptrn_cnt; i++){
      if(memmem(pkt_d.payload, pkt_d.payload_len, 
            ptrn_f->ptrn_target[i], strlen(ptrn_f->ptrn_target[i]))){
        printf("\n***********탐지 완료***********\n"
            "pcap file : [%s]\npattern[%d]  : [%s]\n"
            "payload   : [%s]\n", 
            pkt_d.file_name,
            i,
            ptrn_f->ptrn_target[i],
            pkt_d.payload);

        t = time(NULL);
        time_info = localtime(&t);
        log = fopen(log_file_path, "a");

        if( log == NULL ){
          printf("파일 열기 실패!\n");
          exit(0);
        }
        fprintf(log, "%d-%.2d-%.2d %.2d:%.2d:%.2d | %s | %s\n", time_info->tm_year + 1900, 
            time_info->tm_mon + 1, 
                                                                time_info->tm_mday,
                                                                time_info->tm_hour,
                                                                time_info->tm_min,
                                                                time_info->tm_sec,
                                                                ptrn_f->ptrn_target[i],
                                                                pkt_d.file_name);

        fclose(log);
        break;
      } 
    } 
    if ( i == ptrn_f->ptrn_cnt ){
      printf("탐지 실패\n");  
    }
  }
}

int main(){                                                             
  pthread_t read_thread, detect_thread;                                 
  int thread_err;                                                       
  FILE *cfg;                                                            
  cfg = fopen("/home3/soo0103/IPS_structure_develop/pattern.cfg", "r"); 
  char file_buff[FILE_LEN] = {0, };                                     
  void *t_return;                                                       
  //char cfg_buf[PATTERN_LINE_LEN][PATTERN_BUF_LEN] = {0, {0, }};       
  PATTERN ptrn;                                                         
  memset(ptrn.ptrn_target, 0x00, sizeof(ptrn.ptrn_target));             
  int i, j, k;                                                          
                                                                        
  q = calloc(1, sizeof(circular_queue));                                
  if ( q == NULL ) {                                                    
    printf("메모리 할당 실패");                                         
    exit(0);                                                            
  }                                                                     
                                                                        
  // fopen 함수 실행 실패 시 오류 처리                                  
  if ( cfg == NULL ){                                                   
    printf("cfg 파일 열기 실패\n");                                     
    exit(0);                                                            
  }                                                                     
                                                                        
  // cfg 파일 문자열 읽어오기                                           
  i = 0;                                                                
  while(fgets(file_buff, FILE_LEN, cfg) != NULL){                       
    snprintf(ptrn.ptrn_target[i], sizeof(ptrn.ptrn_target[i]), file_buff);
    ptrn.ptrn_target[i][strlen(ptrn.ptrn_target[i])-1] = '\0';          
    i++;
  }                                                                  

  initQueue(q);                                                         
  
  // 스레드 생성, 실행 및 오류 처리                                     
  if ( thread_err = pthread_create(&read_thread,                        
                                  NULL, 
                                  read_thread_run,                      
                                  NULL) ){
    printf("READ_Thread Err = %d", thread_err);                         
  } 
  if ( thread_err = pthread_create(&detect_thread,                      
                                  NULL, 
                                  detect_thread_run,                    
                                  (void *)&ptrn )){
    printf("DETECT_Thread Err = %d", thread_err);
  }
  pthread_join(read_thread, &t_return);
  pthread_join(detect_thread, &t_return);

  free(q);
  fclose(cfg);
}
