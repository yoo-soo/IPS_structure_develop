#include "pcap_parser.h"
  
void initQueue(circular_queue *q) {
  pthread_mutex_init(&(q->mutex), NULL);
  q->front = 0;
  q->rear = 0;
}

int isEmpty(circular_queue *q) {
  return q->front == q->rear;
}

int isFull(circular_queue *q) {
  return (q->front + 1) % QUEUE_MAX_SIZE == q->rear;
}

int enqueue(circular_queue *q, PKTDATA *pkdt) {
  pthread_mutex_lock(&(q->mutex));
  if (isFull(q)) {
    //printf("Queue is full\n");
    pthread_mutex_unlock(&(q->mutex));
    return 0;
  }
  memcpy(&(q->items[q->front]), pkdt, sizeof(PKTDATA));
  q->front = (q->front + 1) % QUEUE_MAX_SIZE;
  pthread_mutex_unlock(&(q->mutex));
  return 1;
}

int dequeue(circular_queue *q, PKTDATA *pkdt) {
  pthread_mutex_lock(&(q->mutex));
  if (isEmpty(q)) {
    //printf("Queue is Empty\n");
    pthread_mutex_unlock(&(q->mutex));
    return 0;
  }
  memcpy(pkdt, &(q->items[q->rear]), sizeof(PKTDATA));
  q->rear = (q->rear + 1) % QUEUE_MAX_SIZE;
  pthread_mutex_unlock(&(q->mutex));
  return 1;
}
