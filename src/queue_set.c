#include "common.h"
#include "queue_set.h"

#define QUEUE_CAPACITY 1024

void initQueue(MutexQueue *mq, int max_size){
        mq->front = mq->rear = NULL;
        mq->size = 0;
        mq->capacity = max_size;
        pthread_mutex_init(&mq->lock, NULL);
        pthread_cond_init(&mq->not_empty, NULL);
        pthread_cond_init(&mq->not_full, NULL);
        mq->shutdown_flag = 0;
}


int isEmpty(MutexQueue *mq){
        pthread_mutex_lock(&mq->lock);
        int status = (mq->size == 0);
        pthread_mutex_unlock(&mq->lock);
        return status;
}


int isFull(MutexQueue *mq){
        pthread_mutex_lock(&mq->lock);
        int status = (mq->capacity > 0 && mq->size >= mq->capacity);
        pthread_mutex_unlock(&mq->lock);
        return status;
}


int enqueue(MutexQueue *mq, QueueMessage *item){
        pthread_mutex_lock(&mq->lock);
        while(mq->capacity > 0 && mq->size >= mq->capacity){
                pthread_cond_wait(&mq->not_full, &mq->lock);
        }

        if(mq->shutdown_flag){
                pthread_mutex_unlock(&mq->lock);
                return -1;
        }

        Node *new_node = (Node*)malloc(sizeof(Node));
        if(new_node == NULL){
                fprintf(stderr, "Error: Failed to memory allocate for new item\n");
                pthread_mutex_unlock(&mq->lock);
                return -1;
        }

        new_node->data = item;
        new_node->next = NULL;

        if(mq->rear == NULL){
                mq->front = mq->rear = new_node;
        } else{
                mq->rear->next = new_node;
                mq->rear = new_node;
        }

        mq->size++;

        pthread_cond_signal(&mq->not_empty);
        pthread_mutex_unlock(&mq->lock);

        return 0;
}

QueueMessage *dequeue(MutexQueue *mq){
        pthread_mutex_lock(&mq->lock);

        // if queue is empty, waiting(atomic unlocking)
        while(mq->size == 0 && !mq->shutdown_flag){
                pthread_cond_wait(&mq->not_empty, &mq->lock);
        }

        if(mq->size == 0 && mq->shutdown_flag){
                pthread_mutex_unlock(&mq->lock);
                return NULL;
        }

        Node *temp = mq->front;
        QueueMessage *value = temp->data;
        mq->front = temp->next;

        if(mq->front == NULL){
                mq->rear = NULL;
        }

        free(temp);
        mq->size--;
        pthread_cond_signal(&mq->not_full);
        pthread_mutex_unlock(&mq->lock);

        return value;
}

void shutdownQueue(MutexQueue *mq){
        pthread_mutex_lock(&mq->lock);
        mq->shutdown_flag = 1;
        pthread_cond_broadcast(&mq->not_empty);
        pthread_cond_broadcast(&mq->not_full);
        pthread_mutex_unlock(&mq->lock);
        printf("Shutdown queue....\n\n");
}


void destroyQueue(MutexQueue *mq){
        printf("Queue destroying start\n");
        pthread_mutex_lock(&mq->lock);

        Node *current = mq->front;
        while(current != NULL){
                Node *next_node = current->next;
                free(current);
                current = next_node;
        }

        mq->front = NULL;
        mq->rear = NULL;
        mq->size = 0;


        pthread_mutex_unlock(&mq->lock);
        pthread_mutex_destroy(&mq->lock);
        pthread_cond_destroy(&mq->not_empty);
        pthread_cond_destroy(&mq->not_full);
        printf("Queue destroy success\n\n");
}

MutexQueueList *createQueueList(int thread_cnt){
        MutexQueueList *list = (MutexQueueList *)malloc(sizeof(MutexQueueList));
        if(list==NULL){
                fprintf(stderr,"Failed to malloc MutexQueueList\n");
                return NULL;
        }

        list->mutexQueue = (MutexQueue**)malloc(sizeof(MutexQueue*)*thread_cnt);
        if(list->mutexQueue == NULL){
                fprintf(stderr, "Failed to malloc each MutexQueue\n");
                return NULL;
        }

        list->num_of_queue = thread_cnt;

        for(int i = 0; i<thread_cnt; i++){
                MutexQueue *each_queue = list->mutexQueue[i];
                each_queue = (MutexQueue*)malloc(sizeof(MutexQueue));
                if(each_queue == NULL){
                        fprintf(stderr, "Failed to malloc each_queue in queue list\n\n");
                        return NULL;
                }
                list->mutexQueue[i] = each_queue;
                initQueue(list->mutexQueue[i], QUEUE_CAPACITY);
        }

        return list;
}

void destroyQueueList(MutexQueueList *list){
        if(list == NULL) return;
        for(int i=0; i < list->num_of_queue; i++){
                if(list->mutexQueue[i] !=NULL){
                        destroyQueue(list->mutexQueue[i]);
                        free(list->mutexQueue[i]);
                }
        }

        free(list->mutexQueue);
        free(list);
}


MutexQueue *getQueue(MutexQueueList *list, int idx){
        if(list == NULL || idx < 0 || idx > list->num_of_queue) return NULL;
        return list->mutexQueue[idx];
}