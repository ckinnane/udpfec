#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <pthread.h>
#include <time.h>
#include <sys/timerfd.h>
#include "../FEC/fec.h"

#define PACKET_SIZE 65536
#define MAGIC 242456 /* Marker value out-of-band for encap headers */
#define MAXK 10 /* this controls the base FEC k value and min packets in a frame */
#define FEC_MAX 1440 /* if pckts > MAXK use this, else split buffer into MAXK pckts */
#define MAXN 40
#define THRESHOLD 1 /* Acceptable packet loss threshold in percent */
#define INTERVAL 2 
#define REPORT (int)(60/INTERVAL) 
#define BUF_LIMIT ((MAXK*FEC_MAX)/4)
#define STREAM_BUFFER (((BUF_LIMIT*MAXN)/MAXK)+(PACKET_SIZE/4)) /* allocated in words of 4 byte each - so, times 4. */
#define BUFFERS 240 /* number of cyclic buffers to process FEC with */

#define THREADCOUNT 10 /* Number of separate encode transmit threads */
#define REALIGN 30 /* number of frames to wait on when frames are skipped */
#define SLEW (BUFFERS-REALIGN) /* which buffer to search forward from in transmission */

/* STREAM_BUFFER and MAXLOSS must be the same on both sides */

/*
#define MYDEBUG 1 
*/

#define LATENCY 20 /*   latency is the interval for double bufferring input */
#define COMPRESSOR 0.95 /*   The bandwidth compressor for catching up to slew */

pthread_mutex_t mutex1 = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex2 = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t encode_process_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t  encode_process_var   = PTHREAD_COND_INITIALIZER;
pthread_mutex_t encode_transmit_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t encode_transmitB_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t  encode_transmit_var   = PTHREAD_COND_INITIALIZER;
pthread_mutex_t decode_process_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t  decode_process_var   = PTHREAD_COND_INITIALIZER;
pthread_mutex_t decode_transmit_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t  decode_transmit_var   = PTHREAD_COND_INITIALIZER;

struct capture {
/*    struct chan *active;  points to the active buffer */
/*    struct chan *inactive;  points to the inactive buffer */
    uint16_t active;
    uint16_t prev;
    struct chan *raw[BUFFERS]; /* points to the incoming buffers. */
    uint16_t rawcount; /* increment when a new frame is ready to process */
    uint16_t processcount; /* increment when a frame is ready to transmit */
    struct chan *coded[BUFFERS]; /*points to FEC buffer. */
};
 
struct chan {
    uint32_t pckt_count;
    uint32_t release; /* points to current packet to be released from the buffer */
    uint32_t buf_end;
    uint32_t buf[STREAM_BUFFER];
    uint32_t frameno;
    uint32_t framedone;
    uint32_t raw_status;
    uint32_t code_status;
    uint32_t duration;  /* total time this frame takes in nanoseconds. */
};

struct thread_pass {
    int sfd, rfd; /* UDP File descriptors */
    int er_fd; /* timer File Descriptors */
    struct sockaddr_storage * peer_addrptr;
    struct capture *encode;
    struct capture *decode;
    uint32_t decodeactive; /* maintain intended order over arrival order */
    uint32_t losscount; /* keep track of the count of failed packets */
    uint32_t rawloss; /* keep track of the count of lost raw packets */
    uint32_t expected; /* keep track of the count of all expected raw packets */
    uint32_t total; /* keep track of the count of all received raw packets */
    uint32_t extra; /* keep track of the count of redundant packets */
    uint32_t frameloss; /* keep track of the count of lost frames */
    uint32_t foundcount; /* keep track of the count of transmitted packets */
    int type; /* type 0 for entrance, 1 for exit */
    uint32_t losscomp; /* integer MAXK < k < MAXN determines dynamic redundancy */
};

void capture_init (struct capture *stream) {
    int i;
    stream->active = 1;
    stream->prev = 0;
    stream->rawcount = 0;
    stream->processcount = 0;
    for (i=0;i<BUFFERS;i++) {
        stream->raw[i] = malloc(sizeof(struct chan)); 
        stream->coded[i] = malloc(sizeof(struct chan)); 
        stream->coded[i]->release = 0;
        stream->coded[i]->buf_end = 0;
        stream->coded[i]->pckt_count = 0;
        stream->coded[i]->frameno = 1;
        stream->coded[i]->framedone = 2;
        stream->coded[i]->raw_status = 0;
        stream->coded[i]->code_status = 0;
    }
    return;
}

struct encode_thread {
    pthread_t thread; /* the pthread object */
    int ret;   /* the specific return value */
    int id;    /* the id of this thread for an array of these structs */
    struct thread_pass *thread_info; /* be an overclass of thrad_info */
};

void *encode_trans (struct encode_thread *thread);

void enc_thread_init (struct thread_pass *thread_info, struct encode_thread **list) {
    int i;
    for (i=0;i<THREADCOUNT;i++) {
        list[i] = malloc(sizeof(struct encode_thread)); 
        struct encode_thread *this = list[i];
        this->id = i;
        this->thread_info = thread_info;
        this->ret = pthread_create( &(this->thread), NULL,encode_trans , this);
#ifdef MYDEBUG
        printf("EncThrIni Create ID: %u\n",this->id);
#endif
    }
    return;
}

void enc_thread_wait (struct encode_thread **list) {
    int i;
    for (i=0;i<THREADCOUNT;i++) {
        struct encode_thread *this = list[i];
#ifdef MYDEBUG
        printf("EncThrWai Create ID: %u\n",this->id);
#endif
        pthread_join(this->thread, NULL);
#ifdef MYDEBUG
        printf("EncThrWai Post ID: %u\n",this->id);
#endif
    }
    return;
}

/* with cyclic buffers, this cyles the active index by 1 and keeps track of prev */
void swap_chan (struct capture * stream_buf) {
    int active, prev;
    pthread_mutex_lock(&mutex1);
    active = stream_buf->active;
    prev = active;
    active++;
    if (active == BUFFERS) {
        active = 0;
    }
    stream_buf->active = active;
    stream_buf->prev = prev;
    pthread_mutex_unlock(&mutex1);
    return;
}

/* when called, encode using FEC library the given capture and produce a new capture*/
void * encapcode (struct chan *incoming, struct chan *outgoing, uint32_t frameno, int fd, struct itimerspec *itval, uint32_t losscomp) {
/* firstly, an array of pointers to break up the incoming into FEC input format */
    unsigned char **src; /* array of pointers to packet buffers */
    unsigned char *buf_end = &(incoming->buf[incoming->buf_end]);
    int ret; 
    unsigned long remain;
    uint32_t bufsz = (incoming->buf_end)*(sizeof(uint32_t));
    uint32_t duration = incoming->duration;
    uint16_t k, n; /* FEC vars */
    int sz = FEC_MAX;
    if ((bufsz/sz)<MAXK) {
        sz = (bufsz/MAXK)+(sizeof(uint32_t));
        sz = sz >> 2;
        sz = sz << 2;
    }
    uint32_t size = sz+(7*4); /* 7 uint32_t words for FEC header */
    uint32_t offset = size;
    offset = offset >> 2;
    offset += 2; /* 2 words for header and buffer tail */
    uint16_t *tmp16;
    uint32_t *tmp32;
    unsigned char *tmpb;
    uint32_t current = 0;
    uint32_t newend = 0;
/*    float loss = (MAXLOSS/MAXK); */
    k = MAXK;
/*    n = (int)((loss*k)+1); */
    n = losscomp;
    src = malloc(n * (sizeof(unsigned char *)));
    ret = timerfd_gettime (fd, itval);
    remain = itval->it_value.tv_nsec; /* remaining time */
    void *code = fec_new (k, n);
    ret = timerfd_gettime (fd, itval);
    remain -= itval->it_value.tv_nsec; /* remaining time */
#ifdef MYDEBUG
    printf ("EncapCode buffer size=%u, k=%u, n=%u, new code ns=%lu\n", bufsz, k, n, remain);
#endif
    int i;
    unsigned char *base = (unsigned char *) &(incoming->buf);
    uint32_t *dest = (uint32_t *) &(outgoing->buf);
    for (i=0;i<k;i++) {
        src[i] = (void *) &(base[i*sz]);
    }
    for (i=0;i<n;i++) {
#ifdef MYDEBUG
        printf ("EncapCode1 i=%u, k=%u, n=%u\n", i, k, n);
#endif
        newend = current+offset;
        tmp32 = &(dest[current]);
        tmp32[0] = (uint32_t) size;
        tmp32[1] = frameno;
        tmp32[2] = incoming->pckt_count;
        tmp32[3] = incoming->duration;
        tmp16 = (uint16_t *) &(tmp32[4]);
        tmp16[0] = sz; /* size of this packet in bytes */
        tmp16[1] = k; /* fec var k - number of original fec packets */
        tmp16[2] = n; /* fec var n - total number of encoded packets */
        tmp16[3] = i; /* encoded packet id for positioning */
        tmpb = (unsigned char *) &(tmp16[4]);
/* place a header on each packet with frameno, k, n and index. */
        fec_encode(code, src, tmpb, i, sz);
        current = newend;
    }
    outgoing->release = 0;
    outgoing->pckt_count = n; /* only interested in the base subset, not all */
    fec_free (code);
    free(src);
#ifdef MYDEBUG
        printf ("EncapCode EndPoint \n");
#endif
    return;
}

/* when called, decode using FEC library the given capture and produce a new capture
    if not all packets are here yet, use encap to store into incoming */
uint32_t decapcode (struct chan *incoming, struct chan *outgoing) {
/* firstly, an array of pointers to break up the incoming into FEC input format */
    unsigned char **src; /* array of pointers to packet buffers */
    int k, n; /* FEC vars */
    void *code;
    int sz = FEC_MAX;
    uint16_t *tmp16;
    uint32_t *tmp32 = incoming->buf;
    unsigned char *tmpb;
    uint32_t current = 0;
    uint32_t newend = 0;
    uint32_t pcktframeno;  /* non-decreasing frame number for fec udp tracking */
    int i = 0;
    unsigned char *dest = (unsigned char *) &(outgoing->buf);
/* first generate src packet pointers and index array from the incoming buffer */
    uint32_t offset = tmp32[current];
    offset = offset >> 2;
    offset += 2; /* 2 words for header and buffer tail */
    newend = offset;
    pcktframeno = tmp32[current+1];
    outgoing->pckt_count = tmp32[current+2];
    outgoing->duration = tmp32[current+3];
    tmp16 = (uint16_t *) &(tmp32[current+4]);
    sz = tmp16[0];
    k = tmp16[1];
    n = tmp16[2];
#ifdef MYDEBUG
    printf ("DecapCode Entry offset=%u, size=%u, k=%u\n", offset, sz, k);
#endif
    code = fec_new (k, n);
    int *ix = malloc(k * (sizeof(int)));
    ix[0] = tmp16[3];
    src = malloc(k * (sizeof(unsigned char *)));
    src[0] = (unsigned char *) &(tmp16[4]);
    current = newend;
#ifdef MYDEBUG
    printf ("DecapCode size=%u, k=%u\n", sz, k);
#endif
    i++;
    while (i<k) {
#ifdef MYDEBUG
        printf ("DecapCodeA current=%u, size=%u, k=%u, i=%u\n", current, sz, k, i);
#endif
        offset = tmp32[current];
        offset = offset >> 2;
        offset += 2; /* 2 words for header and buffer tail */
        newend = current+offset;
        pcktframeno = tmp32[current+1];
        tmp16 = (uint16_t *) &(tmp32[current+4]);
        sz = tmp16[0];
        k = tmp16[1];
        n = tmp16[2];
        ix[i] = tmp16[3];
        src[i] = (unsigned char *) &(tmp16[4]);
        current = newend;
        i++;
    }
#ifdef MYDEBUG
    printf ("DecapCode1 size=%u, k=%u, i=%u\n", sz, k, i);
#endif
    fec_decode(code, src, ix, sz);
/* now copy all the packets into the outgoing buffer */
    for (i=0;i<k;i++) {
        tmpb = &(dest[sz*i]);
        memcpy (tmpb, (const unsigned char *) src[i], (size_t) sz);
#ifdef MYDEBUG
        printf ("DecapCode2 size=%u, k=%u, i=%u\n", sz, k, i);
#endif
    }
    incoming->pckt_count = 0;
    incoming->release = 0;
    incoming->buf_end = 0;
    outgoing->release = 0;
    fec_free(code);
    free(src);
    free(ix);
#ifdef MYDEBUG
    printf ("DecapCode EndPoint \n");
#endif
    return;
}

/*  serialise and store packets into a buffer, the first 32 bits being this
    packet size - the next buffer position is dynamically calculated from this. */
void encap(struct chan * buffer, int size, unsigned char * packet, int enc) {
    pthread_mutex_lock(&mutex1);
#ifdef MYDEBUG
    printf ("Encap Entrance %u\n", buffer);
#endif
    uint32_t current = buffer->buf_end;
    uint32_t offset = (uint32_t) size; 
    uint32_t *active = buffer->buf;
    active[current] = offset; /* chain like a linked list */
    offset = offset >> 2;
    offset += 2; /* 2 words for header and buffer tail */
/*    offset = offset << 2; */
    uint32_t newend = current + offset;
/*    if ((newend > (0.8*(STREAM_BUFFER/MAXLOSS)))&&(enc == 0)) {
#ifdef MYDEBUG
        fprintf(stdout, "Stream Buffer Overrun!\n");
#endif
        pthread_mutex_unlock(&mutex1);
        return; */
/*        exit(EXIT_FAILURE); */
/*    } */
    current += 1;
    memcpy ((unsigned char *)&active[current], (const char *) packet, (size_t) size);
#ifdef MYDEBUG
    printf ("Encap packet size=%u, current=%u, offset=%u, newend=%u\n",
        size, current, offset, newend);
#endif
    buffer->pckt_count++;
    buffer->buf_end = newend; /* must be last for locking purposes */
    pthread_mutex_unlock(&mutex1);
    return;
}

/* when called, transmit the next available packet to the forwarding destination */
int decap_pop (int fd, struct chan *codesel, int direction, struct sockaddr_storage *peer_addrptr) {
#ifdef MYDEBUG
    printf ("Decap Pop Entrance %u\n", codesel);
#endif
    uint32_t release = codesel->release;
    uint32_t * coded = codesel->buf;
    int done = 0;
    socklen_t peer_addr_len;
    peer_addr_len = sizeof(struct sockaddr_storage);
    uint32_t size = (uint32_t) coded[release];
    unsigned char * packet = (unsigned char *)&(coded[release+1]);
    uint32_t offset = (uint32_t) size;
    offset = offset >> 2;
    offset += 2; /* 2 words for header and buffer tail */
/*    offset = offset << 2; */
#ifdef MYDEBUG
    printf ("Decap packet number=%u, size=%d, release=%u\n", codesel->pckt_count, size, release);
    printf (".");
#endif
    codesel->pckt_count -= 1;
    codesel->release = release + offset;
    if (codesel->pckt_count == 0) {
#ifdef MYDEBUG
        printf ("Decap complete.\n");
#endif
        done = -1; /* all packets decoded */
    }
/* transmit packet differently for forward or reverse operation */
    if (direction == 0) {
        if (write(fd, packet, size) != size) {
            printf ("Decap packet number=%u, size=%d, release=%u\n", codesel->pckt_count, size, release);
            printf("partial/failed write\n");
            exit(EXIT_FAILURE);
        } else {
#ifdef MYDEBUG
            printf("Forward Transmitted %ld bytes. done=%d\n", (long) size, done);
#endif
        }
    } else {
        if (sendto(fd, packet, size, 0,
                    (struct sockaddr *) peer_addrptr,
                    peer_addr_len) != size) {
            printf("Error sending response\n");
        } else {
#ifdef MYDEBUG
            printf("Reply Transmitted %ld bytes. done=%d\n", (long) size, done);
#endif
        }
    }
    return done;
}

/*  if this bin is an entrance, encode receives from source
    if this bin is an exit, encode receves from destination. */
void *encode_receive (struct thread_pass *ptr) {
    int startflag = 0;
    int ret;
    unsigned long ns;
    unsigned int sec;
    int tfd;
    struct itimerspec itval;
    unsigned long duration, missed;

    ssize_t nread;
    unsigned char buf[PACKET_SIZE];
    socklen_t peer_addr_len;
    peer_addr_len = sizeof(struct sockaddr_storage);

    uint32_t bufsize;
#ifdef MYDEBUG
    printf("Encode Debug\n");
#endif
    tfd = timerfd_create (CLOCK_MONOTONIC, 0);
	if (tfd == -1) {
        printf ("Decap Error cannot create main timer\n");
		return tfd;
    }
    sec = 0; /* for visual debug purposes, set this to 1, otherise 0 */
    ns = LATENCY * 1000000; /* millisecond timer */

    while (1) {
        if (ptr->type == 0) {
            nread = recvfrom(ptr->sfd, buf, PACKET_SIZE, 0,
                    (struct sockaddr *) ptr->peer_addrptr, &peer_addr_len);
            if (nread == -1)
                continue;  
#ifdef MYDEBUG
            printf("Entrance Encode Received %ld bytes\n", (long) nread);
#endif
        } else {
            nread = read(ptr->rfd, buf, PACKET_SIZE);
            if (nread == -1) {
                perror("read");
                exit(EXIT_FAILURE);
            }
#ifdef MYDEBUG
            printf("Exit Encode Received %ld bytes.\n", (long) nread);
#endif
        }
/* we have a packet, start the timer if its the first in a frame, then store it. */
        if (startflag == 0) {
            itval.it_value.tv_sec = sec;
            itval.it_value.tv_nsec = ns;
            itval.it_interval.tv_sec = 0;
            itval.it_interval.tv_nsec = 0;
            ret = timerfd_settime (tfd, 0, &itval, NULL);
            startflag = 1;
        }
#ifdef MYDEBUG
        printf("Encode Debug packet received\n");
#endif
        ret = timerfd_gettime (tfd, &itval);
        pthread_mutex_lock(&mutex2);
        if ((ptr->encode->raw[ptr->encode->active]->buf_end + ((nread/4)+2))>BUF_LIMIT) {
/*            if (ptr->encode->raw[ptr->encode->active]->pckt_count > 0) { */
            duration = ((LATENCY*1000000)-itval.it_value.tv_nsec);
            swap_chan(ptr->encode);
            ptr->encode->raw[ptr->encode->prev]->raw_status = 1;
            ptr->encode->raw[ptr->encode->prev]->duration = duration;
            ptr->encode->rawcount++;
#ifdef MYDEBUG
            printf("EncRec Mutex   Lock: encode_process_mutex \n");
#endif
            pthread_mutex_lock(&encode_process_mutex);
            pthread_cond_signal(&encode_process_var);
#ifdef MYDEBUG
            printf("EncRec Mutex Unlock: encode_process_mutex \n");
#endif
            pthread_mutex_unlock(&encode_process_mutex); 
            if (ptr->encode->rawcount == (BUFFERS-1)) {
#ifdef MYDEBUG
#endif
                printf("Encode stack too close to Buffer cycle!\n");
            }
            startflag = 0;
        }
        encap(ptr->encode->raw[ptr->encode->active], nread, buf, 0);
        pthread_mutex_unlock(&mutex2);
    }
    return ptr;
}

/*  pulse sync the encode receive thread to swap out buffers quietly and initiate
    the process and transmit stages */
void *encode_sync (struct thread_pass *ptr) {
    int current;

    int ret;
    unsigned long ns;
    unsigned int sec;
    int er_fd;
    struct itimerspec itval;
    uint64_t duration, missed;

    er_fd = timerfd_create (CLOCK_MONOTONIC, 0);
	if (er_fd == -1) {
        printf ("Encode Sync Error cannot create latency timer\n");
		return er_fd;
    }
    sec = 0; /* for visual debug purposes, set this to 1, otherise 0 */
    ns = LATENCY * 1000000; /* millisecond timer */
	itval.it_value.tv_sec = sec;
	itval.it_value.tv_nsec = ns;
    itval.it_interval.tv_sec = sec;
	itval.it_interval.tv_nsec = ns;
	ret = timerfd_settime (er_fd, 0, &itval, NULL);

    while (1) {
        current = ptr->encode->active;
/* wait for main timer interval */
        ret = read (er_fd, &missed, sizeof (missed));
        if (ret == -1) {
            perror ("Encode Sync read timer error");
            return;
        }
        pthread_mutex_lock(&mutex2);
        if ((ptr->encode->raw[ptr->encode->active]->pckt_count > 0)&&(current == ptr->encode->active)) {
#ifdef MYDEBUG
            printf("Encode sync prev=%u, current=%u, raw_status=%u\n", current, ptr->encode->active, ptr->encode->raw[ptr->encode->active]->raw_status);
#endif
            duration = (COMPRESSOR * (LATENCY*1000000));
            swap_chan(ptr->encode);
            ptr->encode->raw[ptr->encode->prev]->raw_status = 1;
            ptr->encode->raw[ptr->encode->prev]->duration = duration;
            ptr->encode->rawcount++;
#ifdef MYDEBUG
            printf("EncSyn Mutex   Lock: encode_process_mutex \n");
#endif
            pthread_mutex_lock(&encode_process_mutex);
            pthread_cond_signal(&encode_process_var);
#ifdef MYDEBUG
            printf("EncSyn Mutex Unlock: encode_process_mutex \n");
#endif
            pthread_mutex_unlock(&encode_process_mutex); 
            if (ptr->encode->rawcount == (BUFFERS-1)) {
#ifdef MYDEBUG
#endif
                printf("Encode stack too close to Buffer cycle!\n");
            }
        }
        pthread_mutex_unlock(&mutex2);
    }
    return;
}

void *encode_process (struct thread_pass *ptr) {
    uint32_t frameno = 1;
    int ret;
    unsigned long ns;
    unsigned int sec;
    int tfd;
    struct itimerspec itval;
    unsigned long remain, missed;
    int i, j;
    int active = 1;
    int found = -1;

    tfd = timerfd_create (CLOCK_MONOTONIC, 0);
	if (tfd == -1) {
        printf ("Decap Error cannot create main timer\n");
		return tfd;
    }
    sec = 0; /* for visual debug purposes, set this to 1, otherise 0 */
    ns = LATENCY * 1000000; /* millisecond timer */
    while (1) {
        if (ptr->encode->rawcount == 0) {
#ifdef MYDEBUG
            printf("EncPro Mutex   Lock: encode_process_mutex \n");
#endif
            pthread_mutex_lock(&encode_process_mutex);
            pthread_cond_wait(&encode_process_var, &encode_process_mutex); /* self block wait for receive */
#ifdef MYDEBUG
            printf("EncPro Mutex Unlock: encode_process_mutex \n");
#endif
            pthread_mutex_unlock(&encode_process_mutex);
        }
        for (i=active;i<(active+BUFFERS);i++) {
            j = i % BUFFERS;
            if (ptr->encode->raw[j]->raw_status == 1) {
                found = j;
                break;
            }
        }
        if (found == -1) {
#ifdef MYDEBUG
            fprintf (stdout,"Encode Process Buffer not found.\n");
#endif
            ptr->encode->rawcount--;
            continue;
        }
        itval.it_value.tv_sec = sec;
        itval.it_value.tv_nsec = ns;
        itval.it_interval.tv_sec = 0;
        itval.it_interval.tv_nsec = 0;
        ret = timerfd_settime (tfd, 0, &itval, NULL);
        encapcode (ptr->encode->raw[found], ptr->encode->coded[found], frameno, tfd, &itval, ptr->losscomp);
        ptr->encode->coded[found]->duration = ptr->encode->raw[found]->duration;
        ptr->encode->coded[found]->code_status = 1;
        ptr->encode->raw[found]->raw_status = 0;
        ptr->encode->rawcount--;
        ptr->encode->raw[found]->frameno = 0;
        ptr->encode->raw[found]->release = 0;
        ptr->encode->raw[found]->buf_end = 0;
        ptr->encode->raw[found]->pckt_count = 0;
        ret = timerfd_gettime (tfd, &itval);
        remain = itval.it_value.tv_nsec;
        if (remain == 0) {
            fprintf (stdout,"Encode time greater than frame latency! %lu\n", frameno);
/*            exit(EXIT_FAILURE); */
        }
#ifdef MYDEBUG
        printf("Encode Process time: %lu\n", ((LATENCY*1000000)-remain));
#endif
/* select next buffer for incoming packets and unlock encode transmit mutex */
        if (active == found) {
            active++;
            if (active == BUFFERS) {
                active = 0;
            }
        }
        ptr->encode->processcount++;
        found=-1;
#ifdef MYDEBUG
            printf("EncPro Mutex   Lock: encode_transmit_mutex \n");
#endif
        pthread_mutex_lock(&encode_transmit_mutex);
        pthread_cond_signal(&encode_transmit_var);
#ifdef MYDEBUG
            printf("EncPro Mutex Unlock: encode_transmit_mutex \n");
#endif
        pthread_mutex_unlock(&encode_transmit_mutex); 
        frameno++;
    }
}

/* if an entrance, transmit to destination
    if an exit, transmit to source */
/*  Initially, set a once of timer for first receive only frame
    swap active and inactive.
 */
void *encode_trans (struct encode_thread *thread) {
    struct thread_pass *ptr = thread->thread_info;
    int fd, status, direction;
   	int tr_ret;
    unsigned long tr_ns;
    unsigned int tr_sec;
    int tr_fd;
    struct itimerspec tr_itval;
    uint64_t tr_remain, tr_missed;
    int i, j;
    int active = 1;
    int found = -1;
 
    if (ptr->type == 0) { /* entrance */
        fd = ptr->rfd;
        direction = 0; /* forward */
    } else {                /* exit */
        fd = ptr->sfd;
        direction = 1; /* reply */
    }
#ifdef MYDEBUG
    printf("EncTra Entrance ID: %u\n",thread->id);
#endif
/*  main loop for transmitting encoded packets, must swap channels,
    time decoding frame, initiate release loop with this frame time */
	tr_fd = timerfd_create (CLOCK_MONOTONIC, 0);
    while (1) {
/*        while ((ptr->encode->processcount == 0)||(ptr->encode->processcount > THREADCOUNT)) { */
        while (ptr->encode->processcount == 0) {
/*        while (ptr->encode->processcount <= THREADCOUNT) { */
#ifdef MYDEBUG
            printf("EncTra Mutex   Lock: encode_transmit_mutex \n");
#endif
            pthread_mutex_lock(&encode_transmit_mutex);
            pthread_cond_wait(&encode_transmit_var, &encode_transmit_mutex); /* self block wait for receive  */
#ifdef MYDEBUG
            printf("EncTra Mutex Unlock: encode_transmit_mutex \n");
#endif
            pthread_mutex_unlock(&encode_transmit_mutex);
        }
        pthread_mutex_lock(&encode_transmitB_mutex);
        j = (active) % BUFFERS;
        if (ptr->encode->coded[j]->code_status == 1) {
            found = j;
        } else {
            for (i=active+SLEW;i<(active+BUFFERS+SLEW);i++) {
                j = i % BUFFERS;
                if (ptr->encode->coded[j]->code_status == 1) {
                    found = j;
                    break;
                }
            }
        }
        if (found == -1) {
#ifdef MYDEBUG
            fprintf (stdout,"Encode Transmit Buffer %u not found. %u\n", active, ptr->encode->processcount);
#endif
            ptr->encode->processcount--;
            pthread_mutex_unlock(&encode_transmitB_mutex);
            continue;
        }
        ptr->encode->coded[found]->code_status = 0;
        ptr->encode->processcount--;
        pthread_mutex_unlock(&encode_transmitB_mutex);
#ifdef MYDEBUG
        if (found != active) {
            printf ("Encode Trans wanted %u, rec:%u Queued:%u\n", active, found, ptr->encode->coded[found]->pckt_count);
        }
#endif
/* set timer */
        tr_sec = 0; /* for visual debug purposes, set this to 1, otherise 0 */
        tr_ns = (THREADCOUNT * COMPRESSOR * ptr->encode->coded[found]->duration)/ptr->encode->coded[found]->pckt_count; /* squeeze the frame to maintain latency */
        tr_itval.it_value.tv_sec = tr_sec;
        tr_itval.it_value.tv_nsec = tr_ns;
        tr_itval.it_interval.tv_sec = tr_sec;
        tr_itval.it_interval.tv_nsec = tr_ns;
        tr_ret = timerfd_settime (tr_fd, 0, &tr_itval, NULL);
#ifdef MYDEBUG
        printf ("Encode Trans: Timer Set: %u, duration=%u, pckt_count=%u\n", tr_ns, ptr->encode->coded[found]->duration, ptr->encode->coded[found]->pckt_count);
#endif

/* use gettime to caclulate transmit intervals */
        status = decap_pop(fd, ptr->encode->coded[found], direction, ptr->peer_addrptr);
        while (status == 0) {
            tr_ret = read (tr_fd, &tr_missed, sizeof (tr_missed));
            status = decap_pop(fd, ptr->encode->coded[found], direction, ptr->peer_addrptr);
            while ((tr_missed > 1)&&(status == 0)) {
                status = decap_pop(fd, ptr->encode->coded[found], direction, ptr->peer_addrptr);
#ifdef MYDEBUG
                printf ("Encode Trans Overrun %u times\n", tr_missed);
#endif
                --tr_missed;
            }
        } 
/*        ptr->encode->code_ready[ptr->encode->code_out] = 0;
        ptr->encode->code_out++;
        if (ptr->encode->code_out == BUFFERS) {
            ptr->encode->code_out = 0;
        } */
        if (active == found) {
            active++;
            if (active == BUFFERS) {
                active = 0;
            }
        }
/*        ptr->encode->coded[found]->code_status = 0;
        ptr->encode->processcount--; */
        found=-1;
    }
}

/*  if this bin is an entrance, decode receives from destination
    if this bin is an exit, decode receves from source. */
void *decode_receive (struct thread_pass *ptr) {
    ssize_t nread;
    unsigned char buf[PACKET_SIZE];
    uint32_t pcktframeno = 0;
    uint32_t bufframeno = 0;
    uint32_t bufnum = 0;
    uint32_t *tmp32;
    uint16_t *tmp16;
    socklen_t peer_addr_len;
    peer_addr_len = sizeof(struct sockaddr_storage);
#ifdef MYDEBUG
    printf("Decode Debug\n");
#endif
    while (1) {
        if (ptr->type == 1) {
            nread = recvfrom(ptr->sfd, buf, PACKET_SIZE, 0,
                    (struct sockaddr *) ptr->peer_addrptr, &peer_addr_len);
            if (nread == -1)
                continue;  
#ifdef MYDEBUG
            printf("Exit Decode Received %ld bytes\n", (long) nread);
#endif
        } else {
            nread = read(ptr->rfd, buf, PACKET_SIZE);
            if (nread == -1) {
                perror("read");
                exit(EXIT_FAILURE);
            }
#ifdef MYDEBUG
            printf("Entrance Decode Received %ld bytes.\n", (long) nread);
#endif
        }
/*  decode packets here by checking for complete set instead of just storing it
    packet headers will contain which frame, if we have a complete frame, decode all
    release forward decode mutex for transmit to begin.
    Tune the k/n value based on frame drop or extra packets
*/
        tmp32 = buf;
        if ((tmp32[1] == MAGIC)&&(tmp32[2] == MAGIC)) {
            if (ptr->losscomp != tmp32[3]) {
#ifdef MYDEBUG
                printf("Decode Received LossComp, Current N: %u. New N: %u\n", ptr->losscomp, tmp32[2]);
#endif
                ptr->losscomp = tmp32[3];
            }
            continue;
        }
        ptr->total++;
        tmp16 = (uint16_t *) &(tmp32[3]);
/* get the appropriate buffer for this incoming packet */
        pcktframeno = tmp32[0];
        bufnum = (pcktframeno % BUFFERS);
#ifdef MYDEBUG
        printf("Decode Receive packet from frame %u.\n", pcktframeno);
#endif
/*        if (ptr->decode->raw[bufnum]->pckt_count < tmp16[1]) { */
        if (pcktframeno <= ptr->decode->raw[bufnum]->framedone) {
            /* here we have a redundant packet from a completed frame */
            ptr->extra++;
            continue;
        }
        if (ptr->decode->raw[bufnum]->pckt_count == 0) {
            ptr->decode->raw[bufnum]->frameno = pcktframeno;
            bufframeno = pcktframeno;
        } else {
            bufframeno = ptr->decode->raw[bufnum]->frameno;
        }
        if (bufframeno != pcktframeno) {
#ifdef MYDEBUG
            printf("%u\tDecode Receive lost %u packets from frame %u. in buffer %u, %u frames behind\n", pcktframeno, ptr->decode->raw[bufnum]->pckt_count, ptr->decode->raw[bufnum]->frameno, bufnum, (pcktframeno - bufframeno));
#endif
/*            ptr->losscount += (tmp16[1] - ptr->decode->raw[bufnum]->pckt_count); */
            ptr->rawloss += (tmp16[2] - ptr->decode->raw[bufnum]->pckt_count);
            ptr->expected += tmp16[2];
            ptr->frameloss += (((pcktframeno - bufframeno)/BUFFERS)-1);
            ptr->losscount += tmp16[1];
            ptr->decode->raw[bufnum]->pckt_count = 0;
            ptr->decode->raw[bufnum]->buf_end = 0;
            ptr->decode->raw[bufnum]->release = 0;
            ptr->decode->raw[bufnum]->framedone = bufframeno; 
            ptr->decode->raw[bufnum]->frameno = pcktframeno;
            bufframeno = pcktframeno;
        }
        encap(ptr->decode->raw[bufnum], nread, buf, 1);
        if (ptr->decode->raw[bufnum]->pckt_count == tmp16[1]) {
#ifdef MYDEBUG
            printf("%u\tDecode Receive got  %u packets from frame %u in buffer %u, %u frames behind\n", pcktframeno, ptr->decode->raw[bufnum]->pckt_count, ptr->decode->raw[bufnum]->frameno, bufnum, (pcktframeno - bufframeno));
#endif
            ptr->foundcount += tmp16[1]; /* only in found frames. */
            ptr->expected += tmp16[2];
            ptr->decode->raw[bufnum]->raw_status = 1;
            ptr->decode->raw[bufnum]->framedone = bufframeno;
            ptr->decode->rawcount++;
#ifdef MYDEBUG
            printf("Decode Process Unlock=%u\n", tmp16[1]);
#endif
            pthread_mutex_lock(&decode_process_mutex);
            pthread_cond_signal(&decode_process_var);
            pthread_mutex_unlock(&decode_process_mutex); 
        }
/*        } else {
#ifdef MYDEBUG
            printf("Decode Process Excess Packet=%u\n", tmp16[1]);
#endif
        } */
    }
    return ptr;
}

/*  initially waiting to be unlocked by decode receive, this decodes in the
    background a frame and stores the length of time it took to do so, then unlocks
    decode transmit and loops back and locks itself again. */
void *decode_process (struct thread_pass *ptr) {
    int ret;
    unsigned long ns;
    unsigned int sec;
    int tfd;
    struct itimerspec itval;
    unsigned long remain, missed;
    int i, j;
    int active = 1;
    int found = -1;

    tfd = timerfd_create (CLOCK_MONOTONIC, 0);
	if (tfd == -1) {
        printf ("Decap Error cannot create main timer\n");
		return tfd;
    }
    sec = 0; /* for visual debug purposes, set this to 1, otherise 0 */
    ns = LATENCY * 1000000; /* millisecond timer */
    while (1) {
        while (ptr->decode->rawcount == 0) {
            pthread_mutex_lock(&decode_process_mutex);
            pthread_cond_wait(&decode_process_var, &decode_process_mutex); /* self block wait for receive */
            pthread_mutex_unlock(&decode_process_mutex);
        }
        for (i=active;i<(active+BUFFERS);i++) {
            j = i % BUFFERS;
            if (ptr->decode->raw[j]->raw_status == 1) {
                found = j;
                break;
            } else {
#ifdef MYDEBUG
                fprintf (stdout,"Decode Process cyclic Buffer overrun.\n");
#endif
            }
        }
        if (found == -1) {
#ifdef MYDEBUG
            fprintf (stdout,"Decode Process Buffer not found.\n");
#endif
            ptr->decode->rawcount--;
            continue;
        }
        itval.it_value.tv_sec = sec;
        itval.it_value.tv_nsec = ns;
        itval.it_interval.tv_sec = 0;
        itval.it_interval.tv_nsec = 0;
        ret = timerfd_settime (tfd, 0, &itval, NULL);
        decapcode(ptr->decode->raw[found], ptr->decode->coded[found]);
        ret = timerfd_gettime (tfd, &itval);
        ptr->decode->coded[found]->code_status = 1;
        ptr->decode->raw[found]->raw_status = 0;
        ptr->decode->rawcount--;
        ptr->decode->raw[found]->frameno = 0;
/*        ptr->decode->raw[found]->framedone = 0; */
        ptr->decode->raw[found]->release = 0;
        ptr->decode->raw[found]->buf_end = 0;
        ptr->decode->raw[found]->pckt_count = 0;
        remain = itval.it_value.tv_nsec;
        if (remain == 0) {
            printf ("Decode time greater than frame latency!\n");
/*            return; */
        }
#ifdef MYDEBUG
        printf("Decode Process time: %lu\n", ((LATENCY*1000000)-remain));
#endif
/* unlock decode transmit mutex */
/*        ptr->decode->code_in++;
        if (ptr->decode->code_in == BUFFERS) {
            ptr->decode->code_in = 0;
        } */
        if (active == found) {
            active++;
            if (active == BUFFERS) {
                active = 0;
            }
        }
        ptr->decode->processcount++;
        found=-1;
        pthread_mutex_lock(&decode_transmit_mutex);
        pthread_cond_signal(&decode_transmit_var);
        pthread_mutex_unlock(&decode_transmit_mutex); 
    }
}

/* not multithreadable */
void *decode_trans (struct thread_pass *ptr) {
    int fd, status, direction;
   	int tr_ret, mttr_ret;
    unsigned long tr_ns, mttr_ns;
    unsigned int tr_sec, mttr_sec;
    int tr_fd, mttr_fd;
    struct itimerspec tr_itval, mttr_itval;
    unsigned long tr_remain, tr_missed, mttr_missed;
    int i, j;
    int realign;
    int found = -1;
 
    if (ptr->type == 1) { /* exit */
        fd = ptr->rfd;
        direction = 0; /* forward */
    } else {             /* entrance */
        fd = ptr->sfd;
        direction = 1; /* reply */
    }
/*  main loop for transmitting encoded packets, must swap channels,
    time decoding frame, initiate release loop with this frame time */
	tr_fd = timerfd_create (CLOCK_MONOTONIC, 0);
    while (1) {
        while (ptr->decode->processcount == 0) {
            pthread_mutex_lock(&decode_transmit_mutex);
            pthread_cond_wait(&decode_transmit_var, &decode_transmit_mutex); /* self block wait for process */
            pthread_mutex_unlock(&decode_transmit_mutex);
        }
        j = (ptr->decodeactive) % BUFFERS;
        realign = 0;
        while ((ptr->decode->coded[j]->code_status != 1)&&(realign < REALIGN)) {
            pthread_mutex_lock(&decode_transmit_mutex);
            pthread_cond_wait(&decode_transmit_var, &decode_transmit_mutex);
            pthread_mutex_unlock(&decode_transmit_mutex);
            realign++;
        }
        if (realign == REALIGN) { 
#ifdef MYDEBUG
            fprintf (stdout,"Decode Transmit realignment overflow. active: %u\tnot found: %u\n", ptr->decodeactive, j);
#endif
            ptr->decodeactive++;
            if (ptr->decodeactive == BUFFERS) {
                ptr->decodeactive = 0;
            }
            j = (ptr->decodeactive) % BUFFERS;
        }
        if (ptr->decode->coded[j]->code_status == 1) {
#ifdef MYDEBUG
            fprintf (stdout,"Decode Transmit Frame in-order.\n");
#endif
            found = j;
        } else {
            for (i=ptr->decodeactive+SLEW;i<(ptr->decodeactive+BUFFERS+SLEW);i++) {
                j = i % BUFFERS;
                if (ptr->decode->coded[j]->code_status == 1) {
                    found = j;
#ifdef MYDEBUG
                    fprintf (stdout,"Decode Transmit Frame out-of-order. active: %u\tfound: %u\n", ptr->decodeactive, found);
#endif
                    if (found > ptr->decodeactive) {
                        ptr->decodeactive = found;
                    }
                    break;
                } else {
#ifdef MYDEBUG
                    fprintf (stdout,"Decode Transmit cyclic Buffer overrun.\n");
#endif
                }
            }
        }
        if (found == -1) {
#ifdef MYDEBUG
            fprintf (stdout,"Decode Transmit Buffer not found.\n");
#endif
            ptr->decode->processcount--;
            continue;
        }
#ifdef MYDEBUG
        if (found != ptr->decodeactive) {
            printf ("Decode Trans wanted %u, rec:%u Queued:%u\n", ptr->decodeactive, found, ptr->decode->coded[found]->pckt_count);
        }
#endif
/* set timer */
        tr_sec = 0;
/*        tr_ns = ptr->decode->coded->remain; squeeze release for single buffer */
        tr_ns = (COMPRESSOR * ptr->decode->coded[found]->duration)/ptr->decode->coded[found]->pckt_count;
                /* squeeze release a little */
        tr_itval.it_value.tv_sec = tr_sec;
        tr_itval.it_value.tv_nsec = tr_ns;
        tr_itval.it_interval.tv_sec = tr_sec;
        tr_itval.it_interval.tv_nsec = tr_ns;
        tr_ret = timerfd_settime (tr_fd, 0, &tr_itval, NULL);
        
        status = decap_pop(fd, ptr->decode->coded[found], direction, ptr->peer_addrptr);
        while (status == 0) {
            tr_ret = read (tr_fd, &tr_missed, sizeof (tr_missed));
            status = decap_pop(fd, ptr->decode->coded[found], direction, ptr->peer_addrptr);
            while ((tr_missed > 1)&&(status == 0)) {
                status = decap_pop(fd, ptr->decode->coded[found], direction, ptr->peer_addrptr);
#ifdef MYDEBUG
                printf ("Decode Trans Overrun %u times\n", tr_missed);
#endif
                --tr_missed;
            }
        } 
/*        ptr->decode->code_ready[ptr->decode->code_out] = 0;
        ptr->decode->code_out++;
        if (ptr->decode->code_out == BUFFERS) {
            ptr->decode->code_out = 0;
        } */
        if (ptr->decodeactive == found) {
            ptr->decodeactive++;
            if (ptr->decodeactive == BUFFERS) {
                ptr->decodeactive = 0;
            }
        }
        ptr->decode->coded[found]->code_status = 0;
        ptr->decode->processcount--;
        found=-1;
    }
}

void *decode_stat (struct thread_pass *ptr) {
/*    uint32_t losscomp = (int)((MAXK+MAXN)/2);
    uint32_t prevlosscomp = (int)((MAXK+MAXN)/2);
    uint32_t losscomp = (int)(((6*MAXK)+MAXN)/7);
    uint32_t prevlosscomp = (int)(((6*MAXK)+MAXN)/7); */
    uint32_t losscomp = MAXN;
    uint32_t prevlosscomp = MAXN;
    uint32_t initial = 0;
    uint32_t losscount;
    uint32_t extra;
    uint32_t expected;
    uint32_t foundcount;
    uint32_t guess;
    uint32_t total;

    int fd, status, direction;
    socklen_t peer_addr_len = sizeof(struct sockaddr_storage);

    int size = 24; /* just a basic message packet. send it MAXK times */
    unsigned char * packet[size];
    uint32_t * coded = (uint32_t *) packet;
    coded[1] = MAGIC;
    coded[2] = MAGIC;

    int ret;
    unsigned long ns;
    unsigned int sec;
    int st_fd;
    struct itimerspec itval;
    uint64_t missed;

   	int tr_ret;
    unsigned long tr_ns;
    unsigned int tr_sec;
    int tr_fd;
    struct itimerspec tr_itval;
    uint64_t tr_remain, tr_missed;

    float loss, rawloss, overhead;
    unsigned int counter = 0;
    unsigned int report = REPORT;
    unsigned int safestart = 0;
    int noloss = 1;
    int i;

    /* these vales same as encode, not decode. */
    if (ptr->type == 0) { /* entrance */
        fd = ptr->rfd;
        direction = 0; /* forward */
    } else {                /* exit */
        fd = ptr->sfd;
        direction = 1; /* reply */
    }

    sec = INTERVAL; /* seconds between adjustments */
    ns = LATENCY * 0;
	itval.it_value.tv_sec = sec;
	itval.it_value.tv_nsec = ns;
    itval.it_interval.tv_sec = sec;
	itval.it_interval.tv_nsec = ns;
	st_fd = timerfd_create (CLOCK_MONOTONIC, 0);
	ret = timerfd_settime (st_fd, 0, &itval, NULL);

	tr_fd = timerfd_create (CLOCK_MONOTONIC, 0);

    while (1) {
        ret = read (st_fd, &missed, sizeof (missed));
        foundcount = ptr->foundcount;
        ptr->foundcount=0;
        losscount = ptr->losscount;
        ptr->losscount=0;
        extra = ptr->extra;
        ptr->extra=0;
        total = ptr->total;
        ptr->total=0;
        report++;
        if (foundcount != 0) {
            loss = (((float)losscount/(float)(foundcount+losscount))*100);
            overhead = (((float)(total)/(float)(foundcount))*100);
            expected = ptr->expected+(ptr->frameloss*losscomp);
            ptr->expected=0;
            rawloss = (((float)(expected-total)/(float)(expected))*100);
            if (rawloss > 100) {
                rawloss = 0;
            }
            guess = (uint32_t)(((100/(100-rawloss))*MAXK)*1.6);
            if (guess > MAXN) {
                guess = MAXN;
            }
            if (guess < MAXK) {
                guess = losscomp;
            }
            ptr->rawloss=0;
#ifdef MYDEBUG
#endif
            if (report >= REPORT) {
                printf("%u\t%5.2f, Rawloss: %5.2f, Current N: %u. Total Packets Received:%u\toverhead:%5.2f\tguess:%u\n", (counter*INTERVAL),loss, rawloss, losscomp, total, overhead, guess);
                report = 0;
                losscomp = guess;
            } else if (safestart==0) {
                if (report >= (30/INTERVAL)) {
                    safestart = 1;
                } else {
                    --noloss;
                }
                losscomp = guess;
                printf("Safestart %5.2f, Rawloss: %5.2f, Current N: %u. Total Packets Received:%u\toverhead:%5.2f\tguess:%u\n", loss, rawloss, losscomp, total, overhead, guess);
            } else if ((loss > (float)THRESHOLD)&&(losscomp<MAXN)) {
                printf("More Loss %5.2f, Rawloss: %5.2f, Current N: %u. Total Packets Received:%u\toverhead:%5.2f\n", loss, rawloss, losscomp, total, overhead);
                prevlosscomp = losscomp;
                losscomp++;
                noloss = 0;
#ifdef MYDEBUG
#endif
            } else if ((noloss > (20/INTERVAL))&&(losscomp>(MAXK+1))) {
                printf("Less Loss %5.2f, Rawloss: %5.2f, Current N: %u. Total Packets Received:%u\toverhead:%5.2f\n", loss, rawloss, losscomp, total, overhead);
                prevlosscomp = losscomp;
                --losscomp;
                noloss = 0;
#ifdef MYDEBUG
                printf("Less Loss, Current N: %u. New N: %u\n", prevlosscomp, losscomp);
#endif
            }
            if (initial > 0) {
                losscomp = guess;
                initial = 0;
            }
            counter++;
            noloss++;
        } else if (initial == 0) {
            initial = losscomp;
            losscomp = MAXN;
            printf("Initial Current N: %u. New N: %u\n", initial, losscomp);
        }
        ptr->rawloss=0;
        if (prevlosscomp != losscomp) {
/* set transmit timer */
#ifdef MYDEBUG
            printf("Transmit Current N: %u. New N: %u\n", prevlosscomp, losscomp);
#endif
            coded[3] = losscomp; /* the message to transmit */
            tr_sec = 0; 
            tr_ns = 100000; /* not important, just not too small. */
            tr_itval.it_value.tv_sec = tr_sec;
            tr_itval.it_value.tv_nsec = tr_ns;
            tr_itval.it_interval.tv_sec = tr_sec;
            tr_itval.it_interval.tv_nsec = tr_ns;
            tr_ret = timerfd_settime (tr_fd, 0, &tr_itval, NULL);
            for (i=0;i<MAXK;i++) {
/* transmit packets differently for forward or reverse operation */
                if (direction == 0) {
                    if (write(fd, packet, size) != size) {
                        printf ("Decode Stats packet\n");
                        printf("partial/failed write\n");
                        exit(EXIT_FAILURE);
                    } else {
#ifdef MYDEBUG
                        printf("Forward Transmitted %ld bytes.\n", (long) size);
#endif
                    }
                } else {
                    if (sendto(fd, packet, size, 0,
                                (struct sockaddr *) ptr->peer_addrptr,
                                peer_addr_len) != size) {
                        printf ("Decode Stats packet\n");
                        printf("Error sending response\n");
                        exit(EXIT_FAILURE);
                    } else {
#ifdef MYDEBUG
                        printf("Reply Transmitted %ld bytes.\n", (long) size);
#endif
                    }
                }
                tr_ret = read (tr_fd, &tr_missed, sizeof (tr_missed));
            }
            prevlosscomp = losscomp;
        }
    }
    return;
}

int main(int argc, char *argv[]) {
    pthread_t encode_receive_t, encode_sync_t, encode_process_t, encode_transmit_t, decode_receive_t, decode_process_t, decode_transmit_t, decode_stat_t;
    int iret1, iret2, iret3, iret4, iret5, iret6, iret7, iret8;
    int i;
    struct encode_thread *list[THREADCOUNT];

    struct addrinfo hints, rhints;
    struct addrinfo *result, *rresult, *rp;
    int sfd, rfd, r, s;
    struct sockaddr_storage peer_addr;
    socklen_t peer_addr_len, remote_addr_len;

    int ret;
    unsigned long ns;
    unsigned int sec;
    int er_fd;
    struct itimerspec itval;
    unsigned long remain, missed;

    er_fd = timerfd_create (CLOCK_MONOTONIC, 0);
	if (er_fd == -1) {
        printf ("Encode Sync Error cannot create latency timer\n");
		return er_fd;
    }

    struct capture *encode;
    struct capture *decode;
    struct thread_pass *thread_info;
    encode = malloc(sizeof(struct capture)); 
    capture_init(encode);
    decode = malloc(sizeof(struct capture)); 
    capture_init(decode);
    thread_info = malloc(sizeof(struct thread_pass)); 
/* initialise the captures buffer struct to something meaningful. */

    void *code = fec_new (1, 2);

    if (argc != 4) {
        fprintf(stdout, "Usage: %s port remotehost remoteport\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */
    hints.ai_flags = AI_PASSIVE;    /* For wildcard IP address */
    hints.ai_protocol = 0;          /* Any protocol */
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;
    s = getaddrinfo(NULL, argv[1], &hints, &result);
    if (s != 0) {
        fprintf(stdout, "getaddrinfo: %s\n", gai_strerror(s));
        exit(EXIT_FAILURE);
    }

    /* getaddrinfo() returns a list of address structures.
       Try each address until we successfully bind(2).
       If socket(2) (or bind(2)) fails, we (close the socket
       and) try the next address. */

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sfd = socket(rp->ai_family, rp->ai_socktype,
                rp->ai_protocol);
        if (sfd == -1)
            continue;

        if (bind(sfd, rp->ai_addr, rp->ai_addrlen) == 0)
            break;                  /* Success */

        close(sfd);
    }

    if (rp == NULL) {               /* No address succeeded */
        fprintf(stdout, "Could not bind\n");
        exit(EXIT_FAILURE);
    }

    freeaddrinfo(result);           /* No longer needed */

    /* Obtain remote address(es) matching host/port */

    memset(&rhints, 0, sizeof(struct addrinfo));
    rhints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
    rhints.ai_socktype = SOCK_DGRAM; /* Datagram socket */
    rhints.ai_flags = 0;
    rhints.ai_protocol = 0;          /* Any protocol */

    r = getaddrinfo(argv[2], argv[3], &rhints, &rresult);
    if (r != 0) {
        fprintf(stdout, "getaddrinfo: %s\n", gai_strerror(r));
        exit(EXIT_FAILURE);
    }

    /* getaddrinfo() returns a list of address structures.
       Try each address until we successfully connect(2).
       If socket(2) (or connect(2)) fails, we (close the socket
       and) try the next address. */
    for (rp = rresult; rp != NULL; rp = rp->ai_next) {
        rfd = socket(rp->ai_family, rp->ai_socktype,
                     rp->ai_protocol);
        if (rfd == -1)
            continue;

        if (connect(rfd, rp->ai_addr, rp->ai_addrlen) != -1)
            break;                  /* Success */

        close(rfd);
    }

    if (rp == NULL) {               /* No address succeeded */
        fprintf(stdout, "Could not connect\n");
        exit(EXIT_FAILURE);
    } else {
#ifdef MYDEBUG
        fprintf(stdout, "Remote connect success\n");
#endif
    }

    freeaddrinfo(rresult);           /* No longer needed */

    thread_info->sfd = sfd;
    thread_info->rfd = rfd;
    thread_info->er_fd = er_fd;
    thread_info->encode = encode;
    thread_info->decode = decode;
    thread_info->decodeactive = 1;
    thread_info->losscomp = MAXN; /* start the loss from worst case and work back */
    thread_info->type = TYPE;
    thread_info->peer_addrptr = &(peer_addr);

    iret1 = pthread_create( &encode_receive_t, NULL,encode_receive , thread_info);
    iret2 = pthread_create( &encode_sync_t, NULL,encode_sync , thread_info);
    iret3 = pthread_create( &encode_process_t, NULL,encode_process , thread_info);
/*  iret4 = pthread_create( &encode_transmit_t, NULL,encode_trans , thread_info); */
    iret5 = pthread_create( &decode_receive_t, NULL,decode_receive , thread_info);
    iret6 = pthread_create( &decode_process_t, NULL,decode_process , thread_info);
    iret7 = pthread_create( &decode_transmit_t, NULL,decode_trans , thread_info);
    iret8 = pthread_create( &decode_stat_t, NULL,decode_stat , thread_info);

    enc_thread_init (thread_info, list);
    enc_thread_wait (list);

    pthread_join(encode_receive_t, NULL);
    pthread_join(encode_sync_t, NULL); 
    pthread_join(encode_process_t, NULL);
/*    pthread_join(encode_transmit_t, NULL); */
    pthread_join(decode_receive_t, NULL);
    pthread_join(decode_process_t, NULL);
    pthread_join(decode_transmit_t, NULL);
    pthread_join(decode_stat_t, NULL);
/*
    pthread_join( thread_forward, NULL);
    pthread_join( thread_reverse, NULL);
*/

}

