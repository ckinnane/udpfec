#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <pthread.h>

#define STREAM_BUFFER 262144 /* allocated in words of 4 byte each - so, times 4. */
#define PACKET_SIZE 65536

/*
#define MYDEBUG 1 
*/

struct capture {
    uint32_t pckt_count;
    uint32_t buf_start; /* Used when removing packets from the buffer. */
    uint32_t buf_end;
    uint32_t lock; /* Variable for mutex lock of whole struct */
    char * status; /*points to the active buffer, one from the 2 below. */
    uint32_t chana[STREAM_BUFFER];
    uint32_t chanb[STREAM_BUFFER];
};

struct thread_pass {
    int sfd;
    int rfd;
    struct sockaddr_storage peer_addr;
    struct sockaddr_storage remote_addr;
    struct capture *forward;
};

/*  serialise and store packets into a buffer, the first 32 bits being this
    packet size - the next buffer position is dynamically calculated from this. */
void encap(struct capture * stream_buf, int size, unsigned char * packet) {
    uint32_t current = stream_buf->buf_end;
    uint32_t offset = (uint32_t) size; 
    stream_buf->chana[current] = offset;
    offset = offset >> 2;
    offset += 2; /* 2 words for header and buffer tail */
    offset = offset << 2; 
    uint32_t end = current + offset;
    current += 4;
#ifdef MYDEBUG
    printf ("Encap packet size=%u, offset=%u, end=%u\n",
        size, offset, end);
#endif
    memcpy (&stream_buf->chana[current], (const char *) packet, (size_t) size);
    stream_buf->buf_end = end; /* must be last for locking purposes */
    return;
}

/*  pick packets off one at a time FIFO and send them to the forwarding destination
    with a write op. This will evolve into a threaded timed release of the buffer. */
void decap (struct capture * stream_buf) {
    uint32_t current = 0;
    do {
        if (stream_buf->buf_end == current) {
            break;
        }
        uint32_t size = (uint32_t) stream_buf->chana[current] ;
        unsigned char * packet = (unsigned char *)&(stream_buf->chana[current+4]);
        uint32_t offset = (uint32_t) size;
        offset = offset >> 2;
        offset += 2; /* 2 words for header and buffer tail */
        offset = offset << 2; 
#ifdef MYDEBUG
        printf ("Decap packet size=%u, current=%u\n", size, current);
#endif
        current = current + offset;
    }  while (1);
    return;
}

void *forward_func (struct thread_pass *ptr) {
    ssize_t nread;
    char buf[PACKET_SIZE];
    socklen_t peer_addr_len, remote_addr_len;
    peer_addr_len = sizeof(struct sockaddr_storage);
    remote_addr_len = sizeof(struct sockaddr_storage);
#ifdef MYDEBUG
    printf("Debug\n");
#endif
    while (1) {
        nread = recvfrom(ptr->sfd, buf, PACKET_SIZE, 0,
                (struct sockaddr *) &(ptr->peer_addr), &peer_addr_len);
        if (nread == -1)
            continue;  
#ifdef MYDEBUG
        printf("Forward Received %ld bytes: %s\n", (long) nread, buf);
#endif

        if (write(ptr->rfd, buf, nread) != nread) {
#ifdef MYDEBUG
            fprintf(stderr, "partial/failed write\n");
#endif
            exit(EXIT_FAILURE);
        } else {
#ifdef MYDEBUG
            printf("Forward Transmitted %ld bytes: %s\n", (long) nread, buf);
#endif
        }
    }
    return ptr;
}

void *reverse_func (struct thread_pass *ptr) {
    ssize_t nread;
    char buf[PACKET_SIZE];
    socklen_t peer_addr_len, remote_addr_len;
    peer_addr_len = sizeof(struct sockaddr_storage);
    remote_addr_len = sizeof(struct sockaddr_storage);
    nread = read(ptr->rfd, buf, PACKET_SIZE);
    if (nread == -1) {
        perror("read");
        exit(EXIT_FAILURE);
    }
#ifdef MYDEBUG
    printf("Reverse Receive%ld bytes: %s\n", (long) nread, buf);
#endif
    if (sendto(ptr->sfd, buf, nread, 0,
                (struct sockaddr *) &(ptr->peer_addr),
                peer_addr_len) != nread) {
        fprintf(stderr, "Error sending response\n");
    } else {
#ifdef MYDEBUG
        printf("Reverse Transmit%ld bytes: %s\n", (long) nread, buf);
#endif
    }
    return ptr;
}

int main(int argc, char *argv[]) {
    char buf[PACKET_SIZE];
    pthread_t thread_forward, thread_reverse;
    int  iret1, iret2;
    char *message1 = "Forward";
    char *message2 = "Reverse";

    struct addrinfo hints, rhints;
    struct addrinfo *result, *rresult, *rp;
    int sfd, rfd, r, s;
    struct sockaddr_storage peer_addr, remote_addr;
    socklen_t peer_addr_len, remote_addr_len;

    struct capture *forward;
    struct thread_pass *thread_info;
    forward = malloc(sizeof(struct capture)); 
    thread_info = malloc(sizeof(struct thread_pass)); 
    forward->buf_end = 0;

    if (argc != 4) {
        fprintf(stderr, "Usage: %s port remotehost remoteport\n", argv[0]);
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
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
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
        fprintf(stderr, "Could not bind\n");
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
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(r));
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
        fprintf(stderr, "Could not connect\n");
        exit(EXIT_FAILURE);
    } else {
#ifdef MYDEBUG
        fprintf(stderr, "Remote connect success\n");
#endif
    }

    freeaddrinfo(rresult);           /* No longer needed */

    /* Read datagrams and forward them */

/*    for (;;) { */
/*    int i;
    for (i;i<4;i++) {
        peer_addr_len = sizeof(struct sockaddr_storage);
        remote_addr_len = sizeof(struct sockaddr_storage); */
        thread_info->sfd = sfd;
        thread_info->rfd = rfd;
        thread_info->forward = forward;

        iret1 = pthread_create( &thread_forward, NULL, forward_func, thread_info);
        iret2 = pthread_create( &thread_reverse, NULL, reverse_func, thread_info);

        pthread_join( thread_forward, NULL);
        pthread_join( thread_reverse, NULL);
        
/*        char host[NI_MAXHOST], service[NI_MAXSERV];

        s = getnameinfo((struct sockaddr *) &peer_addr,
                        peer_addr_len, host, NI_MAXHOST,
                        service, NI_MAXSERV, NI_NUMERICSERV);
        if (s == 0)
            printf("Received %ld bytes from %s:%s\n",
                    (long) nread, host, service);
        else
            fprintf(stderr, "getnameinfo: %s\n", gai_strerror(s));
    }
    decap (forward);
*/
}

