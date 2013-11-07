#ifndef __NETMAP_MBQ_H__
#define __NETMAP_MBQ_H__

#ifdef linux
#define SPINLOCK_T  safe_spinlock_t
#else
#define SPINLOCK_T  struct mtx
#endif

/* A FIFO queue of mbufs. */
struct mbq {
    struct mbuf *head;
    struct mbuf *tail;
    int count;
    SPINLOCK_T lock;
};

void mbq_init(struct mbq *q);
void mbq_destroy(struct mbq *q);
void mbq_enqueue(struct mbq *q, struct mbuf *m);
struct mbuf *mbq_dequeue(struct mbq *q);
void mbq_purge(struct mbq *q);

void mbq_safe_init(struct mbq *q);
void mbq_safe_destroy(struct mbq *q);
void mbq_safe_enqueue(struct mbq *q, struct mbuf *m);
struct mbuf *mbq_safe_dequeue(struct mbq *q);
void mbq_safe_purge(struct mbq *q);

static inline unsigned int mbq_len(struct mbq *q)
{
    return q->count;
}

#endif

