#ifdef linux
#include "bsd_glue.h"
#else   /* __FreeBSD__ */
#include <sys/param.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#endif  /* __FreeBSD__ */

#include "netmap_mbq.h"


static inline void __mbq_init(struct mbq *q)
{
    q->head = q->tail = NULL;
    q->count = 0;
}

void mbq_safe_init(struct mbq *q)
{
    mtx_init(&q->lock, "mbq", NULL, MTX_SPIN);
    __mbq_init(q);
}

void mbq_init(struct mbq *q)
{
    __mbq_init(q);
}

static inline void __mbq_enqueue(struct mbq *q, struct mbuf *m)
{
    m->m_nextpkt = NULL;
    if (q->tail) {
        q->tail->m_nextpkt = m;
        q->tail = m;
    } else {
        q->head = q->tail = m;
    }
    q->count++;
}

void mbq_safe_enqueue(struct mbq *q, struct mbuf *m)
{
    mtx_lock(&q->lock);
    __mbq_enqueue(q, m);
    mtx_unlock(&q->lock);
}

void mbq_enqueue(struct mbq *q, struct mbuf *m)
{
    __mbq_enqueue(q, m);
}

static inline struct mbuf *__mbq_dequeue(struct mbq *q)
{
    struct mbuf *ret = NULL;

    if (q->head) {
        ret = q->head;
        q->head = ret->m_nextpkt;
        if (q->head == NULL) {
            q->tail = NULL;
        }
        q->count--;
        ret->m_nextpkt = NULL;
    }

    return ret;
}

struct mbuf *mbq_safe_dequeue(struct mbq *q)
{
    struct mbuf *ret;

    mtx_lock(&q->lock);
    ret =  __mbq_dequeue(q);
    mtx_unlock(&q->lock);

    return ret;
}

struct mbuf *mbq_dequeue(struct mbq *q)
{
    return __mbq_dequeue(q);
}

static void __mbq_purge(struct mbq *q, int safe)
{
    struct mbuf *m;

    for (;;) {
        m = safe ? mbq_safe_dequeue(q) : mbq_dequeue(q);
        if (m) {
            m_freem(m);
        } else {
            break;
        }
    }
}

void mbq_purge(struct mbq *q)
{
    __mbq_purge(q, 0);
}

void mbq_safe_purge(struct mbq *q)
{
    __mbq_purge(q, 1);
}

void mbq_safe_destroy(struct mbq *q)
{
    mtx_destroy(&q->lock);
}


void mbq_destroy(struct mbq *q)
{
}

