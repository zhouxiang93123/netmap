/*-
 * (C) 2011 Luigi Rizzo, Matteo Landi - Universita` di Pisa
 *
 * BSD copyright
 */

/*
 * The tx dma threshold is programmable in units of 32 bytes.
 * Default value was 16*16, lowering it to 1*32 gives a negligible
 * performance improvement but seems to kill operation with packets
 * larger than 1460 bytes. So let's stick with the default, 16
 */
static int re_tx_threshold = 16;
/*
 * There is some code in the intr routine to restart the send queue when
 * the interrupt arrives. re_tx_restart can be set to 0 to disable
 * the feature, but it seems to have no effect.
 */
static int re_tx_restart = 1;

/*
 * toggle to use the high priority queue, if it makes any difference
 */
static int re_tx_hi = 0;

SYSCTL_NODE(_dev, OID_AUTO, re, CTLFLAG_RW, 0, "re card");

SYSCTL_INT(_dev_re, OID_AUTO, tx_thresh,
    CTLFLAG_RW, &re_tx_threshold, 0, "count");
SYSCTL_INT(_dev_re, OID_AUTO, tx_restart,
    CTLFLAG_RW, &re_tx_restart, 0, "count");
SYSCTL_INT(_dev_re, OID_AUTO, tx_hi,
    CTLFLAG_RW, &re_tx_hi, 0, "count");
