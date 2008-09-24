/* 
 * Network In Node Advertisement
 *
 * draft-thubert-nina-02
 *
 * $Id: nina.h,v 1a112ce63ba0 2008/09/24 09:24:22 tazaki $
 *
 * Copyright (c) 2008 {TBD}
 *
 * Author: Hajime TAZAKI  (tazaki@sfc.wide.ad.jp)
 *
 */

#ifndef __NINA_H__
#define __NINA_H__

#define NINA_DEF_NA_LATENCY            150 /* 150ms */
#define NINA_MAX_DESTROY_INTERVAL      200 /* 200ms */

#define NINA_DEFAULT_NA_LIFETIME       3600000 /* ms */
#define NINA_RETRY_THRESHOLD           3

struct nina_neighbor
{
	/* A reference to the interface of the advertiser Neighbor. */
	struct interface *ifp;
	/* The IPv6 address of the advertiser Neighbor */
	struct prefix ip6;

	struct nd_opt_network_in_node *nino;
	struct thread *t_expire;
};

/* 
   http://tools.ietf.org/html/draft-thubert-nina-02

      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |     Type      |    Length     | Prefix Length |L| Reserved1 |4|
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                         NINO Lifetime                         |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                           Reserved2                           |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |  NINO Depth   |   Reserved3   |        NINO Sequence          |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                                                               |
     +                                                               +
     |                                                               |
     +                   Prefix (Variable Length)                    +
     |                                                               |
     +                                                               +
     |                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */


#define   ND_OPT_NA_NINO                  11 /* TBD */

struct nd_opt_network_in_node
{
	u_int8_t type;
	u_int8_t length;
	u_int8_t prefixlen;
#define   NINO_ONLINK_BIT                (1 << 7)
#define   NINO_V4MAP_BIT                 (1 << 0)
	u_int8_t flags_rsv1;
	u_int32_t lifetime;
	u_int32_t rsv2;
	u_int8_t depth;
	u_int8_t rsv3;
	u_int16_t seq;
	char prefix[0];
};


struct nina_entry
{
	struct route_node *rn;

	/* The state of the entry: ELAPSED, PENDING, or CONFIRMED */
#define NINO_ELAPSED              0
#define NINO_PENDING              1
#define NINO_CONFIRMED            2
	u_int8_t state;
	/* A 'reported' Boolean to keep track whether this prefix was
	   reported already to the parent AR */
	u_int8_t reported;
	/* reserved */
	u_int16_t rsrv1;

	/* A counter of retries to count how many RA-TIOs were sent on the
	   interface to the neighbor without reachability confirmation for
	   the prefix */
	u_int32_t retries;

	/* A reference to the adjacency that was created for that prefix */
	struct nina_neighbor *nbr;
	/* A reference to the ND entry that was created for 
	   the advertiser Neighbor */
	struct nd_entry *nd;

	/* The logical equivalent of the full NINA information. */
	struct nina *top;

	/* Expire Timer */
	struct thread *t_expire;

	/* Lifetime */
	u_int32_t lifetime;

	/* Interface */
	struct interface *ifp;

	/* Depth */
	u_int8_t depth;
	/* NINO Sequence */
	u_int16_t seq;
	/* reserved */
	u_int8_t rsrv2;

};

struct nina
{
	struct route_table *connected;
	struct route_table *reachable;
	struct route_table *unreachable;
	struct list *nbrs;
	/* The DelayNA timer */
	struct thread *t_delay;
	/* The DestroyTimer  */
	struct thread *t_destroy;

	/* Receive Thread */
	struct thread *t_read;
	int sock;
	u_int64_t ns_error;
	u_int64_t ns_recv;
	u_int64_t ns_send;
	u_int64_t na_error;
	u_int64_t na_recv;
	u_int64_t na_send;
	u_int64_t na_nina_recv;
	u_int64_t na_nina_send;
};


int nina_init();
void nina_set_delay_na_timer(struct td_neighbor *);
void nina_send_ratio(struct interface *);

#endif /* __NINA_H__ */
