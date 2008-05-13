/* 
 * Tree Discovery protocol
 * draft-thubert-tree-discovery-06
 *
 * $Id: td.h,v 7fcbfc13ab62 2008/05/13 01:36:32 tazaki $
 *
 * Copyright (c) 2007 {TBD}
 *
 * Author: Hajime TAZAKI  (tazaki@sfc.wide.ad.jp)
 *
 */

#ifndef __TD_H__
#define __TD_H_

/* 
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |     Type      |    Length     |G|H|B| Reserved|  Sequence     |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |  TreePref.    |        BootTimeRandom                         |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     | MR Preference |   TreeDepth   |         TreeDelay             |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                           PathDigest                          |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                                                               |
     +                                                               +
     |                            TreeID                             |
     +                                                               +
     |                                                               |
     +                                                               +
     |                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |   sub-option(s)...
     +-+-+-+-+-+-+-+-+-+-+-+-+-+

                         Figure 1: TIO base option
 */

#define   TIO_BASE_FLAG_GROUNDED         (1 << 7)
#define   TIO_BASE_FLAG_HOME_NET         (1 << 6)
#define   TIO_BASE_FLAG_BATTERY          (1 << 5)

#define   ND_OPT_RA_TIO                  100 /* TBD */
#define   TIO_TREE_DELAY_DEFAULT         12 /* 12800 msec */

#define   TD_HOLDDOWN_TIMER_DEFAULT     10 /* 10sec */
#define   TD_RA_INTERVAL_DEFAULT        10 /* 10sec */

#define   TD_VALID_LIFETIME             2592000 /* 30days RFC4861 */
#define   TD_PREFERRED_LIFETIME          604800 /* 7days RFC4861 */

#define   TD_TREE_ID(N)                 ((N)->tio ? (N)->tio->tree_id : \
                                         td->tio.tree_id)
#define   TD_TREE_SAME(X,Y)             (memcmp(TD_TREE_ID((X)), TD_TREE_ID((Y)), \
                                                sizeof(TD_TREE_ID((X)))) == 0)

struct nd_opt_tree_discovery
{
  u_int8_t type;
  u_int8_t len;
  u_int8_t flags;
  u_int8_t seq;
  u_int8_t tree_pref;
  u_int32_t boot_time:24;
  u_int8_t mr_pref;
  u_int8_t depth;
  u_int16_t delay;
  u_int32_t path_digest;
  u_int32_t tree_id[4];
};


struct td_master
{
  struct nd_opt_tree_discovery tio;
  /* should be radix-tree/hash instead of llist? FIXME */
  struct list *td_nbrs;
  struct td_neighbor *attach_rtr;
  int old_accept_ra;
#define TD_IS_FIXED_ROUTER     (1<<0)
  u_int8_t flags;
  u_int16_t rsv1;
  u_int8_t last_tree_seq;
  u_int32_t last_tree_id[4];
  u_int64_t rs_error;
  u_int64_t rs_recv;
  u_int64_t rs_send;
  u_int64_t rs_discard;
  u_int64_t ra_error;
  u_int64_t ra_recv;
  u_int64_t ra_send;
  u_int64_t ra_discard;
};


int td_init();
int td_terminate();
int td_make_ti_option(struct nd_opt_tree_discovery *);
int td_process_tree_discovery(struct td_neighbor *);
int td_ra_timeout(struct thread *);

int mndp_config_write (struct vty *);
void mndp_config_if_write (struct vty *, struct interface *);

#endif  /* __TD_H__ */
