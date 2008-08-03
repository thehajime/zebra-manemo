/* 
 * Neighbors of Tree Discovery protocol
 *
 * $Id: td_neighbor.h,v c02b24ba03e6 2008/08/03 11:11:33 tazaki $
 *
 * Copyright (c) 2007 {TBD}
 *
 * Author: Hajime TAZAKI  (tazaki@sfc.wide.ad.jp)
 *
 */

#ifndef __TD_NEIGHBOR_H__
#define __TD_NEIGHBOR_H__

/* TreeDiscovery Neighbor State */
#define   NSM_None                    0
#define   NSM_Candidate               1
#define   NSM_Current                 2
#define   NSM_HeldUp                  3
#define   NSM_HeldDown                4
#define   NSM_Collision               5
#define   NSM_AdminDown               6
#define   TD_NBR_STATE_MAX            7

/* TreeDiscovery StateChange Event */
#define   NSM_NewNeighbor             0
#define   NSM_JoinAR                  1
#define   NSM_LeaveAR                 2
#define   NSM_RA_Timeout              3
#define   NSM_TreeHopTimer_Expire     4
#define   NSM_HoldDownTimer_Expire    5
#define   NSM_NextRA_After_Collision  6
#define   NSM_Toggle_AdminDown        7
#define   TD_NBR_EVENT_MAX            8


#define   MAX_NBR_STATE_LOG          32

struct td_nbr_log
{
	time_t time;
	u_int8_t state;
};

struct td_neighbor
{
	struct sockaddr_in6 saddr;
	struct interface *ifp;
	struct nd_opt_tree_discovery *tio;
	struct thread *t_expire;
	struct thread *t_treehop;
	struct thread *t_holddown;
	u_int8_t tree_depth;
	u_int8_t state;
	u_int8_t rsv1;
	u_int16_t rsv2;
	struct td_nbr_log state_log[MAX_NBR_STATE_LOG];
	u_int32_t changes;
};


struct td_neighbor *td_neighbor_new(struct td_master *, struct sockaddr_in6 *,
    int);
void td_neighbor_free(struct td_master *, struct td_neighbor *);
struct td_neighbor *td_neighbor_lookup(struct td_master *, struct sockaddr_in6 *,
    int);
int td_nsm_event(struct td_neighbor *, int);
char * td_neighbor_print(struct td_neighbor *);

#endif /* __TD_NEIGHBOR_H__ */
