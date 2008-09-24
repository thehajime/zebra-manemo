/* 
 * Neighbors of Tree Discovery protocol
 *
 * $Id: td_neighbor.c,v 1a112ce63ba0 2008/09/24 09:24:22 tazaki $
 *
 * Copyright (c) 2007 {TBD}
 *
 * Author: Hajime TAZAKI  (tazaki@sfc.wide.ad.jp)
 *
 */

#include <zebra.h>

#include "linklist.h"
#include "thread.h"
#include "log.h"
#include "if.h"
#include "prefix.h"
#include "vty.h"
#include "memory.h"

#include "interface.h"
#include "td.h"
#include "td_neighbor.h"
#include "rib.h"
#include "bfd.h"
#include "nina.h"

extern struct thread_master *master;
extern struct td_master *td;
extern struct nina *nina_top;

struct prefix_ipv6 def_route = {AF_INET6, 0, IN6ADDR_ANY_INIT};

struct td_neighbor *
td_neighbor_new(struct td_master *td, struct sockaddr_in6 *from, 
    int ifindex)
{
	struct td_neighbor *new;

	new = XCALLOC(MTYPE_TD_NBR, sizeof(struct td_neighbor));
	if(!new)
		return NULL;

	new->saddr.sin6_family = AF_INET6;
#ifdef HAVE_SIN_LEN
	new->saddr.sin6_len = sizeof(struct sockaddr_in6);
#endif
	new->saddr.sin6_scope_id = ifindex;
	memcpy(&new->saddr.sin6_addr, &from->sin6_addr, sizeof(struct in6_addr));
	new->ifp = if_lookup_by_index(ifindex);
	new->state = NSM_None;

	listnode_add(td->td_nbrs, new);

	return new;
}

void
td_neighbor_free(struct td_master *td, struct td_neighbor *nbr)
{
	struct td_neighbor *tmp;
	struct bfd_peer peer;

	tmp = td_neighbor_lookup(td, &nbr->saddr, nbr->ifp->ifindex);

	if(tmp)
	{
		assert(tmp->t_expire == NULL);
		assert(tmp->t_holddown == NULL);
		assert(tmp->t_treehop == NULL);

		listnode_delete(td->td_nbrs, nbr);

		/* Delete BFD neighbor */
		if(nbr->tio){
			memset (&peer, 0, sizeof (struct bfd_peer));
			memcpy (&peer.su, &tmp->saddr, sizeof (tmp->saddr));
			peer.ifindex = tmp->ifp->ifindex;
			peer.type = BFD_PEER_SINGLE_HOP;
			kernel_bfd_delete_peer (&peer, ZEBRA_ROUTE_MNDP);
		}

		XFREE(MTYPE_TD_NBR, nbr);
		return;
	}

	zlog_warn("Couldn't find entry for delete");
	return;
}

struct td_neighbor *
td_neighbor_lookup(struct td_master *td, struct sockaddr_in6 *from, 
    int ifindex)
{
	struct td_neighbor *nbr = NULL, *tmp;
	struct listnode *node;

	if(!listhead(td->td_nbrs))
		return NULL;

	for(node = listhead(td->td_nbrs); node; nextnode(node))
	{
		tmp = getdata(node);
		if(memcmp(&(from->sin6_addr), &(tmp->saddr.sin6_addr), 
			sizeof(struct in6_addr)) == 0)
		{
			nbr = tmp;
			break;
		}
	}

	return nbr;
}

char * 
td_neighbor_print(struct td_neighbor *nbr)
{
	static char buf[INET6_ADDRSTRLEN+IF_NAMESIZE];

	sprintf(buf, "%s%%%s",
	    inet_ntop(AF_INET6, &nbr->saddr.sin6_addr, buf, sizeof(buf)),
	    nbr->ifp->name);

	return buf;
}



int
nsm_treehop_timer(struct thread *thread)
{
	struct td_neighbor *nbr;

	nbr = thread->arg;
	nbr->t_treehop = NULL;

	td_nsm_event(nbr, NSM_TreeHopTimer_Expire);
	return 0;
}

int
nsm_holddown_timer(struct thread *thread)
{
	struct td_neighbor *nbr;

	nbr = thread->arg;
	nbr->t_holddown = NULL;

	td_nsm_event(nbr, NSM_HoldDownTimer_Expire);
	return 0;
}

int
nsm_new_neighbor(struct td_neighbor *nbr)
{
	struct zebra_if *zif;

	zif = nbr->ifp->info;

	/* Collision? Or Not. */
	if((zif->mndp.flags & MNDP_INGRESS_FLAG) && nbr->tio)
	{
		/* FIXME, why depth care? */
		if(nbr->tio->depth == td->tio.depth)
		{
			/* Am I Best? */
			if(((u_int32_t)nbr->tio->tree_pref) < ((u_int32_t)td->tio.tree_pref))
			{
				return NSM_Collision;
			}
		}
	}

	return NSM_Candidate;
}

int
nsm_ignore(struct td_neighbor *nbr)
{
	zlog_debug("nsm_ignore called");
	return 0;
}

int
nsm_join_ar(struct td_neighbor *nbr)
{
	u_int32_t delay;
	int ret;
	char buf[INET6_ADDRSTRLEN];
	char buf2[INET6_ADDRSTRLEN];

	if(nbr->state == NSM_Candidate)
	{
		/* move within same tree */
		if(nbr->tio && (memcmp(nbr->tio->tree_id, td->last_tree_id, 
			    sizeof(nbr->tio->tree_id)) == 0))
		{
			/* Avoid add default route when MR is root-MR */
			if(td->tio.depth > 0) {
				ret = rib_add_ipv6(ZEBRA_ROUTE_MNDP, 0, &def_route, &nbr->saddr.sin6_addr, 
				    nbr->ifp->ifindex, 0);
				if(ret != 0) {
					zlog_warn("rtm_write failure: on ifindex %d (%s)",
					    nbr->ifp->ifindex, strerror(errno));
				}
			}

			/* no delay */
			return NSM_Current;
		}
		else
		{
			assert(nbr->t_treehop == NULL);

			/* draft-td-06 Sec.5.4.1 Tree Hop Timer */
			if(nbr->tio)
				delay = (nbr->tio->depth + random()/LONG_MAX) * nbr->tio->delay;
			else
				delay = 0;

			zlog_info("nbr->tio = %p, OldTID = %s, NewTID, = %s delay = %d"
			    , nbr->tio, 
			    inet_ntop(AF_INET6, &td->last_tree_id, buf, sizeof(buf)),
			    nbr->tio ? 
			    inet_ntop(AF_INET6, &nbr->tio->tree_id, buf2, sizeof(buf2))
			    : "NULL", 
			    delay);
          
			nbr->t_treehop = thread_add_timer(master, nsm_treehop_timer, nbr, delay);
			return NSM_HeldUp;
		}
	}
	else if(nbr->state == NSM_HeldUp)
	{
		/* reset timer */
		if(nbr->t_treehop)
		{
			thread_cancel(nbr->t_treehop);
			nbr->t_treehop = NULL;
		}

		/* draft-td-06 Sec.5.4.1 Tree Hop Timer */
		if(nbr->tio)
			delay = (nbr->tio->depth + random()/LONG_MAX) * nbr->tio->delay;
		else
			delay = 0;

		nbr->t_treehop = thread_add_timer(master, nsm_treehop_timer, nbr, delay);
		return NSM_HeldUp;
	}

	return 0;
}

int
nsm_leave_ar(struct td_neighbor *nbr)
{
	int ret;

	if(nbr->state == NSM_Current)
	{
		/* move within same tree */
		if(nbr->tio && memcmp(nbr->tio->tree_id, td->last_tree_id, 
			sizeof(nbr->tio->tree_id)))
		{
			/* no delay */
			return NSM_Candidate;
		}
		else
		{
			assert(nbr->t_holddown == NULL);

			/* update seq num by odd number */
			if(nbr->tio)
				nbr->tio->seq++;

			nbr->t_holddown = thread_add_timer(master, nsm_holddown_timer, nbr, 
			    TD_HOLDDOWN_TIMER_DEFAULT);

			ret = rib_delete_ipv6(ZEBRA_ROUTE_MNDP, 0, &def_route, &nbr->saddr.sin6_addr, 
			    nbr->ifp->ifindex, 0);
			if(ret != 0)
			{
				zlog_warn("rtm_write failure: on ifindex %d (%s)",
				    nbr->ifp->ifindex, strerror(errno));
			}

			return NSM_HeldDown;
		}
	}

	return 0;
}

int
nsm_toggle_admin_down(struct td_neighbor *nbr)
{
	/* NOP. FIXME */
	return 0;
}

int
nsm_ra_timeout(struct td_neighbor *nbr)
{
	/* transit Held-down state */
	assert(nbr->t_holddown == NULL);

	/* update seq num by odd number */
	if(nbr->tio)
		nbr->tio->seq++;

	nbr->t_holddown = thread_add_timer(master, nsm_holddown_timer, nbr, 
	    TD_HOLDDOWN_TIMER_DEFAULT);

	return 0;
}

int
nsm_treehop_expired(struct td_neighbor *nbr)
{
	int ret;

	/* schedule ra send timer to ingress if */
	/* FIXME */

	/* Avoid add default route when MR is root-MR */
	if(td->tio.depth > 0)
		ret = rib_add_ipv6(ZEBRA_ROUTE_MNDP, 0, &def_route, &nbr->saddr.sin6_addr,
		    nbr->ifp->ifindex, 0);

	/* start nina advert timer */
	if(nina_top && !nina_top->t_delay) {
		nina_set_delay_na_timer(nbr);
	}

	return 0;
}

int
nsm_holddown_expired(struct td_neighbor *nbr)
{
	/* After RA Timeout */
	if(!nbr->t_expire)
	{
		td_neighbor_free(td, nbr);
		/* quick hack... FIXME */
		return TD_NBR_STATE_MAX;
	}

	/* restore state to Candidate */
	return NSM_Candidate;
}

int
nsm_ra_after_collision(struct td_neighbor *nbr)
{
	return 0;
}


struct
{
	int (*func)(struct td_neighbor *);
	int next_state;
} NSM[TD_NBR_STATE_MAX][TD_NBR_EVENT_MAX]
={
	{
		/* None(dummy) */
		{nsm_new_neighbor,        NSM_None},             /* New_Neighbor(or Detect_Collision) */
		{nsm_ignore,              NSM_None},             /* Join_AR */
		{nsm_ignore,              NSM_None},             /* Leave_AR */
		{nsm_ignore,              NSM_None},             /* RA_Timeout */
		{nsm_ignore,              NSM_None},             /* TreeHopTimer_Expired */
		{nsm_ignore,              NSM_None},             /* HoldDownTimer_Expired */
		{nsm_ignore,              NSM_None},             /* NextRA_After_Collision */
		{nsm_ignore,              NSM_None},             /* Toggle_AdminDown */
	},
	{
		/* Candidate */
		{nsm_ignore,              NSM_Candidate},        /* New_Neighbor */
		{nsm_join_ar,             NSM_None},             /* Join_AR */
		{nsm_ignore,              NSM_Candidate},        /* Leave_AR */
		{nsm_ra_timeout,          NSM_HeldDown},         /* RA_Timeout */
		{nsm_ignore,              NSM_Candidate},        /* TreeHopTimer_Expired */
		{nsm_ignore,              NSM_Candidate},        /* HoldDownTimer_Expired */
		{nsm_ignore,              NSM_Candidate},        /* NextRA_After_Collision */
		{nsm_toggle_admin_down,   NSM_AdminDown},        /* Toggle_AdminDown */
	},
	{
		/* Current */
		{nsm_ignore,              NSM_Current},          /* New_Neighbor */
		{nsm_ignore,              NSM_Current},          /* Join_AR */
		{nsm_leave_ar,            NSM_None},             /* Leave_AR */
		{nsm_ra_timeout,          NSM_HeldDown},         /* RA_Timeout */
		{nsm_ignore,              NSM_Current},          /* TreeHopTimer_Expired */
		{nsm_ignore,              NSM_Current},          /* HoldDownTimer_Expired */
		{nsm_ignore,              NSM_Current},          /* NextRA_After_Collision */
		{nsm_toggle_admin_down,   NSM_AdminDown},        /* Toggle_AdminDown */
	},
	{
		/* Held-Up */
		{nsm_ignore,              NSM_HeldUp},           /* New_Neighbor */
		{nsm_join_ar,             NSM_HeldUp},           /* Join_AR */
		{nsm_ignore,              NSM_HeldUp},           /* Leave_AR */
		{nsm_ra_timeout,          NSM_HeldDown},         /* RA_Timeout */
		{nsm_treehop_expired,     NSM_Current},          /* TreeHopTimer_Expired */
		{nsm_ignore,              NSM_HeldUp},           /* HoldDownTimer_Expired */
		{nsm_ignore,              NSM_HeldUp},           /* NextRA_After_Collision */
		{nsm_toggle_admin_down,   NSM_AdminDown},        /* Toggle_AdminDown */
	},
	{
		/* Held-Down */
		{nsm_ignore,              NSM_HeldDown},         /* New_Neighbor */
		{nsm_ignore,              NSM_HeldDown},         /* Join_AR */
		{nsm_ignore,              NSM_HeldDown},         /* Leave_AR */
		{nsm_ignore,              NSM_HeldDown},         /* RA_Timeout */
		{nsm_ignore,              NSM_HeldDown},         /* TreeHopTimer_Expired */
		{nsm_holddown_expired,    NSM_None},             /* HoldDownTimer_Expired */
		{nsm_ignore,              NSM_HeldDown},         /* NextRA_After_Collision */
		{nsm_toggle_admin_down,   NSM_AdminDown},        /* Toggle_AdminDown */
	},
	{
		/* Collision */
		{nsm_ignore,              NSM_Collision},        /* New_Neighbor */
		{nsm_ignore,              NSM_Collision},        /* Join_AR */
		{nsm_ignore,              NSM_Collision},        /* Leave_AR */
		{nsm_ignore,              NSM_Collision},        /* RA_Timeout */
		{nsm_ignore,              NSM_Collision},        /* TreeHopTimer_Expired */
		{nsm_ignore,              NSM_Collision},        /* HoldDownTimer_Expired */
		{nsm_ra_after_collision,  NSM_Candidate},        /* NextRA_After_Collision */
		{nsm_toggle_admin_down,   NSM_AdminDown},        /* Toggle_AdminDown */
	},
};

static char *td_event_string[] =
	{
		"NSM_NewNeighbor",
			"NSM_JoinAR",
			"NSM_LeaveAR",
			"NSM_RA_Timeout",
			"NSM_TreeHopTimer_Expire",
			"NSM_HoldDownTimer_Expire",
			"NSM_NextRA_After_Collision",
			"NSM_Toggle_AdminDown",
	};

char *td_state_string[] =
	{
		"None",
			"Candidate",
			"Current",
			"HeldUp",
			"HeldDown",
			"Collision",
			"AdminDown",
	};

int
td_nsm_event(struct td_neighbor *nbr, int nsm_event)
{
	int next_state, old_state;

	if(1)
		zlog_info("%s NSM:Event (%s)", 
		    td_neighbor_print(nbr), td_event_string[nsm_event]);

	old_state = nbr->state;
	next_state = (*(NSM[nbr->state][nsm_event].func))(nbr);

	/* killing neighbor */
	if(next_state == TD_NBR_STATE_MAX)
	{
		zlog_info("NSM: Neighbor deleted");
		return 0;
	}

	if(!next_state)
		nbr->state = NSM[nbr->state][nsm_event].next_state;
	else
		nbr->state = next_state;

	if(old_state != next_state)
	{
		zlog_info("%s NSM:Sta Chg %s=>%s(%s)", 
		    td_neighbor_print(nbr),
		    td_state_string[old_state], 
		    td_state_string[nbr->state],
		    td_event_string[nsm_event]);


		nbr->state_log[nbr->changes % MAX_NBR_STATE_LOG].state = old_state;
		time(&nbr->state_log[nbr->changes % MAX_NBR_STATE_LOG].time);
		nbr->changes++;
	}

	if(old_state == NSM_HeldDown && nbr->state != NSM_HeldDown){
		td_process_tree_discovery(nbr);
	}

	return 0;
}
