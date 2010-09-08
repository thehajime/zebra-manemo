/* 
 * Tree Discovery protocol
 * draft-thubert-tree-discovery-06
 *
 * $Id: td.c,v 3b8e514bac06 2010/09/08 04:39:04 tazaki $
 *
 * Copyright (c) 2007 {TBD}
 *
 * Author: Hajime TAZAKI  (tazaki@sfc.wide.ad.jp)
 *
 */

#include <zebra.h>

#include "linklist.h"
#include "prefix.h"
#include "log.h"
#include "if.h"
#include "thread.h"
#include "crc32.h"
#include "command.h"
#include "vty.h"
#include "memory.h"

#include "zebra/debug.h"
#include "zebra/interface.h"
#include "zebra/td.h"
#include "zebra/td_neighbor.h"
#include "zebra/td_api.h"
#include "zebra/rtadv.h"
#include "zebra/nina.h"
#include "zebra/ioctl.h"

#if defined(__FreeBSD__) || defined(__NetBSD__)
const struct in6_addr in6addr_linklocal_allrouters =
  IN6ADDR_LINKLOCAL_ALLROUTERS_INIT;
#endif  /* FreeBSD */

#ifdef GNU_LINUX
u_char in6addr_linklocal_allrouters[] = {0xff,0x02,0,0,0,0,0,0,0,0,0,0,0,0,0,2};
extern u_char in6addr_linklocal_allnodes[];
#endif

#define RA_MAX_RTR_ADV_INTV    600
#define RA_DEFAULT_LIFETIME    (RA_MAX_RTR_ADV_INTV * 3)
#define RA_ADV_REACHABLE_TIME  0

#define ND_PKT_LEN  2048

extern struct rtadv *rtadv;
extern struct nina *nina_top;
struct thread_master *master = NULL;
struct td_master *td = NULL;

static int td_change_attach_router(struct td_neighbor *, struct td_neighbor *);


int
ip6_prefix_equal(struct in6_addr *p1,  struct in6_addr *p2, int len)
{
  int bytelen, bitlen;

  /* sanity check */
  if(0 > len || len > 128)
    {
      zlog_err("TD: in6_are_prefix_equal: invalid prefix length(%d)\n",
           len);
      return (0);
    }

  bytelen = len / 8;
  bitlen = len % 8;

  if(bcmp(&p1->s6_addr, &p2->s6_addr, bytelen))
    return (0);

  if (bitlen != 0 &&
      p1->s6_addr[bytelen] >> (8 - bitlen) !=
      p2->s6_addr[bytelen] >> (8 - bitlen))
    return (0);

  return (1);
}

int
seq_greater(u_int32_t seq1, u_int32_t seq2)
{
  int32_t *comp_seq1 = (int32_t *)&seq1;
  int32_t *comp_seq2 = (int32_t *)&seq2;
  
  if((*comp_seq1 - *comp_seq2) < 0)
    return 0;
  else
    return 1;
}

static
void td_get_coa (struct in6_addr *coa)
{
	struct interface *ifp;
	struct connected *ifc;
	struct prefix *p = NULL;
  struct zebra_if *zif;
  struct listnode *node;

	if (!td->attach_rtr)
		return;

	ifp = td->attach_rtr->ifp;
	zif = ifp->info;
	for(node = listhead(ifp->connected); node; nextnode(node))
		{
			ifc = getdata(node);
			p = ifc->address;
			if(p->family != AF_INET6)
				continue;
			if(CHECK_FLAG(zif->mndp.flags, MNDP_EGRESS_FLAG) &&
				 !IN6_IS_ADDR_LINKLOCAL(&(p->u.prefix6)))
				break;
		}

	memcpy(coa, &p->u.prefix6, sizeof(struct in6_addr));

	{
		char buf[INET6_ADDRSTRLEN];
		zlog_info ("if = %s, egress=%d, ll=%d addr=%s", ifp->name, 
							 CHECK_FLAG(zif->mndp.flags, MNDP_EGRESS_FLAG),
							 IN6_IS_ADDR_LINKLOCAL(&(p->u.prefix6)),
							 inet_ntop(AF_INET6, &(p->u.prefix6), buf, sizeof(buf)));
	}
	
	return;
}

int
td_make_ti_option(struct nd_opt_tree_discovery *tio)
{
  int len = 0;

  if(!tio)
    return 0;

  /* clusterhead operation */
  if(!td->attach_rtr || !td->attach_rtr->tio)
    {
      /* copy from own TIO info */
      memcpy(tio, &td->tio, sizeof(struct nd_opt_tree_discovery));

      if(td->attach_rtr && !td->attach_rtr->tio)
        {
          tio->flags |= TIO_BASE_FLAG_GROUNDED;
          tio->depth = 1;
      }
      else if(td->flags & TD_IS_FIXED_ROUTER)
        {
          tio->flags |= TIO_BASE_FLAG_GROUNDED;
          tio->depth = 0;
        }
      else
        {
          tio->depth = 1;
        }

    }
  else
    {
      /* copy from Attachment Router TIO */
      memcpy(tio, td->attach_rtr->tio, td->attach_rtr->tio->len * 8);
      td->tio.depth = td->attach_rtr->tree_depth +1; 
      if(td->tio.depth == 0){
	      td->tio.depth = 1;
	      zlog_warn("Tree depth would be wrapped");
      }
      /* update tio field */
      tio->depth = td->tio.depth;
      tio->mr_pref = td->tio.mr_pref;
      tio->boot_time = td->tio.boot_time;
      /* FIXME */
      if(1)
        {
          tio->flags |= TIO_BASE_FLAG_BATTERY;
        }
    }
	/* CoA encoding */
	td_get_coa((struct in6_addr *)&tio->coa);
	memcpy (&td->tio.coa, &tio->coa, sizeof (struct in6_addr));

  /* update CRC field */
  /* FIXME non use of CoA */
  tio->path_digest = crc((unsigned char *)tio, tio->len * 8);

	if(IS_ZEBRA_DEBUG_EVENT)
		zlog_info("TIO Flags = %d", tio->flags);

  len += tio->len * 8;
  return len;
}

/* Send Router Solicitation Packet */
static int
td_send_rs_packet(int sock, struct interface *ifp)
{
  int ret;
  struct nd_router_solicit *rtsol;
  u_char buf[ND_PKT_LEN];
  char adata[CMSG_SPACE(sizeof(struct in6_pktinfo)) + CMSG_SPACE(sizeof(int)) + 64];
  struct sockaddr_in6 addr;
  struct msghdr msg;
  struct iovec iov;
  struct cmsghdr *cmsgptr;
  struct in6_pktinfo *pkt;

  memset(&addr, 0, sizeof(struct sockaddr_in6));
  addr.sin6_family = AF_INET6;
  addr.sin6_port = htons(IPPROTO_ICMPV6);
#ifdef SIN6_LEN
  addr.sin6_len = sizeof(struct sockaddr_in6);
#endif /* SIN6_LEN */
  memcpy(&addr.sin6_addr, &in6addr_linklocal_allrouters, sizeof(struct in6_addr));

  msg.msg_name = (void *)&addr;
  msg.msg_namelen = sizeof(struct sockaddr_in6);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = (void *)adata;
  msg.msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo)) + 
      CMSG_SPACE(sizeof(int));

  cmsgptr = CMSG_FIRSTHDR(&msg);

  /* ifindex */
  cmsgptr->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
  cmsgptr->cmsg_level = IPPROTO_IPV6;
  cmsgptr->cmsg_type = IPV6_PKTINFO;
  pkt = (struct in6_pktinfo *)CMSG_DATA(cmsgptr);
  memset(pkt, 0, sizeof(*pkt));
  pkt->ipi6_ifindex = ifp->ifindex;

  cmsgptr = CMSG_NXTHDR(&msg, cmsgptr);
#if 0
  /* HOPLIMIT */
  cmsgptr->cmsg_len = CMSG_LEN(sizeof(int));
  cmsgptr->cmsg_level = IPPROTO_IPV6;
  cmsgptr->cmsg_type = IPV6_HOPLIMIT;
  *(int *)(CMSG_DATA(cmsgptr)) = 255;
  cmsgptr = CMSG_NXTHDR(&msg, cmsgptr);
#endif

  memset(buf, 0, sizeof(buf));
  rtsol = (struct nd_router_solicit *)buf;
  rtsol->nd_rs_type = ND_ROUTER_SOLICIT;
  rtsol->nd_rs_code = 0;
  rtsol->nd_rs_cksum = 0;
  rtsol->nd_rs_reserved = 0;

  iov.iov_base = buf;
  iov.iov_len = sizeof(struct nd_router_solicit);
  
  ret = sendmsg(sock, &msg, 0);
  if(ret < 0)
    {
      td->rs_error++;
      zlog_warn("TD: sendmsg(send_rs) err on %s(%s)", 
           ifp->name, strerror(errno));
      return ret;
    }

  if(0)
    {
      zlog_info("TD: %s: SEND(%llu):RS ifindex=%d", 
           ifp->name, td->ra_send, ifp->ifindex);

      /* Packet dump */
      zlog_dump(buf, ret);
    }

  td->rs_send++;

  return ret;
}



int
td_ra_timeout(struct thread *thread)
{
  struct td_neighbor *nbr;

  nbr = thread->arg;
  nbr->t_expire = NULL;

  if(td->attach_rtr == nbr){
		if(IS_ZEBRA_DEBUG_EVENT)
			zlog_info("Chg Tree: 6");
    td_change_attach_router(nbr, NULL);
  }

  td_nsm_event(nbr, NSM_RA_Timeout);

  return 0;
}



/* Change Attachment Router */
static int
td_change_attach_router(struct td_neighbor *old, struct td_neighbor *new)
{
	char buf[INET6_ADDRSTRLEN];
	char buf2[INET6_ADDRSTRLEN];
	char buf3[INET6_ADDRSTRLEN];

	if(IS_ZEBRA_DEBUG_EVENT){
		zlog_info("Chg AR: old %s(TID=%s) => new %s%%%s(TID=%s)",
		    old ? td_neighbor_print(old) : "NULL", 
		    (old && old->tio) ? inet_ntop(AF_INET6, &old->tio->tree_id, buf, sizeof(buf))
		    : "NULL", 
		    new ? inet_ntop(AF_INET6, &new->saddr.sin6_addr, buf2, sizeof(buf2)) 
		    : "NULL",
		    new ? new->ifp->name : "",
		    (new && new->tio) ? inet_ntop(AF_INET6, &new->tio->tree_id, buf3, sizeof(buf3))
		    : "NULL"
			);
	}

  td->attach_rtr = new;

  if(old && old->tio)
    {
      memcpy(td->last_tree_id, old->tio->tree_id, 
             sizeof(td->last_tree_id));
      td->last_tree_seq = old->tio->seq;
    }
  else
    {
      memset(td->last_tree_id, 0, sizeof(td->last_tree_id));
      td->last_tree_seq = 0;
    }


  if(new)
    td->tio.depth = new->tree_depth +1; 
  else
    td->tio.depth = 1; 

  if(td->tio.depth == 0){
	  td->tio.depth = 1;
	  zlog_warn("%s: Tree depth would be wrapped", __func__);
  }

  if(old)
    td_nsm_event(old, NSM_LeaveAR);
  if(new)
    td_nsm_event(new, NSM_JoinAR);

#ifdef HAVE_SHISA
  api_notify_td_depth_all();
#endif /* HAVE_SHISA */

	if(new && new->state == NSM_Current && new->tio){
		if(nina_top) {
			if(nina_top->t_delay)
				thread_cancel(nina_top->t_delay);
			nina_top->t_delay = thread_add_event(master, 
					nina_delay_na_timer, new, 0);
		}
	}

  return 0;
}

static int
td_tid_cmp(struct td_neighbor *nbr1, struct td_neighbor *nbr2)
{
	int ret=0;

	if(IS_ZEBRA_DEBUG_EVENT){
		char buf[INET6_ADDRSTRLEN];
		char buf2[INET6_ADDRSTRLEN];

		if(IS_ZEBRA_DEBUG_EVENT){
			zlog_info("Comp: TID1=%s with TID2=%s",
					inet_ntop(AF_INET6, &nbr1->tio->tree_id, buf, sizeof(buf)),
					inet_ntop(AF_INET6, &nbr2->tio->tree_id, buf2, sizeof(buf2))); 
		}
	}

	if(ret = (ntohl(nbr2->tio->tree_id[0]) - ntohl(nbr1->tio->tree_id[0])))
		return ret;
	else if(ret = (ntohl(nbr2->tio->tree_id[1]) - ntohl(nbr1->tio->tree_id[1])))
		return ret;
	else if(ret = (ntohl(nbr2->tio->tree_id[2]) -  ntohl(nbr1->tio->tree_id[2])))
			return ret;
	else if(ret = (ntohl(nbr2->tio->tree_id[3]) - ntohl(nbr1->tio->tree_id[3])))
		return ret;

	return 0;
}

/*
 ret <  0 -- nbr1 is better.
 ret == 0 -- nbr1 and nbr2 are the same.
 ret >  0 -- nbr2 is better. 
*/
static int
td_tio_cmp(struct td_neighbor *nbr1, struct td_neighbor *nbr2)
{
	struct timeval timer_now;
	int ret = 0;

  /* if G(grounded) flag is set (or TIO is NULL=>assume GROUDED), this
     tree is assumed as a Internet GW */
  if(!nbr1->tio || (nbr1->tio->flags & TIO_BASE_FLAG_GROUNDED))
    {
      if(nbr2->tio && !(nbr2->tio->flags & TIO_BASE_FLAG_GROUNDED)){
				if(IS_ZEBRA_DEBUG_EVENT)
					zlog_info("Comp Tree: 1");
        return -1;
			}
    }
	if(!nbr2->tio || (nbr2->tio->flags & TIO_BASE_FLAG_GROUNDED))
    {
      if(nbr1->tio && !(nbr1->tio->flags & TIO_BASE_FLAG_GROUNDED)){
				if(IS_ZEBRA_DEBUG_EVENT)
					zlog_info("Comp Tree: 2");
        return 1;
			}
    }

  /* held-down nbr */
  if(nbr1->state == NSM_HeldDown && nbr2->state != NSM_HeldDown){
		if(IS_ZEBRA_DEBUG_EVENT)
			zlog_info("Comp Tree: 3");
    return 1;
	}
  if(nbr2->state == NSM_HeldDown && nbr1->state != NSM_HeldDown){
		if(IS_ZEBRA_DEBUG_EVENT)
			zlog_info("Comp Tree: 4");
    return -1;
	}

	/* TreeID Comparation. Bigger is better. */
#if 0
	if(nbr1->tio && nbr2->tio){
		if(ret = td_tid_cmp(nbr1, nbr2)){
			if(IS_ZEBRA_DEBUG_EVENT)
				zlog_info("Comp Tree: 5 ret = %d", ret);
			return ret;
		}
	}

	/* Tree Preference comparation */
	if(nbr1->tio && nbr2->tio){
		if(ntohl(*(uint32_t *)(&nbr1->tio->tree_pref)) > 
				ntohl(*(uint32_t *)(&nbr2->tio->tree_pref))){
			if(IS_ZEBRA_DEBUG_EVENT)
				zlog_info("Comp Tree: 6");
			return -1;
		}

		if(ntohl(*(uint32_t *)(&nbr1->tio->tree_pref)) <
				ntohl(*(uint32_t *)(&nbr2->tio->tree_pref))){
			if(IS_ZEBRA_DEBUG_EVENT)
				zlog_info("Comp Tree: 7");
			return 1;
		}
	}
#endif

  /* depth. choose deeper tree to join the majority ? */
  if(nbr1->tree_depth != nbr2->tree_depth){
		if(IS_ZEBRA_DEBUG_EVENT)
			zlog_info("Comp Tree: 8");
    return (nbr1->tree_depth - nbr2->tree_depth);
	}

  /* which miscount of nbr is much more? (not in draft, but original) */
  gettimeofday (&timer_now, NULL);

  if (nbr1->t_expire && nbr2->t_expire) {
      time_t t1 = nbr1->lifetime - (nbr1->t_expire->u.sands.tv_sec - timer_now.tv_sec);
      time_t t2 = nbr2->lifetime - (nbr2->t_expire->u.sands.tv_sec - timer_now.tv_sec);

      if((t1 > 60) && (t2 < 60))
	      return 1;
      if((t1 < 60) && (t2 > 60))
	      return -1;
  }

  /* preference */

  /* stable time */

  /* select Attachment Router from DRL in My OWN Manner
     (FIXME, using plug-in?) */
		if(IS_ZEBRA_DEBUG_EVENT)
			zlog_info("Comp Tree: Last");
  return 0;
}

/* 0: same 1: diff */
static int
td_tio_diff(struct td_neighbor *nbr1, struct td_neighbor *nbr2)
{
  if(!nbr1->tio)
    {
      if(nbr2->tio)
          return 1;
    }
  else
    {
      if(!nbr2->tio)
        return 1;

      if(memcmp(nbr1->tio, nbr2->tio, sizeof(struct nd_opt_tree_discovery)))
        return 1;
    }

  return 0;
}

#ifdef USERLAND_ADDR_AUTOCONF
int
td_prefix_expire_timer(struct thread *thread)
{
  struct interface *ifp;
  struct connected *ifc;

  ifc = thread->arg;
  ifp = ifc->ifp;

  if_address_kernel_delete(ifp, &ifa->addr.sin6_addr, &ifc->destination);
  if_address_delete(ifp, ifa);

  return 0;
}

/* Prefix Information processing for 
   Stateless adress auto configuration(RFC4862) */
static int
td_process_prefix_info(struct nd_opt_prefix_info *pi, struct interface *ifp)
{
  struct connected *ifc, *new;
  struct timeval lifetime;
  char buf[INET6_ADDRSTRLEN];
  struct listnode *node;
  struct prefix *p;

  /* 5.5.3(a)  */
  if(!(pi->nd_opt_pi_flags_reserved & ND_OPT_PI_FLAG_AUTO))
    return -1;

  /* 5.5.3(b) */
  if(IN6_IS_ADDR_LINKLOCAL(&pi->nd_opt_pi_prefix))
    return -1;

  /* 5.5.3(c) */
  if(ntohl(pi->nd_opt_pi_preferred_time) > ntohl(pi->nd_opt_pi_valid_time))
    {
      zlog_warn("TD: preferred lifetime is greater than valid lifetime. discard");
      return -1;
    }

  /* 5.5.3(d) */
  for(node = listhead(ifp->connected); node; nextnode(node))
    {
      ifc = getdata(node);
      p = ifc->address;

      if(IN6_IS_ADDR_LINKLOCAL(&(p->u.prefix6)))
        continue;

      if(ifc->destination->prefixlen != pi->nd_opt_pi_prefix_len)
        continue;

      if(ip6_prefix_equal(&p->u.prefix6.s6_addr, &pi->nd_opt_pi_prefix, 
                           pi->nd_opt_pi_prefix_len))
        {
          /* 5.5.3(e) */
          if(ifa->flags & MNDP_IFA_AUTOCONF_FLAG)
            {
              /* reset timer */
              return 0;
            }
          return -1;
        }
    }

  /* 5.5.3(d) */
  if(pi->nd_opt_pi_valid_time == 0)
    return -1;

  /* 5.5.3(d) */
  if(pi->nd_opt_pi_prefix_len + 64 != 128)
    {
      zlog_warn("TD: advertised prefix length is invalid(%d)", 
           pi->nd_opt_pi_prefix_len);
      return -1; 
    }

  /* Now, form address */
  new = if_address_kernel_add(ifp, &pi->nd_opt_pi_prefix, 
                              pi->nd_opt_pi_prefix_len);
  if(!new)
    {
      zlog_warn("TD: something happen on address add(%s)", strerror(errno));
      return -1;
    }

  new->flags |= MNDP_IFA_AUTOCONF_FLAG;
  new->ifp = ifp;
  if_address_add(ifp, new);

  zlog_info("TD: [Address] %s %s add", 
       inet_ntop(AF_INET6, &new->addr.sin6_addr, buf, sizeof(buf)),
       ifp->name);

  /* setting timer */
  lifetime.tv_sec = ntohl(pi->nd_opt_pi_preferred_time);
  lifetime.tv_usec = 0;
  new->t_expire = thread_add_timer_tv(master, td_prefix_expire_timer, 
                                      new, lifetime/1000);

  return 0;
}
#endif /* USERLAND_ADDR_AUTOCONF */

/* Tree Discovery Process(Tree Information Option processing) */
int
td_process_tree_discovery(struct td_neighbor *nbr)
{
	int ret;

	if(td->attach_rtr)
	{
		/* same router */
		if(memcmp(&td->attach_rtr->saddr.sin6_addr, &nbr->saddr.sin6_addr, 
			sizeof(struct in6_addr)) == 0)
		{
			/* FIXME(it doesn't work cause of (td->attach_rtr = nbr) */
			if(td_tio_diff(td->attach_rtr, nbr))
			{
				/* triggered update */
				zlog_info("TD: %s triggered update", td_neighbor_print(nbr));

				rtadv_event (RTADV_TIMER, 1);
			}

			/* if recvd tree-id is own tree-id, it seems to loop, 
				 so avoid to attach */
			if(nbr->tio && (memcmp(td->tio.tree_id, TD_TREE_ID(nbr), 
									sizeof(nbr->tio->tree_id)) == 0))
			{
				if(IS_ZEBRA_DEBUG_EVENT)
					zlog_info("TD: It looks like formed loop(%s). discard and leave current tree",
							td_neighbor_print(nbr));
					/* break tree loop */
					td_change_attach_router(td->attach_rtr, NULL);
			}
		}
		/* from same tree */
		else if(TD_TREE_SAME(td->attach_rtr, nbr))
		{
		/* draft-td-06 Sec.5, 5 */
			if(td->attach_rtr->tree_depth >= nbr->tree_depth)
			{
				ret = td_tio_cmp(td->attach_rtr, nbr);
				if(ret > 0)
				{
					if(IS_ZEBRA_DEBUG_EVENT){
						zlog_info("Chg Tree: 1, old_tio %p new_tio %p",
								td->attach_rtr->tio, nbr->tio);
					}
					/* move in current tree with NO_DELAY */
					td_change_attach_router(td->attach_rtr, nbr);
				}
			}
			/* In caes of AR change (new no TIO RA) */
			else if(!td->attach_rtr->tio && !nbr->tio){
				if(IS_ZEBRA_DEBUG_EVENT)
					zlog_info("Chg Tree: 2");
				/* move in current tree with NO_DELAY */
				td_change_attach_router(td->attach_rtr, nbr);
			}
			else
			{
				/* draft-td-06 Sec.5, 5 ignore RAs */
			}
		}
		/* from different tree */
		else
		{
			ret = td_tio_cmp(td->attach_rtr, nbr);
			if(ret > 0)
			{
				if(IS_ZEBRA_DEBUG_EVENT)
					zlog_info("Chg Tree: 3-1 (move to different tree)");
				/* draft-td-06 Sec.5, 6 
				   move into new tree with Tree Hop Timer */
				td_change_attach_router(td->attach_rtr, nbr);
			}

			/* If both tree are floated, choose the tree which TreeID is greater  */
			if(nbr->tio && !(nbr->tio->flags & TIO_BASE_FLAG_GROUNDED) &&
				 td->attach_rtr->tio && !(td->attach_rtr->tio->flags & TIO_BASE_FLAG_GROUNDED))
				{

					if (memcmp(td->attach_rtr->tio->tree_id, nbr->tio->tree_id, 
										 sizeof(nbr->tio->tree_id)) < 0)
						{
							if(IS_ZEBRA_DEBUG_EVENT)
								zlog_info("Chg Tree: 3-2 (Both are floating tree)");

							td_change_attach_router(td->attach_rtr, nbr);
						}
				}


		}
	}
	else
	{
		/* In case of Parent has TIO */
		if(nbr->tio)
		{
			/* if recvd tree-id is own tree-id, it seems to loop, 
			   so avoid to attach */
			if(memcmp(td->tio.tree_id, TD_TREE_ID(nbr), 
				sizeof(nbr->tio->tree_id)) == 0)
			{
				if(IS_ZEBRA_DEBUG_EVENT)
					zlog_info("TD: It looks like formed loop(%s). discard",
					    td_neighbor_print(nbr));

				/* if loop is detected, try to reset egress 
				   interface, and expect another 802.11 AP */
#ifdef DISCON_WHEN_LOOP
				if_unset_flags (nbr->ifp, IFF_UP);
				if_set_flags (nbr->ifp, IFF_UP);
#endif
			}
			else
			{
				/* draft-td-06 Sec.5, 6 
				   move into new tree with Tree Hop Timer */
				if(td->tio.depth == nbr->tree_depth){
					/* ONLY prevent from loop during E-E */
					if(nbr->tio && (nbr->tio->flags & TIO_BASE_FLAG_GROUNDED)) {
						if(nbr->state != NSM_HeldDown){
							if(IS_ZEBRA_DEBUG_EVENT)
								zlog_info("Chg Tree: 4-1");
							td_change_attach_router(NULL, nbr);
						}
					}
					else if(ntohl(*(uint32_t *)(&nbr->tio->tree_pref)) > 
							ntohl(*(uint32_t *)(&td->tio.tree_pref))){

						if(IS_ZEBRA_DEBUG_EVENT)
							zlog_info("Preference (%lu) is higher than I (%lu)", 
									ntohl(*(uint32_t *)(&nbr->tio->tree_pref)),
									ntohl(*(uint32_t *)(&td->tio.tree_pref)));
						if(nbr->state != NSM_HeldDown){
							if(IS_ZEBRA_DEBUG_EVENT)
								zlog_info("Chg Tree: 4");
							td_change_attach_router(NULL, nbr);
						}
					}
				}
				else{
						if(nbr->state != NSM_HeldDown){
							if(IS_ZEBRA_DEBUG_EVENT)
								zlog_info("Chg Tree: 4-2");
							td_change_attach_router(NULL, nbr);
						}
				}
			}
		}
		else
		{
			if(nbr->state != NSM_HeldDown){
				if(IS_ZEBRA_DEBUG_EVENT)
					zlog_info("Chg Tree: 5");
				td_change_attach_router(NULL, nbr);
			}
		}
	}

	if(nbr->state == NSM_Current && nbr->tio){
		if(nina_top && !nina_top->t_delay) {
			nina_set_delay_na_timer(nbr);
		}
	}


	return 0;
}



DEFUN (ipv6_nd_td_egress,
       ipv6_nd_td_egress_cmd,
       "ipv6 nd td egress",
       IPV6_STR
       "Neighbor discovery\n"
       "Use Tree Discovery\n"
       "Operate as Egress Interface of NEMO\n")
{
  struct interface *ifp;
  struct zebra_if *zif;

  ifp = vty->index;
  zif = ifp->info;

  if(if_is_loopback (ifp))
    {
      vty_out(vty, "Invalid interface%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if(!CHECK_FLAG(zif->mndp.flags, MNDP_EGRESS_FLAG))
    {
      SET_FLAG(zif->mndp.flags, MNDP_EGRESS_FLAG);
      rtadv_event (RTADV_START, rtadv->sock);
      td_send_rs_packet(rtadv->sock, ifp);
    }

  return CMD_SUCCESS;
}

DEFUN (no_ipv6_nd_td_egress,
       no_ipv6_nd_td_egress_cmd,
       "no ipv6 nd td egress",
       NO_STR
       IPV6_STR
       "Neighbor discovery\n"
       "Use Tree Discovery\n"
       "Operate as Egress Interface of NEMO\n")
{
  struct interface *ifp;
  struct zebra_if *zif;

  ifp = vty->index;
  zif = ifp->info;

  if(CHECK_FLAG(zif->mndp.flags, MNDP_EGRESS_FLAG))
    {
      UNSET_FLAG(zif->mndp.flags, MNDP_EGRESS_FLAG);
    }

  return CMD_SUCCESS;
}

DEFUN (ipv6_nd_td_ingress,
       ipv6_nd_td_ingress_cmd,
       "ipv6 nd td ingress",
       IPV6_STR
       "Neighbor discovery\n"
       "Use Tree Discovery\n"
       "Operate as Ingress Interface of NEMO\n")
{
  struct interface *ifp;
  struct zebra_if *zif;

  ifp = vty->index;
  zif = ifp->info;

  if(if_is_loopback (ifp))
    {
      vty_out(vty, "Invalid interface%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if(!CHECK_FLAG(zif->mndp.flags, MNDP_INGRESS_FLAG))
    {
      SET_FLAG(zif->mndp.flags, MNDP_INGRESS_FLAG);
    }

  return CMD_SUCCESS;
}

DEFUN (no_ipv6_nd_td_ingress,
       no_ipv6_nd_td_ingress_cmd,
       "no ipv6 nd td ingress",
       NO_STR
       IPV6_STR
       "Neighbor discovery\n"
       "Use Tree Discovery\n"
       "Operate as Ingress Interface of NEMO\n")
{
  struct interface *ifp;
  struct zebra_if *zif;

  ifp = vty->index;
  zif = ifp->info;

  if(CHECK_FLAG(zif->mndp.flags, MNDP_INGRESS_FLAG))
    {
      UNSET_FLAG(zif->mndp.flags, MNDP_INGRESS_FLAG);
    }

  return CMD_SUCCESS;
}

DEFUN (ipv6_nd_td_fixed,
       ipv6_nd_td_fixed_cmd,
       "ipv6 nd td fixed",
       IPV6_STR
       "Neighbor discovery\n"
       "Use Tree Discovery\n"
       "Operate as Fixed Router(Grounded Flag on)\n")
{

  if(!CHECK_FLAG(td->flags, TD_IS_FIXED_ROUTER))
    {
      SET_FLAG(td->flags, TD_IS_FIXED_ROUTER);
    }

  return CMD_SUCCESS;
}

DEFUN (no_ipv6_nd_td_fixed,
       no_ipv6_nd_td_fixed_cmd,
       "no ipv6 nd td fixed",
       NO_STR
       IPV6_STR
       "Neighbor discovery\n"
       "Use Tree Discovery\n"
       "Operate as Fixed Router(Grounded Flag on)\n")
{
  if(CHECK_FLAG(td->flags, TD_IS_FIXED_ROUTER))
    {
      UNSET_FLAG(td->flags, TD_IS_FIXED_ROUTER);
    }

  return CMD_SUCCESS;
}

#define TIME_BUF 27
static void
td_nbr_show_uptime(struct vty *vty, struct td_neighbor *nbr)
{
  struct timeval timer_now;
  time_t clock;
  struct tm *tm;
  char timebuf [TIME_BUF];
  struct thread *thread;

  gettimeofday (&timer_now, NULL);

  if ((thread = nbr->t_expire) != NULL)
    {
      clock = thread->u.sands.tv_sec - timer_now.tv_sec;
      tm = gmtime (&clock);
      strftime (timebuf, TIME_BUF, "(%H:%M:%S)", tm);
      vty_out (vty, "%s", timebuf);
    }

  return;
}

extern char *td_state_string[];
DEFUN (show_ipv6_nd_td_neighbor,
       show_ipv6_nd_td_neighbor_cmd,
       "show ipv6 nd td neighbor",
       SHOW_STR
       IPV6_STR
       "Neighbor discovery\n"
       "Tree Discovery\n"
       "Show neighbor list(DRL)\n")
{
  struct td_neighbor *nbr;
  struct listnode *node;
  char addrbuf[INET6_ADDRSTRLEN];
  int i, ret;
  struct tm *tm;
  char tbuf[TIME_BUF];

  vty_out(vty, "Default Router List%s", VTY_NEWLINE);
  vty_out(vty, "%-24s %8s %7s %8s %10s%s",
          "Gateway", "TreeDepth", "Grounded", "Iface", "State", VTY_NEWLINE);
  vty_out(vty, "--------------------------------------------------------------%s", VTY_NEWLINE);

  for(node = listhead(td->td_nbrs); node; nextnode(node))
    {
      nbr = getdata(node);
      vty_out(vty, "%-24s %8d %7s %8s %10s%s", 
              inet_ntop(nbr->saddr.sin6_family, 
                        &nbr->saddr.sin6_addr,
                        addrbuf, sizeof(addrbuf)),
              nbr->tree_depth,
              (nbr->tio && (nbr->tio->flags & TIO_BASE_FLAG_GROUNDED)) ||
              !nbr->tio ? "Yes" : "No",
              nbr->ifp->name,
              td_state_string[nbr->state],
              VTY_NEWLINE);

      vty_out(vty, "Expire after  "); 
      td_nbr_show_uptime(vty, nbr);
      vty_out(vty, "%s%s", VTY_NEWLINE, VTY_NEWLINE);
      vty_out(vty, " <State Changes Logs>%s", VTY_NEWLINE);
      vty_out(vty, " State           Time%s", VTY_NEWLINE);
      vty_out(vty, " ----------------------------------------%s", VTY_NEWLINE);
      for(i=0; i < nbr->changes % MAX_NBR_STATE_LOG; i++)
        {
          tm = localtime(&nbr->state_log[i].time);
          ret = strftime(tbuf, TIME_BUF, "%Y/%m/%d %H:%M:%S", tm);

          vty_out(vty, " %-16s%s%s",
                  td_state_string[nbr->state_log[i].state],
                  tbuf, VTY_NEWLINE);
        }
      vty_out(vty, "%s", VTY_NEWLINE);
    }

  return CMD_SUCCESS;
}

DEFUN (show_ipv6_nd_td,
       show_ipv6_nd_td_cmd,
       "show ipv6 nd td",
       SHOW_STR
       IPV6_STR
       "Neighbor discovery\n"
       "Tree Discovery\n")
{
  char buf[INET6_ADDRSTRLEN];

  vty_out(vty, "Tree Discovery Protocol Status%s", VTY_NEWLINE);
  if(!td)
    vty_out(vty, " Not processed%s", VTY_NEWLINE);

  vty_out(vty, " Tree Depth %d%s%s",
          td->tio.depth, td->tio.depth == 1 ? "(Owner of Tree)": "", 
          VTY_NEWLINE);
  vty_out(vty, " MR Preference %d%s",td->tio.mr_pref, VTY_NEWLINE);
  vty_out(vty, " Tree Preference %d%s",td->tio.tree_pref, VTY_NEWLINE);
  vty_out(vty, " Tree Delay %d (ms)%s",td->tio.delay, VTY_NEWLINE);
  vty_out(vty, " Tree ID %s%s", (td->attach_rtr && td->attach_rtr->tio) ?
          inet_ntop(AF_INET6, (struct in6_addr *)&td->attach_rtr->tio->tree_id, 
	      buf, sizeof(buf)) :
          inet_ntop(AF_INET6, (struct in6_addr *)&td->tio.tree_id, 
                    buf, sizeof(buf)), 
      VTY_NEWLINE);

  vty_out(vty, "%s", VTY_NEWLINE);
  vty_out(vty, " Number of Neighbors %d%s", listcount(td->td_nbrs), VTY_NEWLINE);
  vty_out(vty, " Attachment Router %s%s%s", 
      td->attach_rtr ? 
      inet_ntop(AF_INET6, (struct in6_addr *)&td->attach_rtr->saddr.sin6_addr, 
	  buf, sizeof(buf)) : "(Floated)",
      (td->attach_rtr && td->attach_rtr->tio) ? "" : " Non TIO AR", VTY_NEWLINE);
  vty_out(vty, " Flags: %s%s", CHECK_FLAG(td->flags, TD_IS_FIXED_ROUTER) ? 
          "Fixed Router" : " ", VTY_NEWLINE);
  vty_out(vty, " Last Attachment Tree %s, seqnum=%d%s", 
          inet_ntop(AF_INET6, (struct in6_addr *)&td->last_tree_id, 
                    buf, sizeof(buf)), 
          td->last_tree_seq, VTY_NEWLINE);

  vty_out(vty, "%s", VTY_NEWLINE);
  vty_out(vty, " Packet Counter %s", VTY_NEWLINE);
  vty_out(vty, "  Router Solicitation %s", VTY_NEWLINE);
  vty_out(vty, "   Send %llu %s", td->rs_send, VTY_NEWLINE);
  vty_out(vty, "   Receive %llu %s", td->rs_recv, VTY_NEWLINE);
  vty_out(vty, "   Discard %llu %s", td->rs_discard, VTY_NEWLINE);
  vty_out(vty, "   Error %llu %s", td->rs_error, VTY_NEWLINE);
  vty_out(vty, "  Router Advertisement %s", VTY_NEWLINE);
  vty_out(vty, "   Send %llu %s", td->ra_send, VTY_NEWLINE);
  vty_out(vty, "   Receive %llu %s", td->ra_recv, VTY_NEWLINE);
  vty_out(vty, "   Discard %llu %s", td->ra_discard, VTY_NEWLINE);
  vty_out(vty, "   Error %llu %s", td->ra_error, VTY_NEWLINE);


  return CMD_SUCCESS;
}

void
mndp_config_if_write (struct vty *vty, struct interface *ifp)
{
  struct zebra_if *zif;

  zif = ifp->info;

  if(!if_is_loopback (ifp))
    {
      if(CHECK_FLAG(zif->mndp.flags, MNDP_INGRESS_FLAG))
        vty_out (vty, " ipv6 nd td ingress%s", VTY_NEWLINE);

      if(CHECK_FLAG(zif->mndp.flags, MNDP_EGRESS_FLAG))
        vty_out (vty, " ipv6 nd td egress%s", VTY_NEWLINE);
    }
}

int
mndp_config_write (struct vty *vty)
{
  if(CHECK_FLAG(td->flags, TD_IS_FIXED_ROUTER))
    vty_out (vty, "ipv6 nd td fixed%s", VTY_NEWLINE);

  if(nina_top)
    vty_out (vty, "ipv6 nd nina enable%s", VTY_NEWLINE);

  return 0;
}

/* mndp node. */
struct cmd_node mndp_node =
{
  MNDP_NODE,
  "",				/* This node has no interface. */
  1
};


int
td_init()
{
  struct interface *ifp;
  struct connected *ifc;
  struct prefix *p = NULL;
  struct listnode *node, *node2;
	long int rand;

  td = XCALLOC(MTYPE_TD, sizeof(struct td_master));
  if(!td)
    return -1;

  td->td_nbrs = list_new();

  /* set flags(FIXME) */
  td->flags = 0;

  /* set own tree information for clusterhead */
  td->tio.type = ND_OPT_RA_TIO;
  /* units of 8 octets */
  td->tio.len = sizeof(struct nd_opt_tree_discovery) >> 3;
  /* FIXME */
  td->tio.flags = TIO_BASE_FLAG_HOME_NET;
  /* draft-td-06 Sec.5, 1 */
  td->tio.delay = TIO_TREE_DELAY_DEFAULT;
  td->tio.seq = 0;

  /* assign tree-id of own tree from HoA. 
     Currently, pick from interface mip0(SHISA only)(FIXME)  */
	if(ifp = if_lookup_by_name("mip0")){
			for(node = listhead(ifp->connected); node; nextnode(node))
			{
				ifc = getdata(node);
				p = ifc->address;
				if(p->family != AF_INET6)
					continue;
				if(!IN6_IS_ADDR_LINKLOCAL(&(p->u.prefix6)))
					continue;
			break;
			}
	}
	else{
		for(node = listhead(iflist); node; nextnode(node))
		{
			struct zebra_if *zif;

		ifp = getdata(node);
		zif = ifp->info;

			if(if_is_loopback(ifp))
				continue;
			for(node2 = listhead(ifp->connected); node2; nextnode(node2))
			{
				ifc = getdata(node2);
				p = ifc->address;
				if(p->family != AF_INET6)
					continue;
			break;
			}
		}
	}
	if(p){
		memcpy(&td->tio.tree_id, &p->u.prefix6, 
						sizeof(struct in6_addr));
	}
	
  if(memcmp(&td->tio.tree_id, &in6addr_any,
	  sizeof(struct in6_addr)) == 0)
	  zlog_warn("TD: couldn't find HoA for TreeID");

	if(IS_ZEBRA_DEBUG_EVENT || 1){
		char buf[INET6_ADDRSTRLEN];
		zlog_info("TreeID is %s", inet_ntop(AF_INET6, &td->tio.tree_id,
						buf, sizeof(buf)));
	}


  td->tio.tree_pref = 0;
	/* FIXME! */
	if(p)
		srandom(*(unsigned int *)&p->u.val[15]);
  td->tio.boot_time = (random() & 0x00FFFFFF);
  /* draft-td-06 Sec.5, 1 (Fixed Router Case is 0) */
  td->tio.depth = 1;

  /* If using TD, ip6_forwarding=1, accept_rtadv=1 is required.(FIXME) */
  install_node (&mndp_node, mndp_config_write);

  install_element(INTERFACE_NODE, &ipv6_nd_td_egress_cmd);
  install_element(INTERFACE_NODE, &no_ipv6_nd_td_egress_cmd);
  install_element(INTERFACE_NODE, &ipv6_nd_td_ingress_cmd);
  install_element(INTERFACE_NODE, &no_ipv6_nd_td_ingress_cmd);
  install_element(ENABLE_NODE, &show_ipv6_nd_td_neighbor_cmd);
  install_element(VIEW_NODE, &show_ipv6_nd_td_neighbor_cmd);
  install_element(ENABLE_NODE, &show_ipv6_nd_td_cmd);
  install_element(VIEW_NODE, &show_ipv6_nd_td_cmd);

  install_element(CONFIG_NODE, &ipv6_nd_td_fixed_cmd);
  install_element(CONFIG_NODE, &no_ipv6_nd_td_fixed_cmd);

#ifdef HAVE_SHISA
  /* For API */
  api_init(MNDP_API_PATH);
#endif /* HAVE_SHISA */

  return 0;
}

int
td_terminate()
{
  struct interface *ifp;
  struct listnode *node;
  struct zebra_if *zif;

  /* send igress if to purge default route */
  for(node = listhead(iflist); node; nextnode(node))
    {
      ifp = getdata(node);
      zif = ifp->info;

      if(zif->mndp.flags & MNDP_INGRESS_FLAG)
        {
          /* set even number */
          td->tio.seq = td->tio.seq + 2;
          rtadv_send_packet (rtadv->sock, ifp,
	      (struct in6_addr *)&in6addr_linklocal_allnodes, 1);
        }
    }

  return 0;
}

/* Local Variables: */
/* c-basic-offset: 2 */
/* c-indent-level: 2 */
/* indent-tabs-mode: t */
/* tab-width: 2 */
/* end: */
