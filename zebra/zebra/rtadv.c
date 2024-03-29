/* Router advertisement.
   Copyright (C) 1999 Kunihiro Ishiguro.

This file is part of GNU Zebra.

GNU Zebra is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 3, or (at your option)
any later version.

GNU Zebra is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU Zebra; see the file COPYING.  If not, write to
the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
Boston, MA 02110-1301, USA.  */

#include <zebra.h>

#include "memory.h"
#include "sockopt.h"
#include "thread.h"
#include "if.h"
#include "log.h"
#include "prefix.h"
#include "linklist.h"
#include "command.h"

#include "zebra/interface.h"
#include "zebra/rtadv.h"
#include "zebra/debug.h"
#include "zebra/td.h"
#include "zebra/td_neighbor.h"
#include "zebra/nina.h"
#include "zebra/bfd.h"

#if defined (HAVE_IPV6) && defined (RTADV)

/* If RFC2133 definition is used. */
#ifndef IPV6_JOIN_GROUP
#define IPV6_JOIN_GROUP  IPV6_ADD_MEMBERSHIP 
#endif
#ifndef IPV6_LEAVE_GROUP
#define IPV6_LEAVE_GROUP IPV6_DROP_MEMBERSHIP 
#endif

#define ALLNODE   "ff02::1"
#define ALLROUTER "ff02::2"

#ifdef GNU_LINUX
u_char in6addr_linklocal_allnodes[] = {0xff,0x02,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
#endif

int if_join_all_router (int, struct interface *);
int if_leave_all_router (int, struct interface *);

struct rtadv *rtadv = NULL;
extern struct thread_master *master;


struct rtadv *
rtadv_new ()
{
  struct rtadv *new;
  new = XMALLOC (MTYPE_TMP, sizeof (struct rtadv));
  memset (new, 0, sizeof (struct rtadv));
  return new;
}

void
rtadv_free (struct rtadv *rtadv)
{
  XFREE (MTYPE_TMP, rtadv);
}

int
rtadv_recv_packet (int sock, u_char *buf, int buflen,
		   struct sockaddr_in6 *from, unsigned int *ifindex,
		   int *hoplimit)
{
  int ret;
  struct msghdr msg;
  struct iovec iov;
  struct cmsghdr  *cmsgptr;
  struct in6_addr dst;

  char adata[1024];

  /* Fill in message and iovec. */
  msg.msg_name = (void *) from;
  msg.msg_namelen = sizeof (struct sockaddr_in6);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = (void *) adata;
  msg.msg_controllen = sizeof adata;
  iov.iov_base = buf;
  iov.iov_len = buflen;

  /* If recvmsg fail return minus value. */
  ret = recvmsg (sock, &msg, 0);
  if (ret < 0)
    return ret;

  for (cmsgptr = CMSG_FIRSTHDR(&msg); cmsgptr != NULL;
       cmsgptr = CMSG_NXTHDR(&msg, cmsgptr)) 
    {
      /* I want interface index which this packet comes from. */
      if (cmsgptr->cmsg_level == IPPROTO_IPV6 &&
	  cmsgptr->cmsg_type == IPV6_PKTINFO) 
	{
	  struct in6_pktinfo *ptr;
	  
	  ptr = (struct in6_pktinfo *) CMSG_DATA (cmsgptr);
	  *ifindex = ptr->ipi6_ifindex;
	  memcpy(&dst, &ptr->ipi6_addr, sizeof(ptr->ipi6_addr));
        }

      /* Incoming packet's hop limit. */
      if (cmsgptr->cmsg_level == IPPROTO_IPV6 &&
	  cmsgptr->cmsg_type == IPV6_HOPLIMIT)
	*hoplimit = *((int *) CMSG_DATA (cmsgptr));
    }
  return ret;
}

#define RTADV_MSG_SIZE 4096

/* Send router advertisement packet. */
void
rtadv_send_packet (int sock, struct interface *ifp, 
                   const struct in6_addr *to, int expire)
{
  struct msghdr msg;
  struct iovec iov;
  struct cmsghdr  *cmsgptr;
  struct in6_pktinfo *pkt;
  struct sockaddr_in6 addr;
#ifdef HAVE_SOCKADDR_DL
  struct sockaddr_dl *sdl;
#endif /* HAVE_SOCKADDR_DL */
  char adata [sizeof (struct cmsghdr) + sizeof (struct in6_pktinfo)];
  unsigned char buf[RTADV_MSG_SIZE];
  struct nd_router_advert *rtadv;
  int ret;
  int len = 0;
  struct zebra_if *zif;
  struct listnode *node;

  /* Logging of packet. */
  if (IS_ZEBRA_DEBUG_PACKET)
    zlog_info ("Router advertisement send to %s", ifp->name);

  /* Fill in sockaddr_in6. */
  memset (&addr, 0, sizeof (struct sockaddr_in6));
  addr.sin6_family = AF_INET6;
#ifdef SIN6_LEN
  addr.sin6_len = sizeof (struct sockaddr_in6);
#endif /* SIN6_LEN */
  addr.sin6_port = htons (IPPROTO_ICMPV6);
  memcpy (&addr.sin6_addr, to, sizeof (struct in6_addr));

  /* Fetch interface information. */
  zif = ifp->info;

  /* draft-td-06 Sec. 5,7 */
  if(CHECK_FLAG(zif->mndp.flags, MNDP_EGRESS_FLAG))
    {
      if(td->attach_rtr && td->attach_rtr->state == NSM_HeldUp)
        {
          td->ra_discard++;
          return;
        }
    }

  /* Make router advertisement message. */
  rtadv = (struct nd_router_advert *) buf;

  rtadv->nd_ra_type = ND_ROUTER_ADVERT;
  rtadv->nd_ra_code = 0;
  rtadv->nd_ra_cksum = 0;

  rtadv->nd_ra_curhoplimit = 64;
  rtadv->nd_ra_flags_reserved = 0;
  if (zif->rtadv.AdvManagedFlag)
    rtadv->nd_ra_flags_reserved |= ND_RA_FLAG_MANAGED;
  if (zif->rtadv.AdvOtherConfigFlag)
    rtadv->nd_ra_flags_reserved |= ND_RA_FLAG_OTHER;
  if (zif->rtadv.AdvHomeAgentFlag)
    rtadv->nd_ra_flags_reserved |= ND_RA_FLAG_HOME_AGENT;
  if(expire)
    rtadv->nd_ra_router_lifetime = htons (0);
  else
    rtadv->nd_ra_router_lifetime = htons (zif->rtadv.AdvDefaultLifetime);
  rtadv->nd_ra_reachable = htonl (zif->rtadv.AdvReachableTime);
  rtadv->nd_ra_retransmit = htonl (0);

  len = sizeof (struct nd_router_advert);

  if (zif->rtadv.AdvHomeAgentFlag)
    {
      struct nd_opt_homeagent_info *ndopt_hai = 
				(struct nd_opt_homeagent_info *)(buf + len);
      ndopt_hai->nd_opt_hai_type = ND_OPT_HA_INFORMATION;
      ndopt_hai->nd_opt_hai_len = 1;
      ndopt_hai->nd_opt_hai_reserved = 0;
      ndopt_hai->nd_opt_hai_preference = htons(zif->rtadv.HomeAgentPreference);
      ndopt_hai->nd_opt_hai_lifetime = htons(zif->rtadv.HomeAgentLifetime);
      len += sizeof(struct nd_opt_homeagent_info);
    }

  /* Fill in prefix. */
  for (node = listhead (zif->rtadv.AdvPrefixList); node; nextnode (node))
    {
      struct nd_opt_prefix_info *pinfo;
      struct rtadv_prefix *rprefix;

      rprefix = getdata (node);

      pinfo = (struct nd_opt_prefix_info *) (buf + len);

      pinfo->nd_opt_pi_type = ND_OPT_PREFIX_INFORMATION;
      pinfo->nd_opt_pi_len = 4;
      pinfo->nd_opt_pi_prefix_len = rprefix->prefix.prefixlen;

      pinfo->nd_opt_pi_flags_reserved = 0;
      if (rprefix->AdvOnLinkFlag)
				pinfo->nd_opt_pi_flags_reserved |= ND_OPT_PI_FLAG_ONLINK;
      if (rprefix->AdvAutonomousFlag)
				pinfo->nd_opt_pi_flags_reserved |= ND_OPT_PI_FLAG_AUTO;

      pinfo->nd_opt_pi_valid_time = htonl (rprefix->AdvValidLifetime);
      pinfo->nd_opt_pi_preferred_time = htonl (rprefix->AdvPreferredLifetime);
      pinfo->nd_opt_pi_reserved2 = 0;

      /* rootMR or floated tree, adv configured prefix(own prefix==ingress?) */
      if(!td->attach_rtr || td->tio.depth == 1 || 
				  !CHECK_FLAG(zif->mndp.flags, MNDP_EGRESS_FLAG)){
	      memcpy (&pinfo->nd_opt_pi_prefix, &rprefix->prefix.u.prefix6,
						sizeof (struct in6_addr));
      }
      /* Member of tree, adv parent MR's prefix */
      else{
	      memcpy (&pinfo->nd_opt_pi_prefix, &td->attach_rtr->adv_prefix.u.prefix6,
						sizeof (struct in6_addr));
      }

#ifdef DEBUG
      {
	u_char buf[INET6_ADDRSTRLEN];

	zlog_info ("DEBUG %s", inet_ntop (AF_INET6, &pinfo->nd_opt_pi_prefix, buf, INET6_ADDRSTRLEN));

      }
#endif /* DEBUG */

      len += sizeof (struct nd_opt_prefix_info);
    }

  /* Hardware address. */
#ifdef HAVE_SOCKADDR_DL
  sdl = &ifp->sdl;
  if (sdl != NULL && sdl->sdl_alen != 0)
    {
      buf[len++] = ND_OPT_SOURCE_LINKADDR;
      buf[len++] = (sdl->sdl_alen + 2) >> 3;

      memcpy (buf + len, LLADDR (sdl), sdl->sdl_alen);
      len += sdl->sdl_alen;
    }
#else
  if (ifp->hw_addr_len != 0)
    {
      buf[len++] = ND_OPT_SOURCE_LINKADDR;
      buf[len++] = (ifp->hw_addr_len + 2) >> 3;

      memcpy (buf + len, ifp->hw_addr, ifp->hw_addr_len);
      len += ifp->hw_addr_len;
    }
#endif /* HAVE_SOCKADDR_DL */

  /* encode tree information option */
  if(CHECK_FLAG(zif->mndp.flags, MNDP_INGRESS_FLAG))
    {
      len += td_make_ti_option((struct nd_opt_tree_discovery *)
                               ((char *)rtadv + len));


      /* For NINA operation */
      nina_send_ratio(ifp);
    }

  msg.msg_name = (void *) &addr;
  msg.msg_namelen = sizeof (struct sockaddr_in6);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = (void *) adata;
  msg.msg_controllen = sizeof adata;
  iov.iov_base = buf;
  iov.iov_len = len;

  cmsgptr = (struct cmsghdr *)adata;
  cmsgptr->cmsg_len = sizeof adata;
  cmsgptr->cmsg_level = IPPROTO_IPV6;
  cmsgptr->cmsg_type = IPV6_PKTINFO;
  pkt = (struct in6_pktinfo *) CMSG_DATA (cmsgptr);
  /* set link-local address */
  for(node = listhead(ifp->connected); node; nextnode(node)) {
          struct connected *ifc = getdata(node);
          struct prefix *p = ifc->address;
          if(p->family != AF_INET6)
		  continue;
          if(IN6_IS_ADDR_LINKLOCAL(&(p->u.prefix6))) {
		  memcpy (&pkt->ipi6_addr, &(p->u.prefix6), sizeof (struct in6_addr));
		  break;
	  }
  }
  pkt->ipi6_ifindex = ifp->ifindex;

  ret = sendmsg (sock, &msg, 0);
  if(ret < 0)
    {
      td->ra_error++;
      zlog_warn("sendmsg(send_ra) err on %s(%s)", 
           ifp->name, strerror(errno));
      return;
    }

  td->ra_send++;

  if (IS_ZEBRA_DEBUG_PACKET)
    {
      zlog_info("RA: %s: SEND(%llu):RA_TD ifindex=%d", 
           ifp->name, td->ra_send, ifp->ifindex);

      /* Packet dump */
      zlog_dump(buf, ret);
    }

  return;
}

int
rtadv_timer (struct thread *thread)
{
  struct listnode *node;
  struct interface *ifp;
  struct zebra_if *zif;

  rtadv->ra_timer = NULL;
  rtadv_event (RTADV_TIMER, 1);

  for (node = listhead (iflist); node; nextnode (node))
    {
      ifp = getdata (node);

      if (if_is_loopback (ifp))
	continue;

      zif = ifp->info;

      if (zif->rtadv.AdvSendAdvertisements)
	if (--zif->rtadv.AdvIntervalTimer <= 0)
	  {
	    zif->rtadv.AdvIntervalTimer = zif->rtadv.MaxRtrAdvInterval;
            rtadv_send_packet (rtadv->sock, ifp, 
		(struct in6_addr *)&in6addr_linklocal_allnodes, 0);
	  }
    }
  return 0;
}

void
rtadv_process_solicit (struct interface *ifp, struct sockaddr_in6 *from)
{
  if(IS_ZEBRA_DEBUG_EVENT)
	  zlog_info ("Router solicitation received on %s", ifp->name);

  if(IN6_IS_ADDR_UNSPECIFIED(&from->sin6_addr))
    rtadv_send_packet (rtadv->sock, ifp, 
	(struct in6_addr *)&in6addr_linklocal_allnodes, 0);
  else
    rtadv_send_packet (rtadv->sock, ifp, &from->sin6_addr, 0);
}

void
rtadv_process_advert (struct interface *ifp, struct sockaddr_in6 *from,
                      struct nd_router_advert *rtadvp, int len)
{
  struct nd_opt_hdr *opt;
  struct td_neighbor *nbr;
  struct zebra_if *zif;
  char abuf[INET6_ADDRSTRLEN];
  int new = 0;
  int trigger = 0;

  if(IS_ZEBRA_DEBUG_EVENT)
	  zlog_info ("Router advertisement received from %s", 
				inet_ntop(AF_INET6, &from->sin6_addr, abuf, sizeof(abuf)));

  if(!IN6_IS_ADDR_LINKLOCAL(&from->sin6_addr)) {
	  zlog_warn("RA: src %s is not link-local",
	      inet_ntop(AF_INET6, &from->sin6_addr, abuf, sizeof(abuf)));
	  return;
  }

  zif = ifp->info;

  /* FIXME. TD_neighbor?'s name */
  nbr = td_neighbor_lookup(td, from, ifp->ifindex);
  if(nbr)
    {
      if(nbr->t_expire)
        {
          thread_cancel(nbr->t_expire);
          nbr->t_expire = NULL;
        }
    }
  else
    {
      nbr = td_neighbor_new(td, from, ifp->ifindex);
      if(!nbr)
        return;

      /* New_Neighbor */
      td_nsm_event(nbr, NSM_NewNeighbor);
      new = 1;
    }

  /* regist expire timer */
  nbr->t_expire = thread_add_timer(master, td_ra_timeout, nbr, 
      ntohs(rtadvp->nd_ra_router_lifetime));
  nbr->lifetime = ntohs(rtadvp->nd_ra_router_lifetime);

  /* reachable time */
  /* retransmit timer */
#if 0
rtadv->nd_ra_reachable;
rtadv->nd_ra_retransmit;
#endif

  /* Option parsing */
  opt = (struct nd_opt_hdr *)++rtadvp;
  len -= sizeof(struct nd_router_advert);

  while(len>0)
    {
      switch(opt->nd_opt_type)
        {
        case ND_OPT_SOURCE_LINKADDR:
        case ND_OPT_TARGET_LINKADDR:
        case ND_OPT_REDIRECTED_HEADER:
        case ND_OPT_MTU:
          break;
        case ND_OPT_PREFIX_INFORMATION:
					if(nbr){
						memcpy(&nbr->adv_prefix.u.prefix,
								&((struct nd_opt_prefix_info *)opt)->nd_opt_pi_prefix,
								((struct nd_opt_prefix_info *)opt)->nd_opt_pi_prefix_len/8);
						nbr->adv_prefix.family = AF_INET6;
					}
#ifdef USERLAND_ADDR_AUTOCONF
          td_process_prefix_info((struct nd_opt_prefix_info *)opt, ifp);
#endif /* USERLAND_ADDR_AUTOCONF */
          break;
        case ND_OPT_RA_TIO:
          if(!nbr->tio)
            nbr->tio = malloc(sizeof(struct nd_opt_tree_discovery));

					/* If TIO is different from old one */
					if(memcmp(nbr->tio, opt, opt->nd_opt_len * 8))
						{
							struct nd_opt_tree_discovery *tio = (struct nd_opt_tree_discovery *)opt;
							/* triggered update */
							zlog_info("TD: %s triggered update", td_neighbor_print(nbr));
							trigger = 1;
						}

          memcpy(nbr->tio, opt, opt->nd_opt_len * 8);
					if (trigger)
						{
							struct listnode *node;
							for (node = listhead (iflist); node; nextnode (node))
								{
									struct interface *oifp = getdata (node);
									if (if_is_loopback (oifp))
										continue;

									struct zebra_if *ozif = oifp->info;
									if(CHECK_FLAG(ozif->mndp.flags, MNDP_INGRESS_FLAG))
										rtadv_send_packet (rtadv->sock, oifp, 
																			 (struct in6_addr *)&in6addr_linklocal_allnodes, 0);
								}

						}
          break;
        default:
          break;
        }

      /* endof message */
      if(opt->nd_opt_len == 0)
        break;

      len -= opt->nd_opt_len * 8;
      opt = (struct nd_opt_hdr *)(((u_char *)opt) + opt->nd_opt_len * 8);
    }

  if(!nbr->tio)
    {
      if(IS_ZEBRA_DEBUG_EVENT)
        zlog_info("TD: tio doesn't appear(via %s)", nbr->ifp->name);
      nbr->tree_depth = 0;
    }
  else
    {
      nbr->tree_depth = nbr->tio->depth;
      if(IS_ZEBRA_DEBUG_EVENT)
        zlog_info("TD: tio depth is %hhu(via %s)", 
             nbr->tree_depth, nbr->ifp->name);

#ifdef HAVE_KBFD
      if(new){
	      struct bfd_peer peer;
	      /* Add BFD neighbor */
	      memset (&peer, 0, sizeof (struct bfd_peer));
	      memcpy (&peer.su, &nbr->saddr, sizeof (nbr->saddr));
	      peer.ifindex = nbr->ifp->ifindex;
	      peer.type = BFD_PEER_SINGLE_HOP;
	      kernel_bfd_add_peer (&peer, ZEBRA_ROUTE_MNDP);
      }
#endif /* HAVE_KBFD */
    }

  /* Tree Discovery Process */
  if(CHECK_FLAG(zif->mndp.flags, MNDP_EGRESS_FLAG))
    td_process_tree_discovery(nbr);
  else
    {
      zlog_info("TD: %s%%%s: ignore RA cause of not egress/ingress if",
           inet_ntop(AF_INET6, &from->sin6_addr, abuf, sizeof(abuf)),
           ifp->name
           );
      td->ra_discard++;
      return;
    }

  if(0)
    {
      zlog_info("TD: %s%%%s: RECV(%llu):RA_TD ifindex=%d", 
           inet_ntop(AF_INET6, &from->sin6_addr, abuf, sizeof(abuf)),
           ifp->name,
           td->ra_recv, ifp->ifindex);

      /* Packet dump */
      zlog_dump((u_char *)rtadvp, len);
    }

  return;
}

void
rtadv_process_packet (u_char *buf, int len, struct sockaddr_in6 *from,
                      unsigned int ifindex, int hoplimit)
{
  struct icmp6_hdr *icmph;
  struct interface *ifp;
  struct zebra_if *zif;
  struct listnode *node;

  /* Interface search. */
  ifp = if_lookup_by_index (ifindex);
  if (ifp == NULL)
    {
      zlog_warn ("Unknown interface index: %d", ifindex);
      return;
    }

  if (if_is_loopback (ifp))
    return;

  /* Discard self packet */
  for(node = listhead(ifp->connected); node; nextnode(node)) {
          struct connected *ifc = getdata(node);
          struct prefix *p = ifc->address;
	  if(IPV6_ADDR_SAME(&from->sin6_addr, &p->u.prefix6)){
		  if(IS_ZEBRA_DEBUG_EVENT)
			  zlog_warn("RA: recv from self. discard");
		  return;
	  }
  }


  /* Check interface configuration. */
  zif = ifp->info;
  if (! zif->rtadv.AdvSendAdvertisements &&
      !CHECK_FLAG(zif->mndp.flags, MNDP_EGRESS_FLAG))
    return;

  /* ICMP message length check. */
  if (len < sizeof (struct icmp6_hdr))
    {
      zlog_warn ("Invalid ICMPV6 packet length: %d", len);
      return;
    }

  icmph = (struct icmp6_hdr *) buf;

  /* ICMP message type check. */
  if (icmph->icmp6_type != ND_ROUTER_SOLICIT &&
      icmph->icmp6_type != ND_ROUTER_ADVERT)
    {
      zlog_warn ("Unwanted ICMPV6 message type: %d", icmph->icmp6_type);
      return;
    }

  /* Hoplimit check. */
  if (hoplimit >= 0 && hoplimit != 255)
    {
      td->ra_error++;
      zlog_warn ("Invalid hoplimit %d for router advertisement ICMP packet",
		 hoplimit);
      return;
    }

  /* Check ICMP message type. */
  switch(icmph->icmp6_type)
    {
    case ND_ROUTER_SOLICIT:
      rtadv_process_solicit (ifp, from);
      td->rs_recv++;
      break;
    case ND_ROUTER_ADVERT:
      /* process RA packet */
      rtadv_process_advert (ifp, from, (struct nd_router_advert *)buf, len);
      td->ra_recv++;
      break;
    default:
      break;
    }

  return;
}

int
rtadv_read (struct thread *thread)
{
  int sock;
  int len;
  u_char buf[RTADV_MSG_SIZE];
  struct sockaddr_in6 from;
  unsigned int ifindex;
  int hoplimit = -1;

  sock = THREAD_FD (thread);
  rtadv->ra_read = NULL;

  /* Register myself. */
  rtadv_event (RTADV_READ, sock);

  len = rtadv_recv_packet (sock, buf, BUFSIZ, &from, &ifindex, &hoplimit);

  if (len < 0) 
    {
      zlog_warn ("router solicitation recv failed: %s.", strerror (errno));
      return len;
    }

  rtadv_process_packet (buf, len, &from, ifindex, hoplimit);

  return 0;
}

int
rtadv_make_socket (void)
{
  int sock;
  int ret;
  struct icmp6_filter filter;

  sock = socket (AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);

  /* When we can't make ICMPV6 socket simply back.  Router
     advertisement feature will not be supported. */
  if (sock < 0)
    return -1;

  ret = setsockopt_ipv6_pktinfo (sock, 1);
  if (ret < 0)
    return ret;
  ret = setsockopt_ipv6_checksum (sock, 2);
  if (ret < 0)
    return ret;
  ret = setsockopt_ipv6_multicast_loop (sock, 0);
  if (ret < 0)
    return ret;
  ret = setsockopt_ipv6_unicast_hops (sock, 255);
  if (ret < 0)
    return ret;
  ret = setsockopt_ipv6_multicast_hops (sock, 255);
  if (ret < 0)
    return ret;
  ret = setsockopt_ipv6_hoplimit (sock, 1);
  if (ret < 0)
    return ret;

  ICMP6_FILTER_SETBLOCKALL(&filter);
  ICMP6_FILTER_SETPASS (ND_ROUTER_SOLICIT, &filter);
  ICMP6_FILTER_SETPASS (ND_ROUTER_ADVERT, &filter);

  ret = setsockopt (sock, IPPROTO_ICMPV6, ICMP6_FILTER, &filter,
		    sizeof (struct icmp6_filter));
  if (ret < 0)
    {
      zlog_info ("ICMP6_FILTER set fail: %s", strerror (errno));
      return ret;
    }

  return sock;
}

struct rtadv_prefix *
rtadv_prefix_new ()
{
  struct rtadv_prefix *new;

  new = XMALLOC (MTYPE_RTADV_PREFIX, sizeof (struct rtadv_prefix));
  memset (new, 0, sizeof (struct rtadv_prefix));

  return new;
}

void
rtadv_prefix_free (struct rtadv_prefix *rtadv_prefix)
{
  XFREE (MTYPE_RTADV_PREFIX, rtadv_prefix);
}

struct rtadv_prefix *
rtadv_prefix_lookup (struct list *rplist, struct prefix *p)
{
  struct listnode *node;
  struct rtadv_prefix *rprefix;

  for (node = listhead (rplist); node; nextnode (node))
    {
      rprefix = getdata (node);
      if (prefix_same (&rprefix->prefix, p))
	return rprefix;
    }
  return NULL;
}

struct rtadv_prefix *
rtadv_prefix_get (struct list *rplist, struct prefix *p)
{
  struct rtadv_prefix *rprefix;
  
  rprefix = rtadv_prefix_lookup (rplist, p);
  if (rprefix)
    return rprefix;

  rprefix = rtadv_prefix_new ();
  memcpy (&rprefix->prefix, p, sizeof (struct prefix));
  listnode_add (rplist, rprefix);

  return rprefix;
}

void
rtadv_prefix_set (struct zebra_if *zif, struct rtadv_prefix *rp)
{
  struct rtadv_prefix *rprefix;
  
  rprefix = rtadv_prefix_get (zif->rtadv.AdvPrefixList, &rp->prefix);

  /* Set parameters. */
  rprefix->AdvValidLifetime = rp->AdvValidLifetime;
  rprefix->AdvPreferredLifetime = rp->AdvPreferredLifetime;
  rprefix->AdvOnLinkFlag = rp->AdvOnLinkFlag;
  rprefix->AdvAutonomousFlag = rp->AdvAutonomousFlag;
}

int
rtadv_prefix_reset (struct zebra_if *zif, struct rtadv_prefix *rp)
{
  struct rtadv_prefix *rprefix;
  
  rprefix = rtadv_prefix_lookup (zif->rtadv.AdvPrefixList, &rp->prefix);
  if (rprefix != NULL)
    {
      listnode_delete (zif->rtadv.AdvPrefixList, (void *) rprefix);
      rtadv_prefix_free (rprefix);
      return 1;
    }
  else
    return 0;
}

DEFUN (ipv6_nd_suppress_ra,
       ipv6_nd_suppress_ra_cmd,
       "ipv6 nd suppress-ra",
       IP_STR
       "Neighbor discovery\n"
       "Suppress Router Advertisement\n")
{
  struct interface *ifp;
  struct zebra_if *zif;

  ifp = vty->index;
  zif = ifp->info;

  if (if_is_loopback (ifp))
    {
      vty_out (vty, "Invalid interface%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (zif->rtadv.AdvSendAdvertisements)
    {
      zif->rtadv.AdvSendAdvertisements = 0;
      zif->rtadv.AdvIntervalTimer = 0;
      rtadv->adv_if_count--;

      if_leave_all_router (rtadv->sock, ifp);

      if (rtadv->adv_if_count == 0)
	rtadv_event (RTADV_STOP, 0);
    }

  return CMD_SUCCESS;
}

ALIAS (ipv6_nd_suppress_ra,
       no_ipv6_nd_send_ra_cmd,
       "no ipv6 nd send-ra",
       NO_STR
       IP_STR
       "Neighbor discovery\n"
       "Send Router Advertisement\n");

DEFUN (no_ipv6_nd_suppress_ra,
       no_ipv6_nd_suppress_ra_cmd,
       "no ipv6 nd suppress-ra",
       NO_STR
       IP_STR
       "Neighbor discovery\n"
       "Suppress Router Advertisement\n")
{
  struct interface *ifp;
  struct zebra_if *zif;

  ifp = vty->index;
  zif = ifp->info;

  if (if_is_loopback (ifp))
    {
      vty_out (vty, "Invalid interface%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (! zif->rtadv.AdvSendAdvertisements)
    {
      zif->rtadv.AdvSendAdvertisements = 1;
      zif->rtadv.AdvIntervalTimer = 0;
      rtadv->adv_if_count++;

      if_join_all_router (rtadv->sock, ifp);

      if (rtadv->adv_if_count == 1)
	rtadv_event (RTADV_START, rtadv->sock);
    }

  return CMD_SUCCESS;
}

ALIAS (no_ipv6_nd_suppress_ra,
       ipv6_nd_send_ra_cmd,
       "ipv6 nd send-ra",
       IP_STR
       "Neighbor discovery\n"
       "Send Router Advertisement\n");

DEFUN (ipv6_nd_ra_interval,
       ipv6_nd_ra_interval_cmd,
       "ipv6 nd ra-interval SECONDS",
       IP_STR
       "Neighbor discovery\n"
       "Router Advertisement interval\n"
       "Router Advertisement interval in seconds\n")
{
  int interval;
  struct interface *ifp;
  struct zebra_if *zif;

  ifp = (struct interface *) vty->index;
  zif = ifp->info;

  interval = atoi (argv[0]);

  if (interval < 0)
    {
      vty_out (vty, "Invalid Router Advertisement Interval%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  zif->rtadv.MaxRtrAdvInterval = interval;
  zif->rtadv.MinRtrAdvInterval = 0.33 * interval;
  zif->rtadv.AdvIntervalTimer = 0;

  return CMD_SUCCESS;
}

DEFUN (no_ipv6_nd_ra_interval,
       no_ipv6_nd_ra_interval_cmd,
       "no ipv6 nd ra-interval",
       NO_STR
       IP_STR
       "Neighbor discovery\n"
       "Router Advertisement interval\n")
{
  struct interface *ifp;
  struct zebra_if *zif;

  ifp = (struct interface *) vty->index;
  zif = ifp->info;

  zif->rtadv.MaxRtrAdvInterval = RTADV_MAX_RTR_ADV_INTERVAL;
  zif->rtadv.MinRtrAdvInterval = RTADV_MIN_RTR_ADV_INTERVAL;
  zif->rtadv.AdvIntervalTimer = zif->rtadv.MaxRtrAdvInterval;

  return CMD_SUCCESS;
}

DEFUN (ipv6_nd_ra_lifetime,
       ipv6_nd_ra_lifetime_cmd,
       "ipv6 nd ra-lifetime SECONDS",
       IP_STR
       "Neighbor discovery\n"
       "Router lifetime\n"
       "Router lifetime in seconds\n")
{
  int lifetime;
  struct interface *ifp;
  struct zebra_if *zif;

  ifp = (struct interface *) vty->index;
  zif = ifp->info;

  lifetime = atoi (argv[0]);

  if (lifetime < 0 || lifetime > 0xffff)
    {
      vty_out (vty, "Invalid Router Lifetime%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  zif->rtadv.AdvDefaultLifetime = lifetime;

  return CMD_SUCCESS;
}

DEFUN (no_ipv6_nd_ra_lifetime,
       no_ipv6_nd_ra_lifetime_cmd,
       "no ipv6 nd ra-lifetime",
       NO_STR
       IP_STR
       "Neighbor discovery\n"
       "Router lifetime\n")
{
  struct interface *ifp;
  struct zebra_if *zif;

  ifp = (struct interface *) vty->index;
  zif = ifp->info;

  zif->rtadv.AdvDefaultLifetime = RTADV_ADV_DEFAULT_LIFETIME;

  return CMD_SUCCESS;
}

DEFUN (ipv6_nd_reachable_time,
       ipv6_nd_reachable_time_cmd,
       "ipv6 nd reachable-time MILLISECONDS",
       IP_STR
       "Neighbor discovery\n"
       "Reachable time\n"
       "Reachable time in milliseconds\n")
{
  u_int32_t rtime;
  struct interface *ifp;
  struct zebra_if *zif;

  ifp = (struct interface *) vty->index;
  zif = ifp->info;

  rtime = (u_int32_t) atol (argv[0]);

  if (rtime > RTADV_MAX_REACHABLE_TIME)
    {
      vty_out (vty, "Invalid Reachable time%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  zif->rtadv.AdvReachableTime = rtime;

  return CMD_SUCCESS;
}

DEFUN (no_ipv6_nd_reachable_time,
       no_ipv6_nd_reachable_time_cmd,
       "no ipv6 nd reachable-time",
       NO_STR
       IP_STR
       "Neighbor discovery\n"
       "Reachable time\n")
{
  struct interface *ifp;
  struct zebra_if *zif;

  ifp = (struct interface *) vty->index;
  zif = ifp->info;

  zif->rtadv.AdvReachableTime = 0;

  return CMD_SUCCESS;
}

DEFUN (ipv6_nd_homeagent_preference,
       ipv6_nd_homeagent_preference_cmd,
       "ipv6 nd home-agent-preference PREFERENCE",
       "Interface IPv6 config commands\n"
       "Neighbor discovery\n"
       "Home Agent preference\n"
       "Home Agent preference value 0..65535\n")
{
  u_int32_t hapref;
  struct interface *ifp;
  struct zebra_if *zif;

  ifp = (struct interface *) vty->index;
  zif = ifp->info;

  hapref = (u_int32_t) atol (argv[0]);

  if (hapref > 65535)
    {
      vty_out (vty, "Invalid Home Agent preference%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  zif->rtadv.HomeAgentPreference = hapref;

  return CMD_SUCCESS;
}

DEFUN (no_ipv6_nd_homeagent_preference,
       no_ipv6_nd_homeagent_preference_cmd,
       "no ipv6 nd home-agent-preference",
       NO_STR
       "Interface IPv6 config commands\n"
       "Neighbor discovery\n"
       "Home Agent preference\n")
{
  struct interface *ifp;
  struct zebra_if *zif;

  ifp = (struct interface *) vty->index;
  zif = ifp->info;

  zif->rtadv.HomeAgentPreference = 0;

  return CMD_SUCCESS;
}

DEFUN (ipv6_nd_homeagent_lifetime,
       ipv6_nd_homeagent_lifetime_cmd,
       "ipv6 nd home-agent-lifetime SECONDS",
       "Interface IPv6 config commands\n"
       "Neighbor discovery\n"
       "Home Agent lifetime\n"
       "Home Agent lifetime in seconds\n")
{
  u_int32_t ha_ltime;
  struct interface *ifp;
  struct zebra_if *zif;

  ifp = (struct interface *) vty->index;
  zif = ifp->info;

  ha_ltime = (u_int32_t) atol (argv[0]);

  if (ha_ltime > RTADV_MAX_HALIFETIME)
    {
      vty_out (vty, "Invalid Home Agent Lifetime time%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  zif->rtadv.HomeAgentLifetime = ha_ltime;

  return CMD_SUCCESS;
}

DEFUN (no_ipv6_nd_homeagent_lifetime,
       no_ipv6_nd_homeagent_lifetime_cmd,
       "no ipv6 nd home-agent-lifetime",
       NO_STR
       "Interface IPv6 config commands\n"
       "Neighbor discovery\n"
       "Home Agent lifetime\n")
{
  struct interface *ifp;
  struct zebra_if *zif;

  ifp = (struct interface *) vty->index;
  zif = ifp->info;

  zif->rtadv.HomeAgentLifetime = 0;

  return CMD_SUCCESS;
}

DEFUN (ipv6_nd_homeagent_config_flag,
       ipv6_nd_homeagent_config_flag_cmd,
       "ipv6 nd home-agent-config-flag",
       "Interface IPv6 config commands\n"
       "Neighbor discovery\n"
       "Home Agent configuration flag\n")
{
  struct interface *ifp;
  struct zebra_if *zif;

  ifp = (struct interface *) vty->index;
  zif = ifp->info;

  zif->rtadv.AdvHomeAgentFlag = 1;

  return CMD_SUCCESS;
}

DEFUN (no_ipv6_nd_homeagent_config_flag,
       no_ipv6_nd_homeagent_config_flag_cmd,
       "no ipv6 nd home-agent-config-flag",
       NO_STR
       "Interface IPv6 config commands\n"
       "Neighbor discovery\n"
       "Home Agent configuration flag\n")
{
  struct interface *ifp;
  struct zebra_if *zif;

  ifp = (struct interface *) vty->index;
  zif = ifp->info;

  zif->rtadv.AdvHomeAgentFlag = 0;

  return CMD_SUCCESS;
}

DEFUN (ipv6_nd_managed_config_flag,
       ipv6_nd_managed_config_flag_cmd,
       "ipv6 nd managed-config-flag",
       IP_STR
       "Neighbor discovery\n"
       "Managed address configuration flag\n")
{
  struct interface *ifp;
  struct zebra_if *zif;

  ifp = (struct interface *) vty->index;
  zif = ifp->info;

  zif->rtadv.AdvManagedFlag = 1;

  return CMD_SUCCESS;
}

DEFUN (no_ipv6_nd_managed_config_flag,
       no_ipv6_nd_managed_config_flag_cmd,
       "no ipv6 nd managed-config-flag",
       NO_STR
       IP_STR
       "Neighbor discovery\n"
       "Managed address configuration flag\n")
{
  struct interface *ifp;
  struct zebra_if *zif;

  ifp = (struct interface *) vty->index;
  zif = ifp->info;

  zif->rtadv.AdvManagedFlag = 0;

  return CMD_SUCCESS;
}

DEFUN (ipv6_nd_other_config_flag,
       ipv6_nd_other_config_flag_cmd,
       "ipv6 nd other-config-flag",
       IP_STR
       "Neighbor discovery\n"
       "Other statefull configuration flag\n")
{
  struct interface *ifp;
  struct zebra_if *zif;

  ifp = (struct interface *) vty->index;
  zif = ifp->info;

  zif->rtadv.AdvOtherConfigFlag = 1;

  return CMD_SUCCESS;
}

DEFUN (no_ipv6_nd_other_config_flag,
       no_ipv6_nd_other_config_flag_cmd,
       "no ipv6 nd other-config-flag",
       NO_STR
       IP_STR
       "Neighbor discovery\n"
       "Other statefull configuration flag\n")
{
  struct interface *ifp;
  struct zebra_if *zif;

  ifp = (struct interface *) vty->index;
  zif = ifp->info;

  zif->rtadv.AdvOtherConfigFlag = 0;

  return CMD_SUCCESS;
}

DEFUN (ipv6_nd_prefix_advertisement_default,
       ipv6_nd_prefix_advertisement_default_cmd,
       "ipv6 nd prefix-advertisement",
       IP_STR
       "Neighbor discovery\n"
       "Prefix information\n")
{
  int i;
  int ret;
  struct interface *ifp;
  struct zebra_if *zebra_if;
  struct rtadv_prefix *rp;
  struct listnode *node;

  ifp = (struct interface *) vty->index;
  zebra_if = ifp->info;

  rp = rtadv_prefix_new();
  for(node = listhead(ifp->connected); node; nextnode(node)) {
          struct connected *ifc = getdata(node);
          struct prefix *p = ifc->address;
          if(p->family != AF_INET6)
		  continue;
	  /* set first non-ll prefix to adv */
          if(!IN6_IS_ADDR_LINKLOCAL(&(p->u.prefix6))) {
		  prefix_copy(&rp->prefix, p);
		  apply_mask(&rp->prefix);
		  break;
	  }
  }

  rp->AdvOnLinkFlag = 1;
  rp->AdvAutonomousFlag = 1;
  rp->AdvValidLifetime = RTADV_VALID_LIFETIME;
  rp->AdvPreferredLifetime = RTADV_PREFERRED_LIFETIME;

  rtadv_prefix_set (zebra_if, rp);

  return CMD_SUCCESS;
}

DEFUN (ipv6_nd_prefix_advertisement,
       ipv6_nd_prefix_advertisement_cmd,
       "ipv6 nd prefix-advertisement IPV6PREFIX VALID PREFERRED [onlink] [autoconfig]",
       IP_STR
       "Neighbor discovery\n"
       "Prefix information\n"
       "IPv6 prefix\n"
       "Valid lifetime in seconds\n"
       "Preferred lifetime in seconds\n"
       "On link flag\n"
       "Autonomous address-configuration flag\n")
{
  int i;
  int ret;
  struct interface *ifp;
  struct zebra_if *zebra_if;
  struct rtadv_prefix rp;

  ifp = (struct interface *) vty->index;
  zebra_if = ifp->info;

  ret = str2prefix_ipv6 (argv[0], (struct prefix_ipv6 *) &rp.prefix);
  if (!ret)
    {
      vty_out (vty, "Malformed IPv6 prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (argc == 1)
    {
      rp.AdvValidLifetime = RTADV_VALID_LIFETIME;
      rp.AdvPreferredLifetime = RTADV_PREFERRED_LIFETIME;
      rp.AdvOnLinkFlag = 1;
      rp.AdvAutonomousFlag = 1;
    }
  else
    {
      rp.AdvValidLifetime = (u_int32_t) atol (argv[1]);
      rp.AdvPreferredLifetime = (u_int32_t) atol (argv[2]);
      if (rp.AdvPreferredLifetime > rp.AdvValidLifetime)
	{
	  vty_out (vty, "Invalid preferred lifetime%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}

      rp.AdvOnLinkFlag = 0;
      rp.AdvAutonomousFlag = 0;
      for (i = 3; i < argc; i++)
	{
	  if (! strcmp (argv[i], "onlink"))
	    rp.AdvOnLinkFlag = 1;
	  else if (! strcmp (argv[i], "autoconfig"))
	    rp.AdvAutonomousFlag = 1;
	}
    }

  rtadv_prefix_set (zebra_if, &rp);

  return CMD_SUCCESS;
}

ALIAS (ipv6_nd_prefix_advertisement,
       ipv6_nd_prefix_advertisement_no_val_cmd,
       "ipv6 nd prefix-advertisement IPV6PREFIX",
       IP_STR
       "Neighbor discovery\n"
       "Prefix information\n"
       "IPv6 prefix\n");

DEFUN (no_ipv6_nd_prefix_advertisement_default,
       no_ipv6_nd_prefix_advertisement_default_cmd,
       "no ipv6 nd prefix-advertisement",
       NO_STR
       IP_STR
       "Neighbor discovery\n"
       "Prefix information\n")
{
  int ret;
  struct interface *ifp;
  struct zebra_if *zebra_if;
  struct rtadv_prefix rp;
  struct listnode *node;

  ifp = (struct interface *) vty->index;
  zebra_if = ifp->info;

  for(node = listhead(ifp->connected); node; nextnode(node)) {
          struct connected *ifc = getdata(node);
          struct prefix *p = ifc->address;
          if(p->family != AF_INET6)
		  continue;
	  /* set first non-ll prefix to adv */
          if(!IN6_IS_ADDR_LINKLOCAL(&(p->u.prefix6))) {
		  prefix_copy(&rp.prefix, p);
		  break;
	  }
  }

  ret = rtadv_prefix_reset (zebra_if, &rp);
  if (!ret)
    {
      vty_out (vty, "Non-exist IPv6 prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return CMD_SUCCESS;
}

DEFUN (no_ipv6_nd_prefix_advertisement,
       no_ipv6_nd_prefix_advertisement_cmd,
       "no ipv6 nd prefix-advertisement IPV6PREFIX",
       NO_STR
       IP_STR
       "Neighbor discovery\n"
       "Prefix information\n"
       "IPv6 prefix\n")
{
  int ret;
  struct interface *ifp;
  struct zebra_if *zebra_if;
  struct rtadv_prefix rp;

  ifp = (struct interface *) vty->index;
  zebra_if = ifp->info;

  ret = str2prefix_ipv6 (argv[0], (struct prefix_ipv6 *) &rp.prefix);
  if (!ret)
    {
      vty_out (vty, "Malformed IPv6 prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  ret = rtadv_prefix_reset (zebra_if, &rp);
  if (!ret)
    {
      vty_out (vty, "Non-exist IPv6 prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return CMD_SUCCESS;
}

/* Write configuration about router advertisement. */
void
rtadv_config_write (struct vty *vty, struct interface *ifp)
{
  struct zebra_if *zif;
  struct listnode *node;
  struct rtadv_prefix *rprefix;
  char buf[INET6_ADDRSTRLEN];

  if (! rtadv)
    return;

  zif = ifp->info;

  if (! if_is_loopback (ifp))
    {
      if (zif->rtadv.AdvSendAdvertisements)
	vty_out (vty, " no ipv6 nd suppress-ra%s", VTY_NEWLINE);
      else
	vty_out (vty, " ipv6 nd suppress-ra%s", VTY_NEWLINE);
    }

  if (zif->rtadv.MaxRtrAdvInterval != RTADV_MAX_RTR_ADV_INTERVAL)
    vty_out (vty, " ipv6 nd ra-interval %d%s", zif->rtadv.MaxRtrAdvInterval,
	     VTY_NEWLINE);

  if (zif->rtadv.AdvDefaultLifetime != RTADV_ADV_DEFAULT_LIFETIME)
    vty_out (vty, " ipv6 nd ra-lifetime %d%s", zif->rtadv.AdvDefaultLifetime,
	     VTY_NEWLINE);

  if (zif->rtadv.AdvReachableTime)
    vty_out (vty, " ipv6 nd reachable-time %d%s", zif->rtadv.AdvReachableTime,
	     VTY_NEWLINE);

  if (zif->rtadv.AdvManagedFlag)
    vty_out (vty, " ipv6 nd managed-config-flag%s", VTY_NEWLINE);

  if (zif->rtadv.AdvOtherConfigFlag)
    vty_out (vty, " ipv6 nd other-config-flag%s", VTY_NEWLINE);

  for (node = listhead(zif->rtadv.AdvPrefixList); node; nextnode (node))
    {
      rprefix = getdata (node);
      if (connected_check_ipv6(ifp, rprefix))
	      vty_out (vty, " ipv6 nd prefix-advertisement");
      else
	      vty_out (vty, " ipv6 nd prefix-advertisement %s/%d %d %d",
		  inet_ntop (AF_INET6, &rprefix->prefix.u.prefix6, 
		      buf, INET6_ADDRSTRLEN),
		  rprefix->prefix.prefixlen,
		  rprefix->AdvValidLifetime,
		  rprefix->AdvPreferredLifetime);
      if (rprefix->AdvOnLinkFlag)
	vty_out (vty, " onlink");
      if (rprefix->AdvAutonomousFlag)
	vty_out (vty, " autoconfig");
      vty_out (vty, "%s", VTY_NEWLINE);
    }

  mndp_config_if_write (vty, ifp);

}

void
rtadv_event (enum rtadv_event event, int val)
{
  switch (event)
    {
    case RTADV_START:
      if (! rtadv->ra_read)
	rtadv->ra_read = thread_add_read (master, rtadv_read, NULL, val);
      if (! rtadv->ra_timer)
	rtadv->ra_timer = thread_add_event (master, rtadv_timer, NULL, 0);
      break;
    case RTADV_STOP:
      if (rtadv->ra_timer)
	{
	  thread_cancel (rtadv->ra_timer);
	  rtadv->ra_timer = NULL;
	}
      if (rtadv->ra_read)
	{
	  thread_cancel (rtadv->ra_read);
	  rtadv->ra_read = NULL;
	}
      break;
    case RTADV_TIMER:
      if (! rtadv->ra_timer)
	rtadv->ra_timer = thread_add_timer (master, rtadv_timer, NULL, val);
      break;
    case RTADV_READ:
      if (! rtadv->ra_read)
	rtadv->ra_read = thread_add_read (master, rtadv_read, NULL, val);
      break;
    default:
      break;
    }
  return;
}

void
rtadv_init ()
{
  int sock;

  sock = rtadv_make_socket ();
  if (sock < 0)
    return;

  rtadv = rtadv_new ();
  rtadv->sock = sock;

  install_element (INTERFACE_NODE, &ipv6_nd_suppress_ra_cmd);
  install_element (INTERFACE_NODE, &no_ipv6_nd_suppress_ra_cmd);
  install_element (INTERFACE_NODE, &ipv6_nd_send_ra_cmd);
  install_element (INTERFACE_NODE, &no_ipv6_nd_send_ra_cmd);
  install_element (INTERFACE_NODE, &ipv6_nd_ra_interval_cmd);
  install_element (INTERFACE_NODE, &no_ipv6_nd_ra_interval_cmd);
  install_element (INTERFACE_NODE, &ipv6_nd_ra_lifetime_cmd);
  install_element (INTERFACE_NODE, &no_ipv6_nd_ra_lifetime_cmd);
  install_element (INTERFACE_NODE, &ipv6_nd_reachable_time_cmd);
  install_element (INTERFACE_NODE, &no_ipv6_nd_reachable_time_cmd);
  install_element (INTERFACE_NODE, &ipv6_nd_managed_config_flag_cmd);
  install_element (INTERFACE_NODE, &no_ipv6_nd_managed_config_flag_cmd);
  install_element (INTERFACE_NODE, &ipv6_nd_other_config_flag_cmd);
  install_element (INTERFACE_NODE, &no_ipv6_nd_other_config_flag_cmd);
  install_element (INTERFACE_NODE, &ipv6_nd_homeagent_config_flag_cmd);
  install_element (INTERFACE_NODE, &no_ipv6_nd_homeagent_config_flag_cmd);
  install_element (INTERFACE_NODE, &ipv6_nd_homeagent_preference_cmd);
  install_element (INTERFACE_NODE, &no_ipv6_nd_homeagent_preference_cmd);
  install_element (INTERFACE_NODE, &ipv6_nd_homeagent_lifetime_cmd);
  install_element (INTERFACE_NODE, &no_ipv6_nd_homeagent_lifetime_cmd);
  install_element (INTERFACE_NODE, &ipv6_nd_prefix_advertisement_cmd);
  install_element (INTERFACE_NODE, &ipv6_nd_prefix_advertisement_no_val_cmd);
  install_element (INTERFACE_NODE, &no_ipv6_nd_prefix_advertisement_cmd);
  install_element (INTERFACE_NODE, &ipv6_nd_prefix_advertisement_default_cmd);
  install_element (INTERFACE_NODE, &no_ipv6_nd_prefix_advertisement_default_cmd);

}

int
if_join_all_router (int sock, struct interface *ifp)
{
  int ret;

  struct ipv6_mreq mreq;

  memset (&mreq, 0, sizeof (struct ipv6_mreq));
  inet_pton (AF_INET6, ALLROUTER, &mreq.ipv6mr_multiaddr);
  mreq.ipv6mr_interface = ifp->ifindex;

  ret = setsockopt (sock, IPPROTO_IPV6, IPV6_JOIN_GROUP, 
		    (char *) &mreq, sizeof mreq);
  if (ret < 0)
    zlog_warn ("can't setsockopt IPV6_JOIN_GROUP: %s", strerror (errno));

  if(IS_ZEBRA_DEBUG_EVENT)
	  zlog_info ("rtadv: %s join to all-routers multicast group", ifp->name);

  return 0;
}

int
if_leave_all_router (int sock, struct interface *ifp)
{
  int ret;

  struct ipv6_mreq mreq;

  memset (&mreq, 0, sizeof (struct ipv6_mreq));
  inet_pton (AF_INET6, ALLROUTER, &mreq.ipv6mr_multiaddr);
  mreq.ipv6mr_interface = ifp->ifindex;

  ret = setsockopt (sock, IPPROTO_IPV6, IPV6_LEAVE_GROUP, 
		    (char *) &mreq, sizeof mreq);
  if (ret < 0)
    zlog_warn ("can't setsockopt IPV6_LEAVE_GROUP: %s", strerror (errno));

  zlog_info ("rtadv: %s leave from all-routers multicast group", ifp->name);

  return 0;
}

#else
void
rtadv_init ()
{
  /* Empty.*/;
}
#endif /* RTADV && HAVE_IPV6 */

/* Local Variables: */
/* c-basic-offset: 2 */
/* c-indent-level: 2 */
/* indent-tabs-mode: t */
/* tab-width: 2 */
/* end: */
