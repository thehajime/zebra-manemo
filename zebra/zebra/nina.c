/* 
 * Network In Node Advertisement
 *
 * draft-thubert-nina-02
 *
 * $Id: nina.c,v c02b24ba03e6 2008/08/03 11:11:33 tazaki $
 *
 * Copyright (c) 2008 {TBD}
 *
 * Author: Hajime TAZAKI  (tazaki@sfc.wide.ad.jp)
 *
 */

#include <zebra.h>

#include "thread.h"
#include "memory.h"
#include "linklist.h"
#include "sockopt.h"
#include "log.h"
#include "command.h"
#include "vty.h"
#include "if.h"
#include "prefix.h"
#include "table.h"

#include "interface.h"
#include "debug.h"
#include "rib.h"
#include "bfd.h"
#include "td.h"
#include "td_neighbor.h"
#include "nina.h"

extern struct thread_master *master;
extern struct td_master *td;
struct nina *nina_top = NULL;


#define NINA_MSG_SIZE 1024
#define min(a, b) ((a) < (b) ? (a) : (b))

int nina_nino_expire(struct thread *);

static char *nina_state_string[] = 
	{
		"NINO_ELAPSED",
		"NINO_PENDING",
		"NINO_CONFIRMED",
	};

struct nina_neighbor *
nina_neighbor_lookup(struct sockaddr_in6 *addr, int ifindex)
{
	struct nina_neighbor *nbr = NULL, *tmp;
	struct listnode *node;

	if(!listhead(nina_top->nbrs))
		return NULL;

	for(node = listhead(nina_top->nbrs); node; nextnode(node)) {
		tmp = getdata(node);
		if(memcmp(&(addr->sin6_addr), &(tmp->ip6.u.prefix6), 
			sizeof(struct in6_addr)) == 0)
		{
			nbr = tmp;
			break;
		}
	}

	return nbr;
}

struct nina_neighbor *
nina_neighbor_new(struct sockaddr_in6 *addr, int ifindex)
{
	struct nina_neighbor *nbr;
	struct bfd_peer peer;

	nbr = XCALLOC(MTYPE_NINA_NBR, sizeof(struct nina_neighbor));
	if(!nbr)
		return NULL;

	nbr->ifp = if_lookup_by_index (ifindex);
	nbr->ip6.family = AF_INET6;
	nbr->ip6.prefixlen = 128;
	memcpy(&nbr->ip6.u.prefix6, &addr->sin6_addr, sizeof(struct in6_addr));

	listnode_add(nina_top->nbrs, nbr);

	/* Add BFD neighbor */
	memset (&peer, 0, sizeof (struct bfd_peer));
	memcpy (&peer.su.sin6.sin6_addr, &nbr->ip6.u.prefix6,
	    sizeof(nbr->ip6.u.prefix6));
	peer.su.sin6.sin6_family = AF_INET6;
#ifdef HAVE_SIN_LEN
	peer.su.sin6.sin6_len = sizeof(struct sockaddr_in6);
#endif
	peer.ifindex = nbr->ifp->ifindex;
	peer.type = BFD_PEER_SINGLE_HOP;
	kernel_bfd_add_peer (&peer, ZEBRA_ROUTE_MNDP);

	return nbr;
}

void
nina_neighbor_free(struct nina_neighbor *nbr)
{
	struct bfd_peer peer;

	/* Delete BFD neighbor */
	memset (&peer, 0, sizeof (struct bfd_peer));
	memcpy (&peer.su, &nbr->ip6.u.prefix6, sizeof(nbr->ip6.u.prefix6));
	peer.ifindex = nbr->ifp->ifindex;
	peer.type = BFD_PEER_SINGLE_HOP;
	kernel_bfd_delete_peer (&peer, ZEBRA_ROUTE_MNDP);

	listnode_delete(nina_top->nbrs, nbr);
	XFREE(MTYPE_NINA_NBR, nbr);
	return ;
}

int
nina_na_timeout(struct thread *thread)
{
	struct nina_neighbor *nbr;

	nbr = thread->arg;
	nbr->t_expire = NULL;
	nina_neighbor_free(nbr);

	return 0;
}



/* Send neighbor advertisement packet. */
void
nina_send_packet(int sock, struct interface *ifp, 
    const struct in6_addr *to, struct nina_entry *nina)
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
	unsigned char buf[NINA_MSG_SIZE];
	struct nd_neighbor_advert *na;
	struct nd_opt_network_in_node *nino;
	int ret;
	int len = 0;
	struct listnode *node;
	char abuf[INET6_ADDRSTRLEN];

	/* Logging of packet. */
	if (IS_ZEBRA_DEBUG_PACKET)
		zlog_info ("Neighbor advertisement send to %s", 
		    inet_ntop(AF_INET6, to, abuf, sizeof(abuf)));

	/* Fill in sockaddr_in6. */
	memset (&addr, 0, sizeof (struct sockaddr_in6));
	addr.sin6_family = AF_INET6;
#ifdef SIN6_LEN
	addr.sin6_len = sizeof (struct sockaddr_in6);
#endif /* SIN6_LEN */
	addr.sin6_port = htons (IPPROTO_ICMPV6);
	memcpy (&addr.sin6_addr, to, sizeof (struct in6_addr));

	/* Make neighbor advertisement message. */
	na = (struct nd_neighbor_advert *) buf;

	na->nd_na_type = ND_NEIGHBOR_ADVERT;
	na->nd_na_code = 0;
	na->nd_na_cksum = 0;
	na->nd_na_flags_reserved = 
	    ND_NA_FLAG_ROUTER|ND_NA_FLAG_SOLICITED|ND_NA_FLAG_OVERRIDE;

	/* Link-Local addr for Target addres */
	for (node = listhead(ifp->connected); node; nextnode(node)) {
		struct connected *c;
		c = (struct connected *) getdata(node);
		if (c->address->family != AF_INET6)
			continue;

		/* linklocal scope check */
		if (IN6_IS_ADDR_LINKLOCAL (&c->address->u.prefix6)) {
			memcpy(&na->nd_na_target, &c->address->u.prefix6, 
			    sizeof(struct in6_addr));
			break;
		}
	}

	len = sizeof(struct nd_neighbor_advert);

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

	/* encode network in node advertisement option */
	nino = (struct nd_opt_network_in_node *)((char *)na + len);
	memset(nino, 0, sizeof(struct nd_opt_network_in_node));
	nino->type = ND_OPT_NA_NINO;
	nino->length = (sizeof(struct nd_opt_network_in_node) + 
	    (nina->rn->p.prefixlen / 8)) >> 3;
	nino->prefixlen = nina->rn->p.prefixlen;
	nino->lifetime = htonl(nina->lifetime);
	nino->depth = nina->depth + 1;
	nino->seq = nina->seq;
	memcpy(nino->prefix, &nina->rn->p.u.prefix6, nina->rn->p.prefixlen / 8);

	len += (nino->length * 8);

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
	memset (&pkt->ipi6_addr, 0, sizeof (struct in6_addr));
	pkt->ipi6_ifindex = ifp->ifindex;

	ret = sendmsg (sock, &msg, 0);
	if(ret < 0)
	{
		nina_top->na_error++;
		zlog_warn("sendmsg(send_ra) err on %s(%s)", 
		    inet_ntop(AF_INET6, to, abuf, sizeof(abuf)),
		    strerror(errno));
		return;
	}

	nina_top->na_send++;
	nina_top->na_nina_recv++;

	if(IS_ZEBRA_DEBUG_PACKET)
	{
		zlog_info("NA: %s: SEND(%llu):NINO ifindex=%d", 
		    inet_ntop(AF_INET6, to, abuf, sizeof(abuf)),
		    nina_top->na_send, ifp->ifindex);

		/* Packet dump */
		zlog_dump(buf, ret);
	}

	return;
}

int
nina_delay_na_timer(struct thread *thread)
{
	struct td_neighbor *td_nbr;
	struct nina_entry *nina;
	struct route_node *rn, *next;

	td_nbr = THREAD_ARG(thread); 
	if(!td_nbr)
		return 0;

	if(!td_nbr->tio)
		return 0;

	if(nina_top) {
		nina_top->t_delay = NULL;

		/* connected list */
		for(rn = route_top(nina_top->connected); rn; rn = route_next (rn)) {
			if((nina = rn->info) != NULL) {
				nina_send_packet(nina_top->sock, td_nbr->ifp, 
				    &td_nbr->saddr.sin6_addr, nina);
				nina->reported = 1;
			}
		}

		/* reachable list */
		for(rn = route_top(nina_top->reachable); rn; rn = route_next (rn)) {
			if((nina = rn->info) != NULL) {
				nina_send_packet(nina_top->sock, td_nbr->ifp, 
				    &td_nbr->saddr.sin6_addr, nina);
				nina->reported = 1;
			}
		}

		/* unreachable list */
		for(rn = route_top(nina_top->unreachable); rn; rn = next) {
			next = route_next (rn);
			if((nina = rn->info) != NULL) {
				/* Set to no-NINO */
				nina->lifetime = 0;
				nina_send_packet(nina_top->sock, td_nbr->ifp, 
				    &td_nbr->saddr.sin6_addr, nina);
				route_unlock_node(rn);
			}
		}
	}

	return 0;
}

int
nina_destroy_timer(struct thread *thread)
{
	struct nina_entry *nina;
	struct route_node *rn;


	if(nina_top) {
		/* reachable list */
		for(rn = route_top(nina_top->reachable); rn; rn = route_next (rn)) {
			if((nina = rn->info) != NULL) {
				if(nina->state == NINO_ELAPSED){
					thread_cancel(nina->t_expire);
					/* move to unreachable list immediately */
					nina->t_expire = thread_add_timer(master, 
					    nina_nino_expire, nina, 1);
				}
			}
		}
	}
	return 0;
}

/*
 * draft-thubert-nina Sec 7.2
 * When the MR sends a RA-TIO over an ingress interface, for all entries
 * on that interface:
 *
 * o  If the entry is CONFIRMED, it goes PENDING with the retry count
 *    set to 0.
 *
 * o  If the entry is PENDING, the retry count is incremented.  If it
 *    reaches a maximum threshold, the entry goes ELAPSED If at least
 *    one entry is ELAPSED at the end of the process: if the Destroy
 *    timer is not running then it is armed with a jitter.
 */
void
nina_send_ratio(struct interface *ifp)
{
	struct nina_entry *nina;
	struct route_node *rn;
	struct zebra_if *zif;

	if(nina_top) {
		zif = ifp->info;

		/* reachable list */
		for(rn = route_top(nina_top->reachable); rn; rn = route_next (rn)) {
			if((nina = rn->info) != NULL) {
				if(nina->state == NINO_CONFIRMED){
					nina->state = NINO_PENDING;
					nina->retries = 0;
				}
				else if(nina->state == NINO_PENDING){
					nina->retries++;
					if(nina->retries > NINA_RETRY_THRESHOLD){
						nina->state = NINO_ELAPSED;
						if(!nina_top->t_destroy){
							nina_top->t_destroy = thread_add_timer(master, 
							    nina_destroy_timer, NULL,
							    min(NINA_MAX_DESTROY_INTERVAL, 
								zif->rtadv.MaxRtrAdvInterval)/1000);
						}
					}
				}
			}
		}
	}

	return;
}

void
nina_process_solicit (struct interface *ifp, struct sockaddr_in6 *from)
{
	if (IS_ZEBRA_DEBUG_PACKET)
		zlog_info ("Neighbor solicitation received on %s", ifp->name);

	/* Nothing to do */
	return;
}

static int
nina_seq_greater(u_int16_t seq1, u_int16_t seq2)
{
  int16_t *comp_seq1 = (int16_t *)&seq1;
  int16_t *comp_seq2 = (int16_t *)&seq2;
  
  if((*comp_seq1 - *comp_seq2) < 0)
    return 0;
  else
    return 1;
}

int
nina_nino_expire(struct thread *thread)
{
	struct nina_entry *nina;
	struct route_node *rn;
	struct prefix p;
	int ret;

	nina = thread->arg;
	nina->t_expire = NULL;

	prefix_copy(&p, &nina->rn->p);
	/* Delete from reachable list */
	nina->rn->info = NULL;
	route_unlock_node(nina->rn);
	route_unlock_node(nina->rn);

	/* Delete from Rib */
	ret = rib_delete_ipv6(ZEBRA_ROUTE_MNDP, 0, (struct prefix_ipv6 *)&p,
	    &nina->nbr->ip6.u.prefix6,
	    nina->nbr->ifp->ifindex, 0);
	if(ret != 0) {
		zlog_warn("NINA: delete route failure: on ifindex %d (%s)",
		    nina->nbr->ifp->ifindex, strerror(errno));
	}

	if(nina->reported) {
		/* Regist into unreachable list */
		rn = route_node_get(nina_top->unreachable, &p);
		if(rn && rn->info) {
			zlog_warn("NINA: already registered in Unreachable list");
			return 0;
		}

		if(rn) {
			rn->info = nina;
			nina->rn = rn;
		}
	}
	else {
		XFREE(MTYPE_NINA_ENTRY, nina);
	}

	return 0;
}

static void
nina_process_nino(struct nina_neighbor *nbr, struct nd_opt_network_in_node *nino)
{
	struct nina_entry *reach;
	struct prefix p;
	struct route_node *rn;
	char abuf[INET6_ADDRSTRLEN];
	int ret;

	/* check pkt format */

	memset(&p, 0, sizeof(p));
	p.family = AF_INET6;
	p.prefixlen = nino->prefixlen;
	memcpy(&p.u.prefix6, &nino->prefix, nino->prefixlen / 8);

	/* parse reachable list */
	rn = route_node_get(nina_top->reachable, &p);
	if(!rn)
		return;

	if(rn->info) {
		reach = rn->info;
		route_unlock_node(rn);
		/* Sequence number is increased */
		if((nbr == reach->nbr) && 
		    (nina_seq_greater(nino->seq, reach->seq))) {
			/* no-NINO processing */
			if(nino->lifetime == 0) {
				thread_cancel(reach->t_expire);
				/* move to unreachable list immediately */
				reach->t_expire = thread_add_timer(master, 
				    nina_nino_expire, reach, 1);
				goto end;
			}

			/* Update information */
			reach->state = NINO_CONFIRMED;
			reach->reported = 0;
			reach->retries = 0;
			reach->depth = nino->depth;
			reach->seq = nino->seq;
			reach->lifetime = ntohl(nino->lifetime);
			thread_cancel(reach->t_expire);
			reach->t_expire = thread_add_timer(master, 
			    nina_nino_expire, reach, reach->lifetime);

			if(!nina_top->t_delay) {
				nina_top->t_delay = thread_add_timer(master, 
				    nina_delay_na_timer, td->attach_rtr,
				    (NINA_DEF_NA_LATENCY/(2 * td->tio.depth))/1000);
			}
		}
	}
	else {
		reach = XCALLOC(MTYPE_NINA_ENTRY, sizeof(struct nina_entry));
		reach->state = NINO_CONFIRMED;
		reach->depth = nino->depth;
		reach->seq = nino->seq;
		reach->nbr = nbr;
		reach->lifetime = ntohl(nino->lifetime);
		reach->top = nina_top;
		reach->t_expire = thread_add_timer(master, 
		    nina_nino_expire, reach, reach->lifetime);

		reach->rn = rn;
		rn->info = reach;

		if(!nina_top->t_delay) {
			nina_top->t_delay = thread_add_timer(master, 
			    nina_delay_na_timer, td->attach_rtr,
			    (NINA_DEF_NA_LATENCY/(2 * td->tio.depth))/1000);
		}

		/* Add RIB */
		ret = rib_add_ipv6(ZEBRA_ROUTE_MNDP, 0,
		    (struct prefix_ipv6 *)&rn->p, &nbr->ip6.u.prefix6, 
		    nbr->ifp->ifindex, 0);
		if(ret != 0) {
			zlog_warn("NINA: add route failure: on ifindex %d (%s)",
			    nbr->ifp->ifindex, strerror(errno));
		}

		zlog_info("NINO: regist new prefix %s/%d on reachable list", 
		    inet_ntop(AF_INET6, &rn->p.u.prefix6, abuf, INET6_ADDRSTRLEN),
		    rn->p.prefixlen);
	}

end:
	return;
}

void
nina_process_advert (struct interface *ifp, struct sockaddr_in6 *from,
    struct nd_neighbor_advert *nina, int len)
{
	struct nd_opt_hdr *opt;
	struct nina_neighbor *nbr;
	struct nd_opt_network_in_node *nino = NULL;
	char abuf[INET6_ADDRSTRLEN];

	if (IS_ZEBRA_DEBUG_PACKET)
		zlog_info ("Neighbor advertisement received on %s", ifp->name);

	/* Option parsing */
	opt = (struct nd_opt_hdr *)++nina;
	len -= sizeof(struct nd_neighbor_advert);

	while(len>0)
	{
		switch(opt->nd_opt_type)
		{
		case ND_OPT_SOURCE_LINKADDR:
		case ND_OPT_TARGET_LINKADDR:
		case ND_OPT_REDIRECTED_HEADER:
		case ND_OPT_MTU:
		case ND_OPT_PREFIX_INFORMATION:
		case ND_OPT_RA_TIO:
			break;
		case ND_OPT_NA_NINO:
			nino = (struct nd_opt_network_in_node *)opt;
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

	if(nino) {
		if (IS_ZEBRA_DEBUG_PACKET)
			zlog_info ("NA include NINO option from %s", 
			    inet_ntop(AF_INET6, &from->sin6_addr, abuf, INET6_ADDRSTRLEN));

		nbr = nina_neighbor_lookup(from, ifp->ifindex);
		if(nbr) {
			if(nbr->t_expire)
			{
				thread_cancel(nbr->t_expire);
				nbr->t_expire = NULL;
			}
		}
		else {
			nbr = nina_neighbor_new(from, ifp->ifindex);
			if(!nbr)
				return;
		}

		/* regist expire timer */
		nbr->t_expire = thread_add_timer(master, nina_na_timeout, nbr, 
		    NINA_DEFAULT_NA_LIFETIME/1000);

		nina_top->na_nina_recv++;

		/* Parse NINO payload */
		nina_process_nino(nbr, nino);
	}

	return;
}

void
nina_process_packet (u_char *buf, int len, struct sockaddr_in6 *from,
    unsigned int ifindex, int hoplimit)
{
	struct icmp6_hdr *icmph;
	struct interface *ifp;
	struct zebra_if *zif;

	/* Interface search. */
	ifp = if_lookup_by_index (ifindex);
	if (ifp == NULL)
	{
		zlog_warn ("Unknown interface index: %d", ifindex);
		return;
	}

	if (if_is_loopback (ifp))
		return;

	/* Check interface configuration. */
	zif = ifp->info;
	if (!CHECK_FLAG(zif->mndp.flags, MNDP_INGRESS_FLAG))
		return;

	/* ICMP message length check. */
	if (len < sizeof (struct icmp6_hdr))
	{
		zlog_warn ("Invalid ICMPV6 packet length: %d", len);
		return;
	}

	icmph = (struct icmp6_hdr *) buf;

	/* ICMP message type check. */
	if (icmph->icmp6_type != ND_NEIGHBOR_SOLICIT &&
	    icmph->icmp6_type != ND_NEIGHBOR_ADVERT)
	{
		zlog_warn ("Unwanted ICMPV6 message type: %d", icmph->icmp6_type);
		return;
	}

	/* Hoplimit check. */
	if (hoplimit >= 0 && hoplimit != 255)
	{
		nina_top->na_error++;
		zlog_warn ("Invalid hoplimit %d for neighbor advertisement ICMP packet",
		    hoplimit);
		return;
	}

	/* Check ICMP message type. */
	switch(icmph->icmp6_type)
	{
	case ND_NEIGHBOR_SOLICIT:
		nina_process_solicit (ifp, from);
		nina_top->ns_recv++;
		break;
	case ND_NEIGHBOR_ADVERT:
		/* process NA packet */
		nina_process_advert (ifp, from, (struct nd_neighbor_advert *)buf, len);
		nina_top->na_recv++;
		break;
	default:
		break;
	}

	return;
}

/* Packet Receive Process */
int
nina_read(struct thread *thread)
{
	int sock;
	int ret;
	struct msghdr msg;
	struct iovec iov;
	struct cmsghdr  *cmsgptr;
	struct in6_addr dst;
	char adata[1024];
	struct sockaddr_in6 from;
	char abuf[INET6_ADDRSTRLEN];
	u_char buf[NINA_MSG_SIZE];
	unsigned int ifindex = 0;
	int hoplimit = -1;

	sock = THREAD_FD(thread); 
	nina_top->t_read = NULL;

	/* Fill in message and iovec. */
	msg.msg_name = (void *) &from;
	msg.msg_namelen = sizeof (struct sockaddr_in6);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = (void *) adata;
	msg.msg_controllen = sizeof adata;
	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);

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
			ifindex = ptr->ipi6_ifindex;
			memcpy(&dst, &ptr->ipi6_addr, sizeof(ptr->ipi6_addr));
		}

		/* Incoming packet's hop limit. */
		if (cmsgptr->cmsg_level == IPPROTO_IPV6 &&
		    cmsgptr->cmsg_type == IPV6_HOPLIMIT)
			hoplimit = *((int *) CMSG_DATA (cmsgptr));
	}

	if(IS_ZEBRA_DEBUG_PACKET)
		zlog_info("NA: recv_packet: %s idx=%d, hl=%d",
		    inet_ntop(AF_INET6, &from.sin6_addr, abuf, INET6_ADDRSTRLEN), 
		    ifindex, hoplimit);

	/* Process packet... */
	nina_process_packet(buf, ret, &from, ifindex, hoplimit);

	nina_top->t_read = thread_add_read(master, nina_read, NULL, sock);
	return 0;
};





int
nina_make_socket(void)
{
	int sock;
	int ret;
	struct icmp6_filter filter;

	sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
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
	ICMP6_FILTER_SETPASS (ND_NEIGHBOR_SOLICIT, &filter);
	ICMP6_FILTER_SETPASS (ND_NEIGHBOR_ADVERT, &filter);

	ret = setsockopt (sock, IPPROTO_ICMPV6, ICMP6_FILTER, &filter,
	    sizeof (struct icmp6_filter));
	if (ret < 0)
	{
		zlog_info ("NINA:ICMP6_FILTER set fail: %s", strerror (errno));
		return ret;
	}

	return sock;
}

struct nina *
nina_create()
{
	struct listnode *node, *node2;
	struct interface *ifp;
	struct connected *c;
	struct nina_entry *nina;
	struct route_node *rn;

	nina_top = XCALLOC(MTYPE_NINA, sizeof(struct nina));
	if(!nina_top)
		return NULL;

	/* create socket fore receive */
	nina_top->sock = nina_make_socket();
	if(nina_top->sock < 0){
		XFREE(MTYPE_NINA, nina_top);
		return NULL;
	}

	nina_top->nbrs = list_new();
	nina_top->connected = route_table_init();
	nina_top->reachable = route_table_init();
	nina_top->unreachable = route_table_init();

	/* make connected list from MNP */
	for(node = listhead(iflist); node; nextnode(node)){
		struct zebra_if *zif;

		ifp = getdata(node);
		zif = ifp->info;

		if(if_is_loopback(ifp))
			continue;

		if (!CHECK_FLAG(zif->mndp.flags, MNDP_INGRESS_FLAG))
			continue;


		for (node2 = listhead(ifp->connected); node2; nextnode(node2)) {
			c = (struct connected *) getdata(node2);
			if (c->address->family != AF_INET6)
				continue;

			/* linklocal scope check */
			if (IN6_IS_ADDR_LINKLOCAL (&c->address->u.prefix6))
				continue;

			nina = XCALLOC(MTYPE_NINA_ENTRY, sizeof(struct nina_entry));
			if(!nina)
				continue;

			rn = route_node_get(nina_top->connected, c->address);
			if(!rn)
				continue;

			nina->state = NINO_CONFIRMED;
			nina->depth = 0;
			nina->seq = 0;
			nina->lifetime = NINA_DEFAULT_NA_LIFETIME;
			nina->nbr = NULL; /* NULL means selt */
			nina->top = nina_top;
			nina->ifp = ifp;

			nina->rn = rn;
			rn->info = nina;
		}
	}


	nina_top->t_read = thread_add_read(master, nina_read, NULL, nina_top->sock);

	return nina_top;
}

void
nina_stop()
{
	struct route_node *rn;
	struct nina_entry *nina;

	if(!nina_top)
		return;

	thread_cancel(nina_top->t_read);

	list_delete(nina_top->nbrs);


	for(rn = route_top(nina_top->connected); rn; rn = route_next (rn)) {
		if((nina = rn->info) != NULL) {
			rn->info = NULL;
			route_unlock_node(rn);
			XFREE(MTYPE_NINA_ENTRY, nina);
		}
	}

	for(rn = route_top(nina_top->reachable); rn; rn = route_next (rn)) {
		if((nina = rn->info) != NULL) {
			rn->info = NULL;
			route_unlock_node(rn);
			XFREE(MTYPE_NINA_ENTRY, nina);
		}
	}

	for(rn = route_top(nina_top->unreachable); rn; rn = route_next (rn)) {
		if((nina = rn->info) != NULL) {
			rn->info = NULL;
			route_unlock_node(rn);
			XFREE(MTYPE_NINA_ENTRY, nina);
		}
	}

	route_table_finish(nina_top->connected);
	route_table_finish(nina_top->reachable);
	route_table_finish(nina_top->unreachable);

	close(nina_top->sock);

	XFREE(MTYPE_NINA, nina_top);
	return;
}


DEFUN (ipv6_nd_nina_enable,
    ipv6_nd_nina_enable_cmd,
    "ipv6 nd nina enable",
    IPV6_STR
    "Neighbor discovery\n"
    "NINA(Network In Node Advertisement)\n"
    "Use NINA\n")
{
	if(!nina_create()){
		zlog_warn("Failure in starting NINA");
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN (no_ipv6_nd_nina_enable,
    no_ipv6_nd_nina_enable_cmd,
    "no ipv6 nd nina",
    NO_STR
    IPV6_STR
    "Neighbor discovery\n"
    "NINA(Network In Node Advertisement)\n")
{
	if(!nina_top){
		vty_out(vty, "There is no NINA process%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	nina_stop();
	return CMD_SUCCESS;
}

static void
nina_show_uptime(struct vty *vty, struct nina_entry *nina)
{
  struct timeval timer_now;
  time_t clock;
  struct tm *tm;
#define TIME_BUF 25
  char timebuf [TIME_BUF];
  struct thread *thread;

  gettimeofday (&timer_now, NULL);

  if ((thread = nina->t_expire) != NULL)
    {
      clock = thread->u.sands.tv_sec - timer_now.tv_sec;
      tm = gmtime (&clock);
      strftime (timebuf, TIME_BUF, "(%M:%S)", tm);
      vty_out (vty, "%s", timebuf);
    }

  return;
}

void
nina_show_entry_list_vty(struct vty *vty, struct route_table *table)
{
	struct route_node *rn;
	struct nina_entry *nina;
	char abuf[INET6_ADDRSTRLEN];
	char abuf2[INET6_ADDRSTRLEN];

	for(rn = route_top(table); rn; rn = route_next (rn)) {
		if((nina = rn->info) != NULL) {
			vty_out(vty, " %s/%d via %s %s  depth %d seq %d state %s ", 
			    inet_ntop(AF_INET6, &rn->p.u.prefix6, abuf, INET6_ADDRSTRLEN),
			    rn->p.prefixlen, 
			    nina->nbr ? 
			    inet_ntop(AF_INET6, &nina->nbr->ip6.u.prefix6,
				abuf2, INET6_ADDRSTRLEN) : "self",
			    VTY_NEWLINE,
			    nina->depth, nina->seq, nina_state_string[nina->state]);
			nina_show_uptime(vty, nina);
			vty_out(vty, "%s", VTY_NEWLINE);
		}
	}

	return ;
}

DEFUN (show_ipv6_nd_nina,
    show_ipv6_nd_nina_cmd,
    "show ipv6 nd nina",
    SHOW_STR
    IPV6_STR
    "Neighbor discovery\n"
    "NINA(Network In Node Advertisement)\n")
{

	if(!nina_top){
		vty_out(vty, "No NINA process%s", VTY_NEWLINE);
		return CMD_SUCCESS;
	}

	vty_out(vty, "NINA is running...%s", VTY_NEWLINE);

	vty_out(vty, "Connected List %s", VTY_NEWLINE);
	nina_show_entry_list_vty(vty, nina_top->connected);
	vty_out(vty, "%sReachable List %s", VTY_NEWLINE, VTY_NEWLINE);
	nina_show_entry_list_vty(vty, nina_top->reachable);
	vty_out(vty, "%sUnreachable List %s", VTY_NEWLINE, VTY_NEWLINE);
	nina_show_entry_list_vty(vty, nina_top->unreachable);

	return CMD_SUCCESS;
}


int
nina_init()
{

	/* Install command */
	install_element(CONFIG_NODE, &ipv6_nd_nina_enable_cmd);
	install_element(CONFIG_NODE, &no_ipv6_nd_nina_enable_cmd);
	install_element(ENABLE_NODE, &show_ipv6_nd_nina_cmd);
	install_element(VIEW_NODE, &show_ipv6_nd_nina_cmd);

	return 0;
}

int nina_terminate()
{
	return 0;
}
