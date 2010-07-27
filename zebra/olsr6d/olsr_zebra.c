/*
 * OLSR_Zebra.c
 */

#include <zebra.h>

#include <sys/types.h>
#include <netinet/in.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <thread.h>
#include <if.h>
#include <prefix.h>
#include <zclient.h>
#include <linklist.h>

#include "log.h"
#include "olsr_common.h"
#include "olsr_node.h"
#include "olsr_packet.h"

int mainaddr_set = 0;


#define OLSR_ROUTE_ADD		0
#define OLSR_ROUTE_DELETE	1

void
olsr_zebra_route_update (int type, struct olsr_routing_entry *re)
{
  int retval;
  u_int *ifindexes;
  struct in6_addr *nexthops;
  struct in6_addr null_addr;
  struct zapi_ipv6 api;
  struct prefix_ipv6 dst;
  struct olsr_interface_tuple *it;

  if (re == NULL)
    return;

  /* if (re->R_dist == 1) */
  if ( IN6_IS_ADDR_LINKLOCAL(&re->R_dest_addr) )
    return;

  it = olsr_interface_lookup_by_addr (olsr.interface_set, re->R_iface_addr);
  if ((it == NULL) || ! (it->status & ACTIVE) || !it->optset)
    return;

  if (!(nexthops = (struct in6_addr *) malloc (sizeof (struct in6_addr))))
    {
      perror ("zebra_route_update: malloc");
      return;
    }

  if (!(ifindexes = (u_int *) malloc (sizeof (u_int))))
    {
      perror ("zebra_route_update: malloc");
      return;
    }

  *nexthops = re->R_next_addr;
  *ifindexes = it->ifindex;

  memset (&api, 0, sizeof (api));
  api.type = ZEBRA_ROUTE_OLSR6;
  SET_FLAG (api.message, ZAPI_MESSAGE_NEXTHOP);
  api.nexthop_num = 1;
  api.nexthop = &nexthops;
  SET_FLAG (api.message, ZAPI_MESSAGE_IFINDEX);
  api.ifindex_num = 1;
  api.ifindex = ifindexes;
  SET_FLAG (api.message, ZAPI_MESSAGE_DISTANCE);
  api.distance = re->R_dist;

  memset (&dst, 0, sizeof (dst));
  dst.family = AF_INET6;

  memset (&null_addr, 0, sizeof (null_addr));
  if (re->R_plen || IN6_IS_ADDR_SAME (null_addr, re->R_dest_addr))
    dst.prefixlen = re->R_plen;
  else
    dst.prefixlen = HOSTROUTE_PREFIXLEN;

  dst.prefix = re->R_dest_addr;

  if (type == OLSR_ROUTE_ADD)
    retval = zapi_ipv6_add (zclient, &dst, &api);
  else
    retval = zapi_ipv6_delete (zclient, &dst, &api);

#if 0
zlog_warn ("%s ROUTE: dest=%s via=%s, retval = %d",
	 type == OLSR_ROUTE_ADD ? "ADD" : "DEL", 
           ip6_sprintf (&dst.prefix),
           ip6_sprintf (nexthops), retval
           );
#endif

  free (nexthops);
  free (ifindexes);

  return;
}

int
olsr_zebra_ifaddr_add (int command, struct zclient *zclient,
		       zebra_size_t length)
{
  struct listnode *nanode;
  struct in6_addr null_addr;
  struct connected *c;
  struct olsr_interface_tuple *it;
  struct olsr_ifassoc_tuple new;
  struct olsr_nwassoc_tuple *nat;

  c = zebra_interface_address_add_read (zclient->ibuf);
  if ( c == NULL )
    return 0;

  if ( c->address->family != AF_INET6 )
    return 0;

  if ( IN6_IS_ADDR_LOOPBACK (&c->address->u.prefix6) )
    return 0;

  it = (struct olsr_interface_tuple *) c->ifp->info;
  if (! it)
    return 0;

  if ( IN6_IS_ADDR_LINKLOCAL (&c->address->u.prefix6))
    {
      it->link_local_addr = c->address->u.prefix6;
      return 0;
    }

  if ( ! (it->status & LOCAL_ADDR_SET))
    {
      it->local_iface_addr = c->address->u.prefix6;
      it->status |= LOCAL_ADDR_SET;
    }

  if ( ! IN6_IS_ADDR_SITELOCAL (&c->address->u.prefix6)
        && ! (it->status & GLOBAL_ADDR_SET))
    {
      /* global address */
      it->global_iface_addr = c->address->u.prefix6;
      it->status |= GLOBAL_ADDR_SET;
    }

  if (!mainaddr_set && (it->status & ACTIVE))
    {
      olsr.main_addr = c->address->u.prefix6;
      mainaddr_set++;

zlog_debug ("main addr set as main: %s local: %s", ip6_sprintf (&olsr.main_addr), ip6_sprintf (&it->local_iface_addr));

      memset (&null_addr, 0, sizeof (null_addr));
      for (nanode = listhead (olsr.nw_assoc_set); nanode; nextnode (nanode))
        {
          nat = (struct olsr_nwassoc_tuple *) nanode->data;
          if (IN6_IS_ADDR_SAME (null_addr, nat->A_gateway_addr))
            nat->A_gateway_addr = olsr.main_addr;
        }
    }

  if (!it->optset)
    {
      olsr_interface_setsockopt (olsr_sock, it->ifindex);
      it->optset++;
    }

  if (mainaddr_set && (it->status & ACTIVE)
      && !IN6_IS_ADDR_SAME (olsr.main_addr, c->address->u.prefix6))
    {
      memset (&new, 0, sizeof (new));
      new.I_iface_addr = c->address->u.prefix6;
      new.I_main_addr = olsr.main_addr;
      new.I_time = HOLD_TIME_FOREVER;
      olsr_assoc_set_add (olsr.iface_assoc_set, new);

      {
	zlog_info ("ifaddr_add assoc_create %d main %s I_iface_addr %s\n",
		it->ifindex, ip6_sprintf(&olsr.main_addr), ip6_sprintf(&it->local_iface_addr));
      }

    }

  /* Handle HNA configuration */
  if (c->address->family == AF_INET6 &&
      !IN6_IS_ADDR_LINKLOCAL (&c->address->u.prefix6)){
	  struct olsr_nwassoc_tuple new;
	  struct prefix p;

	  if(it->hna_flag){
		  memset (&new, 0, sizeof(new));
		  new.A_gateway_addr = olsr.main_addr;
		  prefix_copy(&p, c->address);
		  apply_mask(&p);

		  memcpy(&new.A_network_addr, &p.u.prefix, sizeof(struct in6_addr));
		  new.A_plen = p.prefixlen;
		  
		  if (!olsr_nwassoc_set_lookup(olsr.nw_assoc_set, olsr.main_addr, new.A_network_addr, new.A_plen)){
			  new.A_time = HOLD_TIME_FOREVER;
			  olsr_nwassoc_set_add (olsr.nw_assoc_set, new);
		  }
	  }
  }

  return 0;
}

int
olsr_zebra_if_add (int command, struct zclient *zclient, zebra_size_t length)
{
  struct interface *ifp;
  struct olsr_interface_tuple *it;

  ifp = zebra_interface_add_read (zclient->ibuf);
  it = (struct olsr_interface_tuple *) ifp->info;
  if (! it)
    it = olsr_interface_create (ifp);
  it->ifindex = ifp->ifindex;

  return 0;
}

void
olsr_zebra_init ()
{
  zclient = zclient_new ();

  zclient_init (zclient, ZEBRA_ROUTE_OLSR6);
  zclient->interface_add = olsr_zebra_if_add;
  zclient->interface_address_add = olsr_zebra_ifaddr_add;

  zclient_start (zclient);

  return;
}


