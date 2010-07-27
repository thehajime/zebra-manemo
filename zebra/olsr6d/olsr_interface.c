/* 
 * OLSR_Interface.c
 */

#include <zebra.h>

#include "thread.h"
#include "if.h"
#include "linklist.h"
#include "log.h"

#include "olsr_common.h"
#include "olsr_node.h"
#include "olsr_packet.h"


int
olsr_socket ()
{
  int s;
  u_int on = 1;

  struct sockaddr_in6 bind_addr;


  if ((s = socket (AF_INET6, SOCK_DGRAM, 0)) < 0)
    {
      perror ("olsr_socket: socket()");
      exit (-1);
    }

  if (setsockopt (s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof (on)) < 0)
    {
      perror ("olsr_socket: setsockopt(SO_REUSEADDR)");
      exit (-1);
    }

#ifdef IPV6_RECVPKTINFO
  if (setsockopt (s, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof (u_int)) < 0)
    {
      perror ("olsr_socket: setsockopt(IPV6_PKTINFO)");
      exit (-1);
    }
#else
  if (setsockopt (s, IPPROTO_IPV6, IPV6_PKTINFO, &on, sizeof (u_int)) < 0)
    {
      perror ("olsr_socket: setsockopt(IPV6_PKTINFO)");
      exit (-1);
    }
#endif /* IPV6_PKTINFO */


  memset (&bind_addr, 0, sizeof (bind_addr));
#ifdef SIN6_LEN
  bind_addr.sin6_len = sizeof (struct sockaddr_in6);
#endif /* SIN6_LEN */
  bind_addr.sin6_family = AF_INET6;
  bind_addr.sin6_port = htons (OLSR_PORT_NUMBER);
  bind_addr.sin6_addr = in6addr_any;

  if (bind (s, (struct sockaddr *) &bind_addr, sizeof (bind_addr)) != 0)
    {
      perror ("olsr_socket: bind()");
      exit (-1);
    }

  return s;
}

void
olsr_interface_setsockopt (int s, int ifindex)
{
  int multicast_if;
  int hlim = 1;
  struct in6_addr multicast_addr;
  struct ipv6_mreq mreq6;

  memset (&mreq6, 0, sizeof (mreq6));
  inet_pton (AF_INET6, OLSR_MULTICAST_GROUP, &multicast_addr);
  memcpy (&(mreq6.ipv6mr_multiaddr), &multicast_addr,
	  sizeof (struct in6_addr));
  mreq6.ipv6mr_interface = ifindex;

  if (setsockopt (s, IPPROTO_IPV6,
		  IPV6_JOIN_GROUP, &mreq6, sizeof (mreq6)) < 0)
    {
      perror ("olsr_socket: setsockopt(IPV6_JOIN_GROUP)");
      exit (-1);
    }

  if (setsockopt (s, IPPROTO_IPV6,
		  IPV6_MULTICAST_HOPS, (char *) &hlim, sizeof (hlim)) < 0)
    {
      perror ("olsr_socket: setsockopt(IPV6MULTICAST_HOPS)");
      exit (-1);
    }

  multicast_if = ifindex;
  if (setsockopt (s, IPPROTO_IPV6,
		  IPV6_MULTICAST_IF, &multicast_if,
		  sizeof (multicast_if)) < 0)
    {
      perror ("olsr_socket: setsockopt(IPV6_MULTICAST_IF)");
      exit (-1);
    }

  return;
}

struct olsr_interface_tuple *
olsr_interface_lookup_by_addr (struct list *set, struct in6_addr addr)
{
  struct listnode *node;
  struct olsr_interface_tuple *it;


  for (node = listhead (set); node; nextnode (node))
    {
      it = (struct olsr_interface_tuple *) node->data;

      if (! (it->status & ACTIVE))
	continue;

      if (IN6_IS_ADDR_SAME (it->local_iface_addr, addr))
	return it;
    }

  return NULL;
}

struct olsr_interface_tuple *
olsr_interface_lookup_by_ifindex (struct list *set, int index)
{
  struct listnode *node;
  struct olsr_interface_tuple *it;

  for (node = listhead (olsr.interface_set); node; nextnode (node))
    {
      it = (struct olsr_interface_tuple *) node->data;

      if (it->ifindex == index)
	return it;
    }

  return NULL;
}

void
olsr_interface_set_create (struct list **set)
{
  *set = list_new ();
  (*set)->del = free;
  return;
}

struct olsr_interface_tuple *
olsr_interface_create (struct interface *ifp)
{
  struct olsr_interface_tuple *it;

  it = (struct olsr_interface_tuple *)
    malloc (sizeof (struct olsr_interface_tuple));
  memset (it, 0, sizeof (struct olsr_interface_tuple));
  ifp->info = it;
  it->ifp = ifp;
  it->status = 0;
  olsr_mpr_set_create (&it->mpr_set);

  listnode_add (olsr.interface_set, it);

  return it;
}

struct olsr_interface_tuple *
olsr_interface_get_by_name (char *ifname)
{
  struct interface *ifp;
  struct olsr_interface_tuple *it;

  ifp = if_get_by_name (ifname);
  it = (struct olsr_interface_tuple *) ifp->info;
  if (!it)
    it = olsr_interface_create (ifp);
  it->ifindex = ifp->ifindex;
  return it;
}
