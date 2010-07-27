/*
 * OLSR_Link.c
 */

#include <sys/types.h>
#include <netinet/in.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <zebra.h>
#include <linklist.h>
#include <vty.h>
#include <command.h>

#include "olsr_common.h"
#include "olsr_node.h"
#include "olsr_packet.h"



DEFUN (show_ipv6_olsr6_neighbor_link,
       show_ipv6_olsr6_neighbor_link_cmd,
       "show ipv6 olsr6 neighbor link",
       SHOW_STR IP6_STR OLSR6_STR "Link to neighbor\n")
{
  char localaddr[40];
  char neighboraddr[40];
  struct listnode *node;
  struct olsr_link_tuple *lt;

  vty_out (vty, "%-30s %s %s",
	   "Neighbor IF Addr", "Local IF Addr", VTY_NEWLINE);

  for (node = listhead (olsr.link_set); node; nextnode (node))
    {
      lt = (struct olsr_link_tuple *) node->data;

      inet_ntop (AF_INET6, &lt->L_neighbor_iface_addr, neighboraddr,
		 sizeof (neighboraddr));
      inet_ntop (AF_INET6, &lt->L_local_iface_addr, localaddr,
		 sizeof (localaddr));
      vty_out (vty, "%-30s %s %s", neighboraddr, localaddr, VTY_NEWLINE);

    }

  return CMD_SUCCESS;
}

void
olsr_link_install_element ()
{
  install_element (VIEW_NODE, &show_ipv6_olsr6_neighbor_link_cmd);
  install_element (ENABLE_NODE, &show_ipv6_olsr6_neighbor_link_cmd);

  return;
}

void
olsr_link_set_create (struct list **set)
{
  *set = list_new ();
  (*set)->del = free;

  return;
}

struct olsr_link_tuple *
olsr_link_set_add (struct list *set, struct olsr_link_tuple tuple)
{
  struct olsr_link_tuple *new;

  if ((new =
       (struct olsr_link_tuple *) malloc (sizeof (struct olsr_link_tuple))) ==
      NULL)
    {
      perror ("olsr_link_set_add: malloc()");
      return NULL;
    }

  *new = tuple;

#ifdef DEBUG
  {
    char buf1[BUFSIZ];
    char buf2[BUFSIZ];
    printf ("link add local %s nei %s\n",
	    inet_ntop (AF_INET6, &new->L_local_iface_addr, buf1, BUFSIZ),
	    inet_ntop (AF_INET6, &new->L_neighbor_iface_addr, buf2, BUFSIZ));
  }
#endif /* DEBUG */

  listnode_add (set, new);
  olsr_routing_set_update ();

  return new;
}

void
olsr_link_set_delete (struct list *set, struct olsr_link_tuple *tuple)
{
  listnode_delete (set, tuple);
  free (tuple);
  olsr_routing_set_update ();

  return;
}

void
olsr_link_set_destroy (struct list **set)
{
  list_delete_all_node (*set);
  *set = NULL;

  return;
}

struct olsr_link_tuple *
olsr_link_set_lookup (struct list *link_set, struct in6_addr recv_addr,
		      struct in6_addr src_addr)
{
  struct listnode *ls;
  struct olsr_link_tuple *link_tuple;

  for (ls = listhead (link_set); ls; nextnode (ls))
    {
      link_tuple = (struct olsr_link_tuple *) ls->data;

      if (IN6_IS_ADDR_SAME (recv_addr, link_tuple->L_local_iface_addr) &&
	  IN6_IS_ADDR_SAME (src_addr, link_tuple->L_neighbor_iface_addr))
	return link_tuple;
    }


  return NULL;
}

struct olsr_link_tuple *
olsr_link_set_lookup_by_foreign_ifaddr (struct list *link_set,
					struct in6_addr ifaddr)
{
  struct listnode *ls;
  struct olsr_link_tuple *link_tuple;

  for (ls = listhead (link_set); ls; nextnode (ls))
    {
      link_tuple = (struct olsr_link_tuple *) ls->data;

      if (IN6_IS_ADDR_SAME (ifaddr, link_tuple->L_neighbor_iface_addr))
	return link_tuple;
    }


  return NULL;
}


int
olsr_link_is_SYM (struct olsr_link_tuple *ls)
{
  time_t now;

  now = time (NULL);
  if (ls->L_SYM_time >= now)
    return 1;
  return 0;
}

int
olsr_link_is_ASYM (struct olsr_link_tuple *ls)
{
  time_t now;

  now = time (NULL);
  if ((ls->L_SYM_time < now) && (ls->L_ASYM_time >= now))
    {
#if 0
      printf ("ASYM link\n");
#endif
      return 1;
    }
  return 0;
}

int
olsr_link_is_LOST (struct olsr_link_tuple *ls)
{
  time_t now;

  now = time (NULL);
  if ((ls->L_SYM_time < now) && (ls->L_ASYM_time < now))
    return 1;
  return 0;
}

struct olsr_neighbor_tuple *
olsr_link_tuple_is_last_link (struct in6_addr if_addr)
{
  struct listnode *node;
  struct in6_addr main_addr;
  struct olsr_ifassoc_tuple *at;


  main_addr = *olsr_assoc_ifaddr2mainaddr (olsr.iface_assoc_set, &if_addr);

  for (node = listhead (olsr.iface_assoc_set); node; nextnode (node))
    {
      at = (struct olsr_ifassoc_tuple *) node->data;

      if (!IN6_IS_ADDR_SAME (at->I_main_addr, main_addr))
	continue;

      if (IN6_IS_ADDR_SAME (at->I_iface_addr, if_addr))
	continue;

      if (olsr_link_set_lookup_by_foreign_ifaddr
	  (olsr.link_set, at->I_iface_addr))
	return NULL;
    }

  return olsr_neighbor_tuple_lookup_from_main_addr (olsr.neighbor_set,
						    main_addr);
}

void
neighbor_link_expire_check ()
{
  time_t now;
  struct listnode *node, *next;
  struct in6_addr main_addr;
  struct olsr_link_tuple *lt;
  struct olsr_neighbor_tuple *nt;

  now = time (NULL);
  node = listhead (olsr.link_set);
  while (node)
    {
      lt = (struct olsr_link_tuple *) node->data;

      next = node->next;

      if (lt->L_SYM_time < now)
	{
	  main_addr =
	    *olsr_assoc_ifaddr2mainaddr (olsr.iface_assoc_set,
					 &lt->L_neighbor_iface_addr);
#if 0
	  if ((nt = olsr_link_tuple_is_last_link (main_addr)))
	    neighbor_set_delete (olsr.neighbor_set, nt);
#endif

	  if ((nt = olsr_link_tuple_is_last_link (lt->L_neighbor_iface_addr)))
            {
	      neighbor_set_delete (olsr.neighbor_set, nt);
            }
	}

      if (lt->L_ASYM_time < now)
	{
	  if (lt->L_ASYM_time == lt->L_time)
		  lt->L_time += (olsr.hello_validity == -1 ? 
                                 olsr.hello_interval * 3 : olsr.hello_validity);
	}

      if (lt->L_time < now)
	{
	  if ((nt = olsr_link_tuple_is_last_link (lt->L_neighbor_iface_addr)))
            {
	      neighbor_set_delete (olsr.neighbor_set, nt);
            }
	  olsr_link_set_delete (olsr.link_set, lt);
	  node = next;
	  continue;
	}

      node = next;
    }

  return;
}
