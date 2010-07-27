/*
 * OLSR_Route.c
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


#define IFNAMESIZ	20

struct olsr_neighbor_tuple *
olsr_neighbor_tuple_lookup_from_main_addr (
     struct list *neighbor_set,
     struct in6_addr main_addr);


DEFUN (show_ipv6_olsr6_route,
       show_ipv6_olsr6_route_cmd,
       "show ipv6 olsr6 route",
       SHOW_STR IP6_STR OLSR6_STR "Route information list\n")
{
  char ifname[IFNAMSIZ];
  char destaddr[64];
  char nextaddr[64];
  struct listnode *node;
  struct olsr_interface_tuple *it;
  struct olsr_routing_entry *re;

  vty_out (vty, "%-30s %-25s %4s %s%s",
	   "Dest Addr", "Next-hop", "Hops", "IF Name", VNL);

  for (node = listhead (olsr.routing_table); node; nextnode (node))
    {
      re = (struct olsr_routing_entry *) node->data;

      inet_ntop (AF_INET6, &re->R_dest_addr, destaddr, sizeof (destaddr));
      inet_ntop (AF_INET6, &re->R_next_addr, nextaddr, sizeof (nextaddr));
      it =
	olsr_interface_lookup_by_addr (olsr.interface_set, re->R_iface_addr);
      memset (ifname, 0, sizeof (ifname));
      if (it)
	if_indextoname (it->ifindex, ifname);
      vty_out (vty, "%-30s %-25s %4d %s%s",
	       destaddr, nextaddr, re->R_dist, ifname, VNL);
    }

  return CMD_SUCCESS;
}

void
olsr_route_install_element ()
{
  install_element (VIEW_NODE, &show_ipv6_olsr6_route_cmd);
  install_element (ENABLE_NODE, &show_ipv6_olsr6_route_cmd);

  return;
}


void
olsr_routing_set_create (struct list **set)
{
  *set = list_new ();
  (*set)->del = free;

  return;
}

void
olsr_routing_set_clear (struct list *set)
{
  struct listnode *node;
  struct olsr_routing_entry *re;

  for (node = listhead (set); node; nextnode (node))
    {
      re = (struct olsr_routing_entry *) node->data;

/*    olsr_zebra_route_update (OLSR_ROUTE_DELETE, re); */
      free (node->data);
    }
  list_delete_all_node (set);

  return;
}

struct olsr_routing_entry *
olsr_routing_set_lookup (struct list *set, struct in6_addr dest)
{
  struct listnode *node;
  struct olsr_routing_entry *re;

  for (node = listhead (set); node; nextnode (node))
    {
      re = (struct olsr_routing_entry *) node->data;

      if (IN6_IS_ADDR_SAME (re->R_dest_addr, dest))
	return re;
    }

  return NULL;
}

struct olsr_routing_entry *
olsr_routing_set_lookup_complete (struct list *set, struct olsr_routing_entry *target)
{
  struct listnode *node;
  struct olsr_routing_entry *re;

  for (node = listhead (set); node; nextnode (node))
    {
      re = (struct olsr_routing_entry *) node->data;

      if ( ! memcmp (target, re, sizeof (struct olsr_routing_entry)))
	return re;
    }

  return NULL;
}

struct olsr_routing_entry *
olsr_network_routing_set_lookup (struct list *set, struct in6_addr dest, int plen)
{
  struct listnode *node;
  struct olsr_routing_entry *re;

  for (node = listhead (set); node; nextnode (node))
    {
      re = (struct olsr_routing_entry *) node->data;

      if (IN6_IS_ADDR_SAME (re->R_dest_addr, dest) && (re->R_plen == plen))
	return re;
    }

  return NULL;
}

struct olsr_routing_entry *
olsr_routing_set_add (struct list *set, struct olsr_routing_entry *new)
{
  struct olsr_routing_entry *re;

  if (!
      (re =
       (struct olsr_routing_entry *)
       malloc (sizeof (struct olsr_routing_entry))))
    {
      perror ("olsr_routing_set_add: malloc()");
      exit (-1);
    }

  memcpy (re, new, sizeof (struct olsr_routing_entry));
  listnode_add (set, re);

  if (re->R_dist > 1)
    olsr_zebra_route_update (OLSR_ROUTE_ADD, re);

#if DEBUG
  {
    char buf1[BUFSIZ];
    char buf2[BUFSIZ];
    printf ("route_add: dest %s next %s\n",
	    inet_ntop (AF_INET6, &re->R_dest_addr, buf1, sizeof (buf1)),
	    inet_ntop (AF_INET6, &re->R_next_addr, buf2, sizeof (buf2)));
  }
#endif

  return re;
}

struct olsr_routing_entry *
olsr_routing_set_add_simple (struct list *set, struct olsr_routing_entry *new)
{
  struct olsr_routing_entry *re;

  if (!
      (re =
       (struct olsr_routing_entry *)
       malloc (sizeof (struct olsr_routing_entry))))
    {
      perror ("olsr_routing_set_add_simple: malloc()");
      exit (-1);
    }

  memcpy (re, new, sizeof (struct olsr_routing_entry));
  listnode_add (set, re);

  return re;
}

void
olsr_routing_set_delete (struct list *set, struct olsr_routing_entry *del)
{
  listnode_delete (set, del);
  free (del);

  return;
}

void
olsr_routing_set_update ()
{
  int h;			/* hop count value */
  int new_rt_cnt;
  time_t now;
  struct list *nwrt;
  struct list *newrt;
  struct list *oldrt;
  struct listnode *anode;
  struct listnode *lnode;
  struct listnode *tnnode;
  struct listnode *rnode;
  struct listnode *tnode;
  struct listnode *nnode;
  struct in6_addr main_addr;
  struct olsr_link_tuple *lt;
  struct olsr_neighbor_tuple *nt;
  struct olsr_2hop_neighbor_tuple *tnt;
  struct olsr_routing_entry new_re;
  struct olsr_routing_entry *re, *re2;
  struct olsr_topology_tuple *tt;
  struct olsr_ifassoc_tuple *at;
  struct olsr_nwassoc_tuple *nat;


  oldrt = olsr.routing_table;
  olsr_routing_set_create (&newrt);

  now = time (NULL);
  for (lnode = listhead (olsr.link_set); lnode; nextnode (lnode))
    {
      lt = (struct olsr_link_tuple *) lnode->data;
      if (lt->L_SYM_time < now)	/* not SYM neighbor */
	continue;
      if (lt->L_ASYM_time < now)
	continue;
      if (lt->L_time < now)
	continue;

      if (olsr_routing_set_lookup
	  (newrt, lt->L_neighbor_iface_addr))
	continue;

      /* 
       * This adds a route for 1 hop neighbors. Since manet nodes do 
       * not have network on-link prefix route, routes for neighbors 
       * is needed to send NDP neighbor solicited message
       */
      memset (&new_re, 0, sizeof (new_re));
      new_re.R_dest_addr = lt->L_neighbor_iface_addr;
      new_re.R_next_addr = lt->L_neighbor_iface_addr;
      new_re.R_iface_addr = lt->L_local_iface_addr;
      new_re.R_plen = HOSTROUTE_PREFIXLEN;
      new_re.R_dist = 1;
      olsr_routing_set_add_simple (newrt, &new_re);

      main_addr =
	*olsr_assoc_ifaddr2mainaddr (olsr.iface_assoc_set,
				     &lt->L_neighbor_iface_addr);
      if (IN6_IS_ADDR_SAME (lt->L_neighbor_iface_addr, main_addr))
	continue;		/* processed addr is main_addr */

      memset (&new_re, 0, sizeof (new_re));
      new_re.R_dest_addr = main_addr;
      new_re.R_next_addr = lt->L_neighbor_iface_addr;
      new_re.R_iface_addr = lt->L_local_iface_addr;
      new_re.R_plen = HOSTROUTE_PREFIXLEN;
      new_re.R_dist = 1;
      olsr_routing_set_add_simple (newrt, &new_re);
    }

  for (tnnode = listhead (olsr.two_neighbor_set); tnnode; nextnode (tnnode))
    {
      tnt = (struct olsr_2hop_neighbor_tuple *) tnnode->data;

      if (IN6_IS_ADDR_SAME (olsr.main_addr, tnt->N_2hop_addr))
	continue;

      if (olsr_routing_set_lookup (newrt, tnt->N_2hop_addr))
	continue;

      if (olsr_neighbor_tuple_lookup_from_main_addr
	  (olsr.neighbor_set, tnt->N_2hop_addr))
	continue;

      if (!
	  (nt =
	   olsr_neighbor_tuple_lookup_from_main_addr (olsr.neighbor_set,
						      tnt->
						      N_neighbor_main_addr))
	  || (nt->N_willingness == WILL_NEVER))
	continue;

      for (rnode = listhead (newrt); rnode; nextnode (rnode))
	{
	  re = (struct olsr_routing_entry *) rnode->data;
	  if (IN6_IS_ADDR_SAME (re->R_dest_addr, tnt->N_neighbor_main_addr))
	    break;
	}
      if (rnode == NULL)
	continue;

      memset (&new_re, 0, sizeof (new_re));
      new_re.R_dest_addr = tnt->N_2hop_addr;
      new_re.R_next_addr = re->R_next_addr; 
      new_re.R_iface_addr = re->R_iface_addr;
      new_re.R_plen = HOSTROUTE_PREFIXLEN;
      new_re.R_dist = 2;
      olsr_routing_set_add_simple (newrt, &new_re);
    }

  new_rt_cnt = 1;
  for (h = 2; new_rt_cnt; h++)
    {
      new_rt_cnt = 0;
      for (tnode = listhead (olsr.topology_set); tnode; nextnode (tnode))
	{
	  tt = (struct olsr_topology_tuple *) tnode->data;

          if (IN6_IS_ADDR_SAME (olsr.main_addr, tt->T_dest_addr))
            continue;

	  if (olsr_routing_set_lookup (newrt, tt->T_dest_addr))
	    continue;

	  if (!
	      (re =
	       olsr_routing_set_lookup (newrt, tt->T_last_addr)))
	    continue;

	  if (re->R_dist != h)
	    continue;

	  memset (&new_re, 0, sizeof (new_re));
	  new_re.R_dest_addr = tt->T_dest_addr;
	  new_re.R_next_addr = re->R_next_addr;
	  new_re.R_iface_addr = re->R_iface_addr;
          new_re.R_plen = HOSTROUTE_PREFIXLEN;
	  new_re.R_dist = h + 1;
	  olsr_routing_set_add_simple (newrt, &new_re);
	  new_rt_cnt++;
	}
    }


  for (rnode = listhead (newrt); rnode; nextnode (rnode))
    {
      re = (struct olsr_routing_entry *) rnode->data;

      main_addr =
	*olsr_assoc_ifaddr2mainaddr (olsr.iface_assoc_set, &re->R_dest_addr);
      if (!IN6_IS_ADDR_SAME (main_addr, re->R_dest_addr))
	continue;

      for (anode = listhead (olsr.iface_assoc_set); anode; nextnode (anode))
	{
	  at = (struct olsr_ifassoc_tuple *) anode->data;

	  if (!IN6_IS_ADDR_SAME (main_addr, at->I_main_addr))
	    continue;

	  if (olsr_routing_set_lookup (newrt, at->I_iface_addr))
	    continue;

          /* If the mid entry is neighbor's, it must already processed */
	  if (olsr_link_set_lookup_by_foreign_ifaddr
	      (olsr.link_set, at->I_iface_addr))
	    continue; 

	  memset (&new_re, 0, sizeof (new_re));
	  new_re.R_dest_addr = at->I_iface_addr;
	  new_re.R_next_addr = re->R_next_addr;
	  new_re.R_iface_addr = re->R_iface_addr;
	  new_re.R_dist = re->R_dist;
	  olsr_routing_set_add_simple (newrt, &new_re);
	}
    }

  olsr_routing_set_create (&nwrt); 
  for (nnode = listhead (olsr.nw_assoc_set); nnode; nextnode (nnode))
    {
      nat = (struct olsr_nwassoc_tuple *) nnode->data;

/*      if (! (re2 = olsr_network_routing_set_lookup
                  (olsr.routing_table, nat->A_gateway_addr, nat->A_plen))) */

      if (! (re2 = olsr_routing_set_lookup
                  (newrt, nat->A_gateway_addr)))
        continue;

      if (! (re = olsr_network_routing_set_lookup
                  (nwrt, nat->A_network_addr, nat->A_plen)))
        {
          memset(&new_re, 0, sizeof(new_re));
          new_re.R_dest_addr = nat->A_network_addr;
          new_re.R_next_addr = re2->R_next_addr;
          new_re.R_dist = re2->R_dist + 1;
          new_re.R_plen = nat->A_plen;
          new_re.R_iface_addr = re2->R_iface_addr;

          olsr_routing_set_add_simple (nwrt, &new_re);

          continue;
        }


      if (re->R_dist > re2->R_dist)
        {
          memset(&new_re, 0, sizeof(new_re));
          new_re.R_dest_addr = nat->A_network_addr;
          new_re.R_next_addr = re2->R_next_addr;
          new_re.R_dist = re2->R_dist + 1;
          new_re.R_plen = nat->A_plen;
          new_re.R_iface_addr = re2->R_iface_addr;

          olsr_routing_set_delete (nwrt, re);
          olsr_routing_set_add_simple (nwrt, &new_re);
        }
    }

  for (rnode = listhead (nwrt); rnode; nextnode (rnode))
    {

      re = (struct olsr_routing_entry *) rnode->data;

      olsr_routing_set_add_simple (newrt, re);
    }
  list_delete(nwrt);


  /* remove old entry from kernel routing table */
  for (rnode = listhead (oldrt); rnode; nextnode (rnode) )
    {
      re = (struct olsr_routing_entry *)rnode->data;

      if (olsr_routing_set_lookup_complete (newrt, re))
        continue;

      olsr_zebra_route_update (OLSR_ROUTE_DELETE, re);
    }


  /* add new entry to kernel routing table */
  for (rnode = listhead (newrt); rnode; nextnode (rnode) )
    {
      re = (struct olsr_routing_entry *)rnode->data;

      if (olsr_routing_set_lookup_complete (oldrt, re))
        continue;

      olsr_zebra_route_update (OLSR_ROUTE_ADD, re);
    }

  list_delete (oldrt);

  olsr.routing_table = newrt;

  return;
}
