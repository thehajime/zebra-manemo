

#include <zebra.h>

#include "linklist.h"
#include "vty.h"
#include "command.h"
#include "log.h"

#include "olsr_common.h"
#include "olsr_node.h"
#include "olsr_packet.h"

#define IFNAMESIZ	10

DEFUN (show_ipv6_olsr6_mpr,
       show_ipv6_olsr6_mpr_cmd,
       "show ipv6 olsr6 mpr",
       SHOW_STR
       IP6_STR
       OLSR6_STR
       "MPR list\n")
{
  char mpraddr[BUFSIZ];
  char ifname[IFNAMESIZ];
  struct listnode *inode;
  struct listnode *mnode;
  struct olsr_interface_tuple *it;
  struct olsr_mpr_tuple *mt;

  memset(mpraddr, 0, sizeof(mpraddr));
  memset(ifname, 0, sizeof(ifname));

  vty_out (vty, "%-30s %s%s", "MPR Main Addr", "IF Name", VNL);

  for (inode = listhead (olsr.interface_set); inode; nextnode (inode))
    {
      it = (struct olsr_interface_tuple *) inode->data;

      for (mnode = listhead (it->mpr_set); mnode; nextnode (mnode))
	{
	  mt = (struct olsr_mpr_tuple *) mnode->data;

	  if_indextoname (it->ifindex, ifname);
	  inet_ntop (AF_INET6, &mt->M_main_addr, mpraddr, sizeof (mpraddr));
	  vty_out (vty, "%-30s %s%s", mpraddr, ifname, VNL);
	}
    }

  return CMD_SUCCESS;
}

DEFUN (show_ipv6_olsr6_mpr_selector,
       show_ipv6_olsr6_mpr_selector_cmd,
       "show ipv6 olsr6 mpr selector",
       SHOW_STR
       IP6_STR
       OLSR6_STR
       "MPR Selector list\n")
{
  char msaddr[40];
  struct listnode *node;
  struct olsr_mpr_selector_tuple *mst;

  vty_out (vty, "%-30s %s", "MPR Selector Main Addr", VNL);

  for (node = listhead (olsr.mpr_selector_set); node; nextnode (node))
    {
      mst = (struct olsr_mpr_selector_tuple *) node->data;

      inet_ntop (AF_INET6, &mst->MS_main_addr, msaddr, sizeof (msaddr));
      vty_out (vty, "%-30s %s", msaddr, VNL);
    }

  return CMD_SUCCESS;
}

void
olsr_mpr_install_element ()
{
  install_element (VIEW_NODE, &show_ipv6_olsr6_mpr_cmd);
  install_element (ENABLE_NODE, &show_ipv6_olsr6_mpr_cmd);
  install_element (VIEW_NODE, &show_ipv6_olsr6_mpr_selector_cmd);
  install_element (ENABLE_NODE, &show_ipv6_olsr6_mpr_selector_cmd);
}

void
neighbor_set_create_onehop_neighbor_on_if (struct olsr_interface_tuple *oif,
					   struct list **set)
{
  struct listnode *ls;
  struct in6_addr main_addr;
  struct olsr_link_tuple *link_tuple;
  struct olsr_neighbor_tuple *neighbor_tuple;

  neighbor_set_create (set);
  for (ls = listhead (olsr.link_set); ls; nextnode (ls))
    {
      link_tuple = (struct olsr_link_tuple *) ls->data;
#ifdef DEBUG
      {
	char buf1[BUFSIZ];
	char buf2[BUFSIZ];
	printf ("mpr_create_onehop: compare %s %s\n",
		inet_ntop (AF_INET6, &link_tuple->L_local_iface_addr, buf1,
			   sizeof (buf1)), inet_ntop (AF_INET6,
						      &oif->local_iface_addr,
						      buf2, sizeof (buf2)));
      }
#endif

      if (memcmp (&link_tuple->L_local_iface_addr, &oif->local_iface_addr,
		  sizeof (struct in6_addr)) == 0)
	{
	  main_addr = *olsr_assoc_ifaddr2mainaddr
	    (olsr.iface_assoc_set, &link_tuple->L_neighbor_iface_addr);

	  if (olsr_neighbor_tuple_lookup_from_main_addr (*set, main_addr))
	    {
	      continue;
	    }

	  if ((neighbor_tuple = olsr_neighbor_tuple_lookup_from_main_addr
	       (olsr.neighbor_set, main_addr)) == NULL)
	    continue;

          if (neighbor_tuple->N_status == NOT_SYM)
            continue;

#if 0
	  {
	    char buf[BUFSIZ];
	    printf ("mpr_create_onehop: add %s\n",
		    inet_ntop (AF_INET6,
			       &neighbor_tuple->N_neighbor_main_addr, buf,
			       sizeof (buf)));
	  }
#endif
	  neighbor_set_add (*set, neighbor_tuple);
	}
    }

  return;
}

struct olsr_neighbor_tuple *
twohop_neighbor_is_also_onehop_neighbor (struct list *onehop,
					 struct olsr_2hop_neighbor_tuple node)
{
  struct listnode *ns;
  struct olsr_neighbor_tuple *neighbor_tuple;

  for (ns = listhead (onehop); ns; nextnode (ns))
    {
      neighbor_tuple = (struct olsr_neighbor_tuple *) ns->data;

      if (! memcmp
	  (&neighbor_tuple->N_neighbor_main_addr, &node.N_neighbor_main_addr,
	   sizeof (struct in6_addr)) 
	  && (neighbor_tuple->N_status == SYM))
	return neighbor_tuple;
    }

  return NULL;
}

int
twohop_neighbor_is_reachable_by_willnever (struct list *onehop,
					   struct olsr_2hop_neighbor_tuple
					   node)
{
  struct olsr_neighbor_tuple *ns;

  if ((ns = olsr_neighbor_tuple_lookup_from_main_addr
       (onehop, node.N_neighbor_main_addr)) != NULL)
    {
      if (ns->N_willingness == WILL_NEVER)
	return 1;
      else
	return 0;
    }
  return 1;
}

void
neighbor_set_create_strict_twohop_neighbor_on_if (struct list *onehop,
						  struct list **twohop)
{
  struct listnode *nnode;
  struct listnode *tnnode;
  struct in6_addr main_addr;
  struct olsr_neighbor_tuple new, *nt, *nt2, *nt3, *nt4;
  struct olsr_2hop_neighbor_tuple *tnt;

  neighbor_set_create (twohop);

  for (nnode = listhead (onehop); nnode; nextnode (nnode))
    {
      nt = (struct olsr_neighbor_tuple *) nnode->data;

      for (tnnode = listhead (olsr.two_neighbor_set); tnnode;
	   nextnode (tnnode))
	{
	  tnt = (struct olsr_2hop_neighbor_tuple *) tnnode->data;

	  if (!IN6_IS_ADDR_SAME
	      (nt->N_neighbor_main_addr, tnt->N_neighbor_main_addr))
	    continue; /* link for tnt is not provided by nt */

	  main_addr =
	    *olsr_assoc_ifaddr2mainaddr (olsr.iface_assoc_set,
					 &tnt->N_2hop_addr);
	  if (!IN6_IS_ADDR_SAME (main_addr, tnt->N_2hop_addr))
	    continue;

	  if (IN6_IS_ADDR_SAME (tnt->N_2hop_addr, olsr.main_addr))
	    continue;

	  if ((nt2 = olsr_neighbor_tuple_lookup_from_main_addr
	      (onehop, tnt->N_2hop_addr)) && (nt2->N_status == SYM))
	    continue;

	  if ((nt4 = olsr_neighbor_tuple_lookup_from_main_addr
	      (olsr.neighbor_set, tnt->N_2hop_addr)) && (nt4->N_status == SYM))
	    continue;

	  if (!
	      (nt3 =
	       olsr_neighbor_tuple_lookup_from_main_addr (*twohop,
							  tnt->N_2hop_addr)))
	    {
	      memset (&new, 0, sizeof (new));
	      new.N_neighbor_main_addr = tnt->N_2hop_addr;
              new.N_willingness = tnt->N_willingness;

#if 0
	      {
		char buf[BUFSIZ];
		printf ("create_twohop: add %s\n",
			inet_ntop (AF_INET6, &new.N_neighbor_main_addr, buf,
				   sizeof (buf)));
	      }
#endif
	      nt3 = neighbor_set_add (*twohop, &new);
	    }
	  nt3->N_routecount++;
#if 0
	  {
	    char buf[BUFSIZ];
	    printf ("mpr_create_twohop: %s route_count %d\n",
		    inet_ntop (AF_INET6, &nt3->N_neighbor_main_addr, buf,
			       sizeof (buf)), nt3->N_routecount);
	  }
#endif
	}
    }

  return;
}

void
olsr_mpr_set_create (struct list **set)
{
  *set = list_new ();
  (*set)->del = free;

  return;
}

struct olsr_mpr_tuple *
olsr_mpr_set_add (struct list *mpr_set, struct olsr_mpr_tuple node)
{
  struct olsr_mpr_tuple *new;

#if 0
  {
    char buf[BUFSIZ];
    printf ("mpr_set_add: new mpr add %s %x\n",
	    inet_ntop (AF_INET6, &node.M_main_addr, buf, sizeof (buf)), time(NULL));
  }
#endif

  if ((new =
       (struct olsr_mpr_tuple *) malloc (sizeof (struct olsr_mpr_tuple))) ==
      NULL)
    {
      perror ("olsr_mpr_set_add(): malloc()");
      return NULL;
    }

  *new = node;
  listnode_add (mpr_set, new);

  return new;
}

void
olsr_mpr_delete_allnode (struct list *mpr_set)
{
  list_delete_all_node (mpr_set);

  return;
}

void
olsr_mpr_selector_set_create (struct list **set)
{
  *set = list_new ();
  (*set)->del = free;

  return;
}

void
olsr_mpr_selector_set_delete (struct list *set,
			      struct olsr_mpr_selector_tuple *node)
{
  listnode_delete (set, node);
  free (node);

  return;
}


struct olsr_mpr_selector_tuple *
olsr_mpr_selector_set_add (struct list *mpr_set,
			   struct olsr_mpr_selector_tuple node)
{
  struct olsr_mpr_selector_tuple *new;

  if ((new =
       (struct olsr_mpr_selector_tuple *)
       malloc (sizeof (struct olsr_mpr_selector_tuple))) == NULL)
    {
      perror ("olsr_mpr_selector_set_add(): malloc()");
      return NULL;
    }
  {
    char buf[BUFSIZ];
    zlog_info ("selector_add: new entry %s\n",
	    inet_ntop (AF_INET6, &node.MS_main_addr, buf, sizeof (buf)));
  }
  *new = node;
  listnode_add (mpr_set, new);
  ansn++;

  return new;
}

void
olsr_mpr_selecotr_delete_allnode (struct list *mpr_selector_set)
{
  list_delete_all_node (mpr_selector_set);
  ansn++;

  return;
}


struct olsr_mpr_tuple *
olsr_mpr_set_lookup (struct list *set, struct in6_addr main_addr)
{
  struct listnode *node;
  struct olsr_mpr_tuple *mt;

  for (node = listhead (set); node; nextnode (node))
    {
      mt = (struct olsr_mpr_tuple *) node->data;

      if (IN6_IS_ADDR_SAME (mt->M_main_addr, main_addr))
	return mt;
    }

  return NULL;
}

void
olsr_mpr_caluculate_degree (struct list *onehop_set)
{
  struct listnode *nei;
  struct listnode *nei2;
  struct olsr_neighbor_tuple *nt;
  struct olsr_2hop_neighbor_tuple *tnt;

  for (nei = listhead (onehop_set); nei; nextnode (nei))
    {
      nt = (struct olsr_neighbor_tuple *) nei->data;
      nt->N_degree = 0;

      if ( nt->N_status != SYM )
        continue;

      for (nei2 = listhead (olsr.two_neighbor_set); nei2; nextnode (nei2))
	{
	  tnt = (struct olsr_2hop_neighbor_tuple *) nei2->data;

	  if (!IN6_IS_ADDR_SAME
	      (nt->N_neighbor_main_addr, tnt->N_neighbor_main_addr))
	    continue;

	  if (IN6_IS_ADDR_SAME (tnt->N_2hop_addr, olsr.main_addr))
	    continue;

	  if (olsr_neighbor_tuple_lookup_from_main_addr
	      (onehop_set, tnt->N_2hop_addr))
	    continue;

	  nt->N_degree++;
	}
    }


  return;
}

int
olsr_2hop_neighbor_is_linked (struct list *top, struct in6_addr l1,
			      struct in6_addr l2)
{
  struct listnode *two_nei;
  struct olsr_2hop_neighbor_tuple *two_nei_tuple;

  for (two_nei = listhead (top); two_nei; nextnode (two_nei))
    {
      two_nei_tuple = (struct olsr_2hop_neighbor_tuple *) two_nei->data;

      if (!memcmp
	  (&two_nei_tuple->N_neighbor_main_addr, &l1,
	   sizeof (struct in6_addr))
	  && !memcmp (&two_nei_tuple->N_2hop_addr, &l2,
		      sizeof (struct in6_addr)))
	return 1;
    }

  return 0;
}

void
olsr_mpr_caluculate_reachability (struct list *onehop_set,
				  struct list *twohop_set)
{
  struct listnode *nei;
  struct listnode *nei2;
  struct olsr_neighbor_tuple *n;
  struct olsr_neighbor_tuple *n2;

  for (nei = listhead (onehop_set); nei; nextnode (nei))
    {
      n = (struct olsr_neighbor_tuple *) nei->data;
      n->N_reachability = 0;

      for (nei2 = listhead (twohop_set); nei2; nextnode (nei2))
	{
	  n2 = (struct olsr_neighbor_tuple *) nei2->data;
	  if (olsr_2hop_neighbor_is_linked (olsr.two_neighbor_set,
					    n->N_neighbor_main_addr,
					    n2->N_neighbor_main_addr))
	    n->N_reachability++;
	}
    }

  return;
}

struct olsr_neighbor_tuple *
candidate_evaluation (struct olsr_neighbor_tuple *node1,
		      struct olsr_neighbor_tuple *node2)
{
  if (node1->N_willingness < node2->N_willingness)
    {
      return node2;
    }
  else if (node1->N_willingness == node2->N_willingness)
    {
      if (node1->N_reachability < node2->N_reachability)
	{
	  return node2;
	}
      else if (node1->N_reachability == node2->N_reachability)
	{
	  if (node1->N_degree < node2->N_degree)
	    return node2;
	}
    }

  return node1;
}

void
olsr_mpr_remove_node_covered_by_mpr_addr (struct list *set,
					  struct in6_addr mpr_addr)
{
  struct listnode *two_nei;
  struct olsr_neighbor_tuple *nei_tuple;
  struct olsr_2hop_neighbor_tuple *two_nei_tuple;

  for (two_nei = listhead (olsr.two_neighbor_set); two_nei;
       nextnode (two_nei))
    {
      two_nei_tuple = (struct olsr_2hop_neighbor_tuple *) two_nei->data;

      if (memcmp (&two_nei_tuple->N_neighbor_main_addr,
		  &mpr_addr, sizeof (struct in6_addr)))
	continue;

      if (nei_tuple = olsr_neighbor_tuple_lookup_from_main_addr
	   (set, two_nei_tuple->N_2hop_addr))
	{
	  neighbor_set_delete (set, nei_tuple);
	}
    }

  return;
}

int
olsr_mpr_neighbor_lookup_by_dest (struct list *set, struct list *onehop,
				  struct in6_addr dst, struct in6_addr *m)
{
  struct listnode *node;
  struct olsr_2hop_neighbor_tuple *tnt;

  for (node = listhead (set); node; nextnode (node))
    {
      tnt = (struct olsr_2hop_neighbor_tuple *) node->data;

      if (!IN6_IS_ADDR_SAME (dst, tnt->N_2hop_addr))
	continue;

      if (!olsr_neighbor_tuple_lookup_from_main_addr
	  (onehop, tnt->N_neighbor_main_addr))
	continue;

      *m = tnt->N_neighbor_main_addr;
      return 1;
    }

  return 0;
}

void
olsr_mpr_selection_interface (struct olsr_interface_tuple *oif)
{
  int cnt, ocnt;
  struct list *onehop_set;
  struct list *twohop_set;
  struct listnode *nei;
  struct in6_addr mpraddr;
  struct olsr_mpr_tuple new;
  struct olsr_neighbor_tuple *candidate;
  struct olsr_neighbor_tuple *neighbor_tuple = NULL;


  olsr_mpr_delete_allnode (oif->mpr_set);

  neighbor_set_create_onehop_neighbor_on_if (oif, &onehop_set);
  neighbor_set_create_strict_twohop_neighbor_on_if (onehop_set, &twohop_set);


  for (nei = listhead (onehop_set); nei; nextnode (nei))
    {
      neighbor_tuple = (struct olsr_neighbor_tuple *) nei->data;

      if ( (neighbor_tuple->N_status == SYM ) &&
                ( neighbor_tuple->N_willingness == WILL_ALWAYS))
	{
	  memset (&new, 0, sizeof (new));
	  new.M_main_addr = neighbor_tuple->N_neighbor_main_addr;
	  olsr_mpr_set_add (oif->mpr_set, new);
	  neighbor_set_delete (onehop_set, neighbor_tuple);
	  olsr_mpr_remove_node_covered_by_mpr_addr (twohop_set,
						    new.M_main_addr);
	}
    }


  olsr_mpr_caluculate_degree (onehop_set);

/*	nei = listhead(twohop_set); */
  cnt = listcount (twohop_set);
  ocnt = 0;
  while (cnt != ocnt)
    {

      nei = listhead (twohop_set);
      if (nei == NULL)
	break;

      neighbor_tuple = (struct olsr_neighbor_tuple *) nei->data;
      /* Ignore NEVER's nbr */
      if (neighbor_tuple->N_willingness == WILL_NEVER)
        {
          neighbor_set_delete (twohop_set, neighbor_tuple);
	  ocnt = cnt;
	  cnt = listcount (twohop_set);
	  continue;
        }

      if (neighbor_tuple->N_routecount != 1)
	{
	  ocnt = cnt;
	  cnt = listcount (twohop_set);
	  continue;
	}

      if (!olsr_mpr_neighbor_lookup_by_dest
	  (olsr.two_neighbor_set, onehop_set,
	   neighbor_tuple->N_neighbor_main_addr, &mpraddr))
	{
	  ocnt = cnt;
	  cnt = listcount (twohop_set);
	  continue;
	}


      memset (&new, 0, sizeof (new));
      new.M_main_addr = mpraddr;
      olsr_mpr_set_add (oif->mpr_set, new);
      neighbor_set_delete (twohop_set, neighbor_tuple);
      olsr_mpr_remove_node_covered_by_mpr_addr (twohop_set, new.M_main_addr);

      ocnt = cnt;
      cnt = listcount (twohop_set);
    }

  candidate = NULL;
  while (listcount (twohop_set))
    {
      olsr_mpr_caluculate_reachability (onehop_set, twohop_set);

      for (nei = listhead (onehop_set); nei; nextnode (nei))
	{
	  neighbor_tuple = (struct olsr_neighbor_tuple *) nei->data;

	  if (neighbor_tuple->N_reachability < 1)
	    continue;

	  if (candidate == NULL)
	    {
	      candidate = neighbor_tuple;
	      continue;
	    }

	  candidate = candidate_evaluation (candidate, neighbor_tuple);
	}
      if (candidate == NULL)
	break;

      memset (&new, 0, sizeof (new));
      new.M_main_addr = candidate->N_neighbor_main_addr;
      olsr_mpr_set_add (oif->mpr_set, new);
      neighbor_set_delete (onehop_set, neighbor_tuple);
      olsr_mpr_remove_node_covered_by_mpr_addr (twohop_set, new.M_main_addr);
      candidate = NULL;
    }

  list_delete (onehop_set);
  list_delete (twohop_set);

  return;
}

void
olsr_mpr_selection ()
{
  struct listnode *is;

  struct olsr_interface_tuple *interface_tuple;

  for (is = listhead (olsr.interface_set); is; nextnode (is))
    {
      interface_tuple = (struct olsr_interface_tuple *) is->data;

#ifdef DEBUG
      {
	char buf[BUFSIZ];
	printf ("olsr_mpr_selection(): now proccesing %s %d\n",
		if_indextoname (interface_tuple->ifindex, buf),
		interface_tuple->status);
      }
#endif
      if (! (interface_tuple->status & ACTIVE)
	  || !(interface_tuple->optset))
	continue;

      olsr_mpr_selection_interface (interface_tuple);
    }

  return;
}

struct olsr_mpr_selector_tuple *
olsr_mpr_selector_set_lookup (struct list *set, struct in6_addr MS_main_addr)
{
  struct listnode *mss;
  struct olsr_mpr_selector_tuple *selector_tuple;


  for (mss = listhead (set); mss; nextnode (mss))
    {
      selector_tuple = (struct olsr_mpr_selector_tuple *) mss->data;

      if (!memcmp
	  (&selector_tuple->MS_main_addr, &MS_main_addr,
	   sizeof (struct in6_addr)))
	return selector_tuple;
    }

  return NULL;
}

void
olsr_mpr_selector_expire_check ()
{
  time_t now;
  struct listnode *node, *next;
  struct olsr_mpr_selector_tuple *mst;
  char buf[1024];

  now = time (NULL);
  node = listhead (olsr.mpr_selector_set);
  while (node)
    {
      mst = (struct olsr_mpr_selector_tuple *) node->data;

      next = node->next;
      if (mst->MS_time <= now)
	{
	
  	  zlog_info("MPR SELECTOR DELTED %s\n", inet_ntop (AF_INET6, &mst->MS_main_addr, buf, sizeof (buf)));
	  next = node->next;
	  olsr_mpr_selector_set_delete (olsr.mpr_selector_set, mst);
	  node = next;
	  continue;
	}
      node = next;
    }

  return;
}

int
olsr_mpr_dump_timer (struct thread *thread)
{

  thread_add_timer(master, olsr_mpr_dump_timer, NULL, 1);

  if (!IS_OLSR_DEBUG_MESSAGE (TC))
    return 0;

  if (listcount (olsr.mpr_selector_set) > 0)
    zlog_warn ("MPRLOG 1");
  else
    zlog_warn ("MPRLOG 0");

#if 0
  char mpraddr[BUFSIZ];
  char ifname[IFNAMESIZ];
  struct listnode *inode;
  struct listnode *mnode;
  struct olsr_interface_tuple *it;
  struct olsr_mpr_tuple *mt;

  memset(mpraddr, 0, sizeof(mpraddr));
  memset(ifname, 0, sizeof(ifname));

  zlog_warn ("%-30s %s", "MPR Main Addr", "IF Name");

  for (inode = listhead (olsr.interface_set); inode; nextnode (inode))
    {
      it = (struct olsr_interface_tuple *) inode->data;

      for (mnode = listhead (it->mpr_set); mnode; nextnode (mnode))
	{
	  mt = (struct olsr_mpr_tuple *) mnode->data;
	  if_indextoname (it->ifindex, ifname);
	  inet_ntop (AF_INET6, &mt->M_main_addr, mpraddr, sizeof (mpraddr));
	  zlog_warn ("%-30s %s", mpraddr, ifname);
	}
    }
#endif

  return 0;
}
