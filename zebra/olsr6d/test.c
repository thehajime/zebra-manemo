#include <sys/types.h>
#include <sys/param.h>
#include <netinet/in.h>

#include <zebra.h>

#include "thread.h"
#include "if.h"
#include "prefix.h"
#include "linklist.h"
#include "log.h"
#include "command.h"
#include "zclient.h"

char *arg;

struct thread_master *master;
struct zclient *zclient;
struct list *interfaces_lits;

struct connected *
connected_check_ipv6 (struct interface *ifp, struct prefix *p)
{
  struct connected *ifc;
  listnode node;

  for (node = listhead (ifp->connected); node; node = nextnode (node))
    {
      ifc = getdata (node);

      if (prefix_same (ifc->address, p))
        return ifc;
    }
  return 0;
}

int
tmp_if_add (int command, struct zclient *zclient, zebra_size_t length)
{
  struct interface *ifp;

printf ("if add: name %s\n", ifp->name);
  ifp = zebra_interface_add_read (zclient->ibuf);
  listnode_add (interfaces_lits, ifp);

  return 0;
}

int
tmp_if_addr_add (int command, struct zclient *zclient, zebra_size_t length)
{
  struct connected *c;

printf ("addr add function called\n");

  c = zebra_interface_address_add_read (zclient->ibuf);

  return 0;
}

int
ifaddr_add (struct interface *ifp, char *addr_str)
{
  struct prefix_ipv6 cp;
  struct connected *ifc;
  struct prefix_ipv6 *p;

  str2prefix_ipv6 (addr_str, &cp);

  ifc = connected_check_ipv6 (ifp, (struct prefix *) &cp);
  if (! ifc)
    {
      ifc = connected_new ();
      ifc->ifp = ifp;

      /* Address. */
      p = prefix_ipv6_new ();
      *p = cp;
      ifc->address = (struct prefix *) p;

      listnode_add (ifp->connected, ifc);
    }

  if_prefix_add_ipv6 (ifp, ifc);

  exit (0);
}

int
main_thread ()
{
  listnode node;
  struct interface *ifp;

  thread_add_timer (master, main_thread, NULL, 5);

printf ("main_thread %d\n", zclient->sock);
  for (node = listhead (interfaces_lits); node; node = nextnode (node))
   {
     ifp = (struct interface *)node->data;

printf ("seach if list: %s\n", ifp->name);
     ifaddr_add (ifp, arg);
   }

  return ;
}

void
usage (char *prog_name)
{
  printf("%s addr\n", prog_name);

  return;
}

int
main (int argc, char *argv[])
{
  struct thread thread;

  if (argc != 2)
   {
     usage (argv[0]);
     exit(0);
   }

  arg = argv[1];

  master = thread_master_create ();

  if_init ();

  zclient = zclient_new ();
  zclient_init (zclient, ZEBRA_ROUTE_OLSR6);
  zclient->interface_add = tmp_if_add;
  zclient->interface_address_add = tmp_if_addr_add;
  zclient_start (zclient);

  interfaces_lits = list_new ();

printf("zclient started %d\n", zclient->sock);

  thread_add_timer (master, main_thread, NULL, 5);

  while (thread_fetch (master, &thread))
    thread_call (&thread);

  return 0;
}
