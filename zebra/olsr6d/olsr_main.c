
#include <zebra.h>

#include "getopt.h"
#include "thread.h"
#include "if.h"
#include "prefix.h"
#include "zclient.h"
#include "log.h"
#include "vty.h"
#include "command.h"

#include "olsr_common.h"
#include "olsr_node.h"
#include "olsr_packet.h"

#define OLSR6_VTY_PORT		2607
#define OLSR6_VTYSH_PATH	"/tmp/.olsr6d"

#define OLSR6_DEFAULT_CONFIG	"olsr6d.conf"

/* Configuration file and directory. */
char config_current[] = OLSR6_DEFAULT_CONFIG;
char config_default[] = SYSCONFDIR OLSR6_DEFAULT_CONFIG;

int olsr_sock;
char *progname;
FILE *errout;

struct olsr olsr;
struct zclient *zclient;
struct thread_master *master;

void olsr6_init ();

struct option longopts[] = {
  {"daemon", no_argument, NULL, 'd'},
  {"config_file", required_argument, NULL, 'f'},
  {"interface", required_argument, NULL, 'i'},
  {0}
};

void
sigint (int sig)
{
  zlog_info ("sigint recv");
  olsr_routing_set_clear (olsr.routing_table);

  exit (0);
}

void
signal_init ()
{
  int retval;
  struct sigaction sig, osig;

  sig.sa_handler = sigint;
  sig.sa_flags = 0;
  sigemptyset (&sig.sa_mask);

  retval = sigaction (SIGINT, &sig, &osig);

  if (retval < 0)
    {
      zlog_err ("sigaction() error, abort");
      exit (0);
    }

  return;
}

int
olsr_expire_check ()
{
  thread_add_timer (master, olsr_expire_check, NULL, 1);

  neighbor_link_expire_check ();
  neighbor_2hop_expire_check ();
  olsr_mpr_selector_expire_check ();
  olsr_duplicate_set_expire_check ();
  olsr_topology_set_expire_check ();
  olsr_interface_association_set_expire_check ();
  olsr_network_association_set_expire_check ();
  olsr_global_prefix_expire_check ();

  olsr_routing_set_update ();
  olsr_mpr_selection ();

  return 0;
}

void
olsr_set_mainaddr (struct in6_addr *main_addr)
{
  struct listnode *node;
  struct olsr_interface_tuple *it;

  for (node = listhead (olsr.interface_set); node; nextnode (node))
    {
      it = (struct olsr_interface_tuple *) node->data;

      if (! (it->status & ACTIVE))
	continue;

      *main_addr = it->local_iface_addr;
      return;
    }

  zlog_warn ("No active interface found");
  exit (0);
}

int
main (int argc, char *argv[])
{
  char *p;
  int flag;
  int opt;
  int daemon_mode = 0;
  char *config_file = NULL;
  struct olsr *o = &olsr;
  struct thread thread;
  char *ifname = NULL; /* for backward compatibility */

  errout = stderr;

  progname = ((p = strrchr (argv[0], '/')) ? ++p : argv[0]);

  master = thread_master_create ();

  flag = ZLOG_STDOUT;
  zlog_default = openzlog (progname, flag, ZLOG_OLSR6,
			   /* LOG_CONS | */ LOG_NDELAY | LOG_PERROR | LOG_PID,
			   LOG_DAEMON);

  while (1)
    {
      opt = getopt_long (argc, argv, "df:i:", longopts, 0);

      if (opt == EOF)
	break;

      switch (opt)
	{
	case 0:
	  break;
	case 'd':
	  daemon_mode = 1;
	  break;
	case 'f':
	  config_file = optarg;
	  break;
	case 'i':
          ifname = optarg;
	  break;
	default:
	  break;
	}
    }

  if (daemon_mode)
    daemon (0, 0);

  if_init ();
  signal_init ();
  cmd_init (1);
  vty_init ();

  olsr6_init ();
  vty_read_config (config_file, config_current, config_default);

  /* for backward compatibility */
  if (ifname)
    {
      struct olsr_interface_tuple *it;
      it = olsr_interface_get_by_name (ifname);
      it->status |= ACTIVE;
    }

  vty_serv_sock (NULL, OLSR6_VTY_PORT, OLSR6_VTYSH_PATH);

  thread_add_timer (master, olsr_hello_send_thread, NULL, 2);
  thread_add_timer (master, olsr_mid_send_thread, NULL, o->mid_interval);
  thread_add_timer (master, olsr_tc_send_thread, NULL, 5);
  thread_add_timer (master, olsr_hna_send_thread, NULL, 5);
  thread_add_timer (master, olsr_expire_check, NULL, 1);
  thread_add_timer (master, olsr_mpr_dump_timer, NULL, 1);

  zlog_info("olsr6d is ready and run");

  while (thread_fetch (master, &thread))
    thread_call (&thread);

  return 0;
}

