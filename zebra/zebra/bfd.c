/* BFD Function Interface with netlink interface.
   Copyright (C) 2007  Hajime TAZAKI.

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

#ifdef HAVE_KBFD

/* FIXME */
#include <kbfd.h>

#include "log.h"
#include "thread.h"
#include "sockunion.h"
#include "prefix.h"
#include "zclient.h"
#include "linklist.h"
#include "command.h"
#include "memory.h"

#include "zebra/netlink.h"
#include "zebra/bfd.h"
#include "zebra/rib.h"
#include "zebra/zserv.h"
#include "zebra/debug.h"

struct nlsock bfd_nlsock = { -1, 0, {0}, "bfd-netlink", NULL };
static struct list *bfd_peer_list;

extern struct thread_master *master;
extern struct list *client_list;

char *bfd_nl_msg_str[] = {
  "BFD_NEWPEER",
  "BFD_DELPEER",
  "BFD_GETPEER",
  "BFD_ADMINDOWN",
  "BFD_GETPEERSTAT",
};

char *bfd_state_string[] = {
  "AdminDown",
  "Down",
  "Init",
  "Up",
};

static int
bfd_netlink_state_change (struct sockaddr_nl *snl, struct nlmsghdr *h)
{
  int len;
  struct bfd_nl_peerinfo *peerinfo;
  struct bfd_peer peer;
  struct zserv *client;
  struct listnode *node;

  if (h->nlmsg_type != BFD_NEWPEER)
    {
      zlog_warn ("invalid nlmsg_type");
      return 0;
    }

  len = h->nlmsg_len - NLMSG_LENGTH (sizeof (struct bfd_nl_peerinfo));
  if (len < 0)
    return -1;

  peerinfo = NLMSG_DATA (h);
  if (IS_ZEBRA_DEBUG_KERNEL)
    zlog_info ("rcvd peerinfo %s: state=%d, ifindex=%d",
               sockunion_log ((union sockunion *) &peerinfo->dst),
               peerinfo->state, peerinfo->ifindex);

  memcpy (&peer.su, &peerinfo->dst.sa, sizeof (union sockunion));
  peer.ifindex = peerinfo->ifindex;

  if (peerinfo->state == BSM_Up)
    {
      for (node = listhead (client_list); node; nextnode (node))
        if ((client = getdata (node)) != NULL)
          zsend_bfd_peer_up (client, &peer);
    }
  else if (peerinfo->state == BSM_Down)
    {
      for (node = listhead (client_list); node; nextnode (node))
        if ((client = getdata (node)) != NULL)
          zsend_bfd_peer_down (client, &peer);
    }
  else
    {
    }

  return 0;
}

static int
kernel_bfd_read (struct thread *th)
{
  int ret;
  int sock;

  sock = THREAD_FD (th);
  ret = netlink_parse_info (bfd_netlink_state_change, &bfd_nlsock);
  thread_add_read (master, kernel_bfd_read, NULL, bfd_nlsock.sock);
  return 0;
}

/* User=>Kernel Netlink message */
static int
bfd_netlink_peer (int cmd, struct bfd_peer *peer)
{
  int ret;
  size_t size;
  struct
  {
    struct nlmsghdr nlh;
    struct bfd_nl_peerinfo info;
  } req;

  memset (&req, 0, sizeof req);
  req.nlh.nlmsg_len = NLMSG_LENGTH (sizeof (struct bfd_nl_peerinfo));
  req.nlh.nlmsg_flags = NLM_F_CREATE | NLM_F_REQUEST | NLM_F_ACK;
  req.nlh.nlmsg_type = cmd;

  if (peer->su.sa.sa_family == AF_INET)
    size = sizeof (struct sockaddr_in);
  else if (peer->su.sa.sa_family == AF_INET6)
    size = sizeof (struct sockaddr_in6);
  else
    {
      zlog_warn ("peer sockaddr is invalid");
      return -1;
    }

  memcpy (&req.info.dst.sa, &peer->su, size);
  req.info.ifindex = peer->ifindex;

  ret = netlink_talk (&req.nlh, &bfd_nlsock);
  if (ret < 0)
    {
      perror ("sendmsg");
      return -1;
    }

  if (IS_ZEBRA_DEBUG_KERNEL)
    zlog_info ("bfd peer %s (%s)", bfd_nl_msg_str[cmd - 1],
               sockunion_log (&peer->su));
  return 0;
}

struct bfd_peer *
bfd_peer_lookup (union sockunion *su, int ifindex, u_char peer_type)
{
  struct bfd_peer *peer;
  struct listnode *node;

  for (node = listhead (bfd_peer_list); node; nextnode (node))
    {
      peer = getdata (node);
      if (sockunion_same (&peer->su, su) &&
          peer->ifindex == ifindex && peer->type == peer_type)
        return peer;
    }

  return NULL;
}

int
kernel_bfd_add_peer (struct bfd_peer *peer, char appid)
{
  struct bfd_peer *tmp_peer;
  char *tmp_appid = NULL;
  struct listnode *node;

  /* lookup same peer */
  tmp_peer = bfd_peer_lookup (&peer->su, peer->ifindex, peer->type);
  if (!tmp_peer)
    {
      tmp_peer = XCALLOC (MTYPE_BFD_PEER, sizeof (struct bfd_peer));
      memcpy (&tmp_peer->su, &peer->su, sizeof (union sockunion));
      tmp_peer->ifindex = peer->ifindex;
      tmp_peer->type = peer->type;
      tmp_peer->appid_lst = list_new ();
      tmp_appid = malloc (sizeof (char));
      *tmp_appid = appid;
      listnode_add (tmp_peer->appid_lst, tmp_appid);
      listnode_add (bfd_peer_list, tmp_peer);
    }
  else
    {
      for (node = listhead (tmp_peer->appid_lst); node; nextnode (node))
        {
          tmp_appid = getdata (node);
          if (*tmp_appid == appid)
            break;
          tmp_appid = NULL;
        }

      if (tmp_appid)
        {
          zlog_warn ("duplicate registration.");
          return 0;
        }
      tmp_appid = malloc (sizeof (char));
      *tmp_appid = appid;
      listnode_add (tmp_peer->appid_lst, tmp_appid);
    }

  bfd_netlink_peer (BFD_NEWPEER, peer);
  return 0;
}

int
kernel_bfd_delete_peer (struct bfd_peer *peer, char appid)
{
  struct bfd_peer *tmp_peer;
  struct listnode *node;
  char *tmp_appid;

  tmp_peer = bfd_peer_lookup (&peer->su, peer->ifindex, peer->type);
  if (!tmp_peer)
    return 0;

  for (node = listhead (tmp_peer->appid_lst); node; nextnode (node))
    {
      tmp_appid = getdata (node);
      if (*tmp_appid == appid)
        break;
      tmp_appid = NULL;
    }

  if (!tmp_appid)
    return 0;

  listnode_delete (tmp_peer->appid_lst, (void *) tmp_appid);
  if (listcount (tmp_peer->appid_lst) == 0)
    {
      list_delete (tmp_peer->appid_lst);
      listnode_delete (bfd_peer_list, tmp_peer);
      bfd_netlink_peer (BFD_DELPEER, tmp_peer);
      XFREE (MTYPE_BFD_PEER, tmp_peer);
    }

  return 0;
}

/* Request Message */
static int
bfd_netlink_request (int type, struct nlsock *nl)
{
  int ret;
  struct sockaddr_nl snl;

  struct
  {
    struct nlmsghdr nlh;
    struct bfd_nl_peerinfo peer;
  } req;


  /* Check netlink socket. */
  if (nl->sock < 0)
    {
      zlog_err ("%s socket isn't active.", nl->name);
      return -1;
    }

  memset (&snl, 0, sizeof snl);
  snl.nl_family = AF_NETLINK;

  memset (&req, 0, sizeof req);
  req.nlh.nlmsg_len = sizeof req;
  req.nlh.nlmsg_type = type;
  req.nlh.nlmsg_flags = NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST;
  req.nlh.nlmsg_pid = 0;
  req.nlh.nlmsg_seq = ++nl->seq;
  //  memcpy (&req.peer.su.sa, &su, sizeof (req.peer.su));

  ret = sendto (nl->sock, (void *) &req, sizeof req, 0,
                (struct sockaddr *) &snl, sizeof snl);
  if (ret < 0)
    {
      zlog_err ("%s sendto failed: %s", nl->name, strerror (errno));
      return -1;
    }

  return 0;
}

static int
bfd_netlink_peer_info (struct sockaddr_nl *snl, struct nlmsghdr *h)
{
  int len;
  struct bfd_nl_peerinfo *peer;
  char buf1[BUFSIZ], buf2[BUFSIZ];
  struct vty *vty = bfd_nlsock.vty;

  if (h->nlmsg_type != BFD_NEWPEER)
    {
      zlog_warn ("invalid nlmsg_type");
      return 0;
    }

  len = h->nlmsg_len - NLMSG_LENGTH (sizeof (struct bfd_nl_peerinfo));
  if (len < 0)
    return -1;

  peer = NLMSG_DATA (h);

  vty_out (vty, "%s",
           inet_ntop (peer->dst.sa.sa_family,
                      peer->dst.sa.sa_family == AF_INET ?
                      (char *) &peer->dst.sin.sin_addr
                      : (char *) &peer->dst.sin6.sin6_addr, buf1, BUFSIZ));
  vty_out (vty, "  %u %u  %s %s%s",
           ntohl (peer->my_disc),
           ntohl (peer->your_disc),
           bfd_state_string[peer->state],
           ifindex2ifname (peer->ifindex), VTY_NEWLINE);

  vty_out (vty, "  SrcIP: %s%s",
           inet_ntop (peer->src.sa.sa_family,
                      peer->src.sa.sa_family == AF_INET ?
                      (char *) &peer->src.sin.sin_addr
                      : (char *) &peer->src.sin6.sin6_addr, buf2, BUFSIZ),
           VTY_NEWLINE);

  vty_out (vty, "  Packet Rcvd: %llu%s", peer->pkt_in, VTY_NEWLINE);
  vty_out (vty, "  Packet Send: %llu%s", peer->pkt_out, VTY_NEWLINE);
  vty_out (vty, "  Last UpTime(sysUptime): %u%s", peer->last_up, VTY_NEWLINE);
  vty_out (vty, "  Last DownTime(sysUptime): %u%s",
           peer->last_down, VTY_NEWLINE);
  vty_out (vty, "  Up Count: %u%s", peer->up_cnt, VTY_NEWLINE);

  return 0;
}


int
bfd_netlink_peer_list (struct vty *vty)
{
  int ret;

  ret = bfd_netlink_request (BFD_GETPEER, &bfd_nlsock);
  if (ret < 0)
    return ret;
  bfd_nlsock.vty = vty;
  ret = netlink_parse_info (bfd_netlink_peer_info, &bfd_nlsock);
  if (ret < 0)
    return ret;

  return 0;
}

#define  SHOW_BFD_HEADER   "DstIP                    LD/RD  State Interface %s"
DEFUN (show_bfd_neighbors,
       show_bfd_neighbors_cmd,
       "show bfd neighbors",
       SHOW_STR "Bi-Directional Forarding Detection\n" "Neighbor \n")
{

  vty_out (vty, SHOW_BFD_HEADER, VTY_NEWLINE);

  bfd_netlink_peer_list (vty);
  return CMD_SUCCESS;
}


DEFUN (bfd_parameter_if,
       bfd_parameter_if_cmd,
       "bfd interval <10-10000000> min_rx <10-10000000> multiplier <1-100>",
       "Bi-Directional Forarding Detection\n"
       "Set Desired Min TX Interval on this interface\n"
       "Desired Min TX Interval\n"
       "Set Required Min RX Interval on this interface\n"
       "Required Min RX Interval\n"
       "Set Detect Time Multiplier on this interface\n"
       "Detect Time Multiplier\n")
{
  struct interface *ifp;
  int ret;
  struct
  {
    struct nlmsghdr nlh;
    struct bfd_nl_linkinfo info;
  } req;

  ifp = (struct interface *) vty->index;

  memset (&req, 0, sizeof req);
  req.nlh.nlmsg_len = NLMSG_LENGTH (sizeof (struct bfd_nl_peerinfo));
  req.nlh.nlmsg_flags = NLM_F_CREATE | NLM_F_REQUEST | NLM_F_ACK;
  req.nlh.nlmsg_type = BFD_SETLINK;

  req.info.ifindex = ifp->ifindex;
  req.info.mintx = strtol (argv[0], NULL, 10);
  req.info.minrx = strtol (argv[1], NULL, 10);
  req.info.mult = strtol (argv[2], NULL, 10);

  ret = netlink_talk (&req.nlh, &bfd_nlsock);
  if (ret < 0)
    {
      vty_out (vty, "bfd_netlink: BFD_SETLINK(sendmsg) err");
      return CMD_WARNING;
    }

  if (IS_ZEBRA_DEBUG_KERNEL)
    zlog_info ("bfd_netlink: BFD_SETLINK done");

  return CMD_SUCCESS;
}


int
bfd_init ()
{
  int ret;
  struct sockaddr_nl snl;
  int namelen;

  bfd_peer_list = list_new ();

  /* socket initialization */
  bfd_nlsock.sock = socket (AF_NETLINK, SOCK_RAW, NETLINK_BFD);
  if (bfd_nlsock.sock < 0)
    {
      zlog_err ("Can't open %s socket: %s", bfd_nlsock.name,
                strerror (errno));
      return -1;
    }

  ret = fcntl (bfd_nlsock.sock, F_SETFL, O_NONBLOCK);
  if (ret < 0)
    {
      zlog_err ("Can't set %s socket flags: %s", bfd_nlsock.name,
                strerror (errno));
      close (bfd_nlsock.sock);
      return -1;
    }

  memset (&snl, 0, sizeof snl);
  snl.nl_family = AF_NETLINK;
  snl.nl_groups = 1;

  /* Bind the socket to the netlink structure for anything. */
  ret = bind (bfd_nlsock.sock, (struct sockaddr *) &snl, sizeof snl);
  if (ret < 0)
    {
      zlog_err ("Can't bind %s socket to group 0x%x: %s",
                bfd_nlsock.name, snl.nl_groups, strerror (errno));
      close (bfd_nlsock.sock);
      return -1;
    }

  /* multiple netlink sockets will have different nl_pid */
  namelen = sizeof snl;
  ret =
    getsockname (bfd_nlsock.sock, (struct sockaddr *) &snl,
                 (socklen_t *) & namelen);
  if (ret < 0 || namelen != sizeof snl)
    {
      zlog_err ("Can't get %s socket name: %s", bfd_nlsock.name,
                strerror (errno));
      close (bfd_nlsock.sock);
      return -1;
    }

  /* Now schedule incoming kernel message */
  thread_add_read (master, kernel_bfd_read, NULL, bfd_nlsock.sock);

  install_element (VIEW_NODE, &show_bfd_neighbors_cmd);
  install_element (ENABLE_NODE, &show_bfd_neighbors_cmd);
  install_element (INTERFACE_NODE, &bfd_parameter_if_cmd);

  return ret;
}

int
bfd_finish ()
{
  struct bfd_peer *peer;
  struct listnode *node;

  /* cleanup kernel peer list */
  for (node = listhead (bfd_peer_list); node; nextnode (node))
    {
      peer = getdata (node);
      bfd_netlink_peer (BFD_DELPEER, peer);
    }

  return 0;
}

#endif /*HAVE_KBFD */
