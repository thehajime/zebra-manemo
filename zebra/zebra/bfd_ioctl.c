/* BFD Function Interface with ioctl interface.
   Copyright (C) 2008  Hajime TAZAKI.

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

#include "zebra/bfd.h"
#include "zebra/rib.h"
#include "zebra/zserv.h"
#include "zebra/debug.h"

#define KBFD_DEVICE "/dev/kbfd0"

int bfd_ioctl_sock = -1;
static struct list *bfd_peer_list;

unsigned long bfd_debug_flag = 0;

extern struct thread_master *master;
extern struct list *client_list;

char *bfd_ioctl_msg_str[] = {
	"BFD_NEWPEER",
		"BFD_DELPEER",
		"BFD_GETPEER",
		"BFD_GETPEER_NUM",
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
bfd_ioctl_state_change (struct bfd_nl_peerinfo *peerinfo)
{
	struct bfd_peer peer;
	struct zserv *client;
	struct listnode *node;


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
	struct bfd_nl_peerinfo *peer;

	sock = THREAD_FD (th);

	if(bfd_ioctl_sock)
		return 0;

	peer = XCALLOC(MTYPE_BFD_PEER, sizeof(*peer));
	ret = read(bfd_ioctl_sock, peer, sizeof(*peer));
	if(ret < 0)
		zlog_warn("read notify %s", strerror(errno));

	bfd_ioctl_state_change(peer);
	thread_add_read (master, kernel_bfd_read, NULL, bfd_ioctl_sock);
	XFREE(MTYPE_BFD_PEER, peer);
	return 0;
}

/* User=>Kernel IOCTL message */
static int
bfd_ioctl_peer (int cmd, struct bfd_peer *peer)
{
	int ret;
	int size;
	struct bfd_nl_peerinfo req;

	if(bfd_ioctl_sock)
		return -1;

	if (peer->su.sa.sa_family == AF_INET)
		size = sizeof (struct sockaddr_in);
	else if (peer->su.sa.sa_family == AF_INET6)
		size = sizeof (struct sockaddr_in6);
	else
	{
		zlog_warn ("peer sockaddr is invalid");
		return -1;
	}

	memcpy (&req.dst.sa, &peer->su, size);
	req.ifindex = peer->ifindex;

	ret = ioctl(bfd_ioctl_sock, cmd, &req);
	if (ret == -1)
	{
		zlog_warn ("ioctl %s", strerror(errno));
		return -1;
	}

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_info ("bfd peer %s (%s)", 
		    cmd == BFD_NEWPEER ? "BFD_NEWPEER" : "BFD_DELPEER",
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

	bfd_ioctl_peer (BFD_NEWPEER, peer);
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
		bfd_ioctl_peer (BFD_DELPEER, tmp_peer);
		XFREE (MTYPE_BFD_PEER, tmp_peer);
	}

	return 0;
}


static int
bfd_ioctl_peer_info (struct bfd_nl_peerinfo *peer, struct vty *vty)
{
	char buf1[BUFSIZ], buf2[BUFSIZ];

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
bfd_ioctl_peer_list (struct vty *vty)
{
	int ret;
	int num;
	int i;
	struct bfd_nl_peerinfo *peer, *org;

	if(bfd_ioctl_sock)
		return -1;

	ret = ioctl(bfd_ioctl_sock, BFD_GETPEER_NUM, &num);
	if(ret == -1)
		zlog_warn("ioctl(GET_NUM)");

	peer = XCALLOC(MTYPE_BFD_PEER, num * sizeof(struct bfd_nl_peerinfo));
	if(!peer)
		zlog_warn("malloc");

	org = peer;

	ret = ioctl(bfd_ioctl_sock, BFD_GETPEER, peer);
	if(ret == -1)
		zlog_warn("ioctl(GET_PEER)");

	for(i=0; i<num; i++){
		bfd_ioctl_peer_info(peer, vty);
		peer++;
	}
	XFREE(MTYPE_BFD_PEER, org);

	return 0;
}

#define  SHOW_BFD_HEADER   "DstIP                    LD/RD  State Interface %s"
DEFUN (show_bfd_neighbors,
    show_bfd_neighbors_cmd,
    "show bfd neighbors",
    SHOW_STR "Bi-Directional Forarding Detection\n" "Neighbor \n")
{

	vty_out (vty, SHOW_BFD_HEADER, VTY_NEWLINE);

	bfd_ioctl_peer_list (vty);
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
	struct bfd_nl_linkinfo req;

	if(bfd_ioctl_sock)
		return CMD_WARNING;

	ifp = (struct interface *) vty->index;

	memset (&req, 0, sizeof req);

	req.ifindex = ifp->ifindex;
	req.mintx = strtol (argv[0], NULL, 10);
	req.minrx = strtol (argv[1], NULL, 10);
	req.mult = strtol (argv[2], NULL, 10);

	ret = ioctl(bfd_ioctl_sock, BFD_SETLINK, &req);
	if (ret == -1)
	{
		vty_out (vty, "bfd_ioctl: BFD_SETLINK(sendmsg) err");
		return CMD_WARNING;
	}

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_info ("bfd_ioctl: BFD_SETLINK done");

	return CMD_SUCCESS;
}

int
bfd_ioctl_set_flag(unsigned long flags)
{
	int ret;

	if(bfd_ioctl_sock)
		return -1;

	ret = ioctl(bfd_ioctl_sock, BFD_SETFLAG, &bfd_debug_flag);
	if (ret == -1)
	{
		return CMD_WARNING;
	}
	return CMD_SUCCESS;
} 

DEFUN (debug_bfd_bsm,
    debug_bfd_bsm_cmd,
    "debug bfd bsm",
    DEBUG_STR
    "kbfd configuration\n"
    "Debug option set for bfd state machine\n")
{
	bfd_debug_flag |= BFD_DEBUG_BSM;
	return bfd_ioctl_set_flag(bfd_debug_flag);
}

DEFUN (no_debug_bfd_bsm,
    no_debug_bfd_bsm_cmd,
    "no debug bfd bsm",
    NO_STR
    DEBUG_STR
    "kbfd configuration\n"
    "Debug option set for bfd state machine\n")
{
	bfd_debug_flag &= ~BFD_DEBUG_BSM;
	return bfd_ioctl_set_flag(bfd_debug_flag);
}

DEFUN (debug_bfd_ctrl_pkt,
    debug_bfd_ctrl_pkt_cmd,
    "debug bfd packet control",
    DEBUG_STR
    "kbfd configuration\n"
    "Debug option set for Packet\n"
    "Debug option set for Control Packet\n")
{
	bfd_debug_flag |= BFD_DEBUG_CTRL_PACKET;
	return bfd_ioctl_set_flag(bfd_debug_flag);
}

DEFUN (no_debug_bfd_ctrl_pkt,
    no_debug_bfd_ctrl_pkt_cmd,
    "no debug bfd packet control",
    NO_STR
    DEBUG_STR
    "kbfd configuration\n"
    "Debug option set for Packet\n"
    "Debug option set for Control Packet\n")
{
	bfd_debug_flag &= ~BFD_DEBUG_CTRL_PACKET;
	return bfd_ioctl_set_flag(bfd_debug_flag);
}

DEFUN (debug_bfd_uio,
    debug_bfd_uio_cmd,
    "debug bfd kernel",
    DEBUG_STR
    "kbfd configuration\n"
    "Debug option set for kernel io\n")
{
	bfd_debug_flag |= BFD_DEBUG_UIO;
	return bfd_ioctl_set_flag(bfd_debug_flag);
}


DEFUN (no_debug_bfd_uio,
    no_debug_bfd_uio_cmd,
    "no debug bfd kernel",
    NO_STR
    DEBUG_STR
    "kbfd configuration\n"
    "Debug option set for kernel io\n")
{
	bfd_debug_flag &= ~BFD_DEBUG_UIO;
	return bfd_ioctl_set_flag(bfd_debug_flag);
}

DEFUN (debug_bfd_debug,
    debug_bfd_debug_cmd,
    "debug bfd debug",
    DEBUG_STR
    "kbfd configuration\n"
    "Debug option set for internal debug\n")
{
	bfd_debug_flag |= BFD_DEBUG_DEBUG;
	return bfd_ioctl_set_flag(bfd_debug_flag);
}

DEFUN (no_debug_bfd_debug,
    no_debug_bfd_debug_cmd,
    "no debug bfd debug",
    NO_STR
    DEBUG_STR
    "kbfd configuration\n"
    "Debug option set for internal debug\n")
{
	bfd_debug_flag &= ~BFD_DEBUG_DEBUG;
	return bfd_ioctl_set_flag(bfd_debug_flag);
}




int
bfd_init ()
{
	bfd_peer_list = list_new ();

	/* socket initialization */
	bfd_ioctl_sock = open (KBFD_DEVICE, O_RDWR);
	if (bfd_ioctl_sock < 0) {
		zlog_err ("Can't open %s socket: %s", KBFD_DEVICE,
		    strerror (errno));
		return -1;
	}

	/* Now schedule incoming kernel message */
	thread_add_read (master, kernel_bfd_read, NULL, bfd_ioctl_sock);

	install_element (VIEW_NODE, &show_bfd_neighbors_cmd);
	install_element (ENABLE_NODE, &show_bfd_neighbors_cmd);
	install_element (INTERFACE_NODE, &bfd_parameter_if_cmd);

	install_element (ENABLE_NODE, &debug_bfd_bsm_cmd);
	install_element (ENABLE_NODE, &no_debug_bfd_bsm_cmd);
	install_element (ENABLE_NODE, &debug_bfd_ctrl_pkt_cmd);
	install_element (ENABLE_NODE, &no_debug_bfd_ctrl_pkt_cmd);
	install_element (ENABLE_NODE, &debug_bfd_uio_cmd);
	install_element (ENABLE_NODE, &no_debug_bfd_uio_cmd);
	install_element (ENABLE_NODE, &debug_bfd_debug_cmd);
	install_element (ENABLE_NODE, &no_debug_bfd_debug_cmd);

	return 0;
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
		bfd_ioctl_peer (BFD_DELPEER, peer);
	}

	return 0;
}

#endif /*HAVE_KBFD */
