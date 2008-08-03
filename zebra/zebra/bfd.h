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

#ifndef __BFD_NETLINK_H_
#define __BFD_NETLINK_H_

#ifdef HAVE_KBFD

#include "sockunion.h"

struct bfd_peer
{
	union sockunion su;
	int ifindex;
	struct list *appid_lst;
#define   BFD_PEER_SINGLE_HOP        0x01
#define   BFD_PEER_MULTI_HOP         0x02
	u_char type;
	u_char pad1;
	u_short pad2;
};

int kernel_bfd_add_peer(struct bfd_peer *, char);
int kernel_bfd_delete_peer(struct bfd_peer *, char);
int bfd_init();
int bfd_finish();

#endif /*HAVE_KBFD*/

#endif /* __BFD_NETLINK_H_ */
