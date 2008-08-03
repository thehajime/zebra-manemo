/* Kernel netlink interface GNU/Linux system.
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

#ifndef _NETLINK_H_
#define _NETLINK_H_

/* Socket interface to kernel */
struct nlsock
{
  int sock;
  int seq;
  struct sockaddr_nl snl;
  char *name;
  struct vty *vty;
};

int netlink_talk (struct nlmsghdr *, struct nlsock *);
int netlink_parse_info (int (*filter) (struct sockaddr_nl *,
                                       struct nlmsghdr *), struct nlsock *);

#endif /*_NETLINK_H_*/