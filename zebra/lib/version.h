/* Zebra version.
   Copyright (C) 1997, 1999, 2007 Kunihiro Ishiguro.

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

#ifndef _ZEBRA_VERSION_H
#define _ZEBRA_VERSION_H

#define ZEBRA_VERSION     "0.95a-sfc"

#define ZEBRA_BUG_ADDRESS "bug-zebra@gnu.org"

extern char *host_name;

void print_version(char *);
pid_t pid_output (char *);
pid_t pid_output_lock (char *);

#ifndef HAVE_DAEMON
int daemon(int, int);
#endif

#endif /* _ZEBRA_VERSION_H */
