/* Virtual terminal [aka TeletYpe] interface routine.
   Copyright (C) 1997 Kunihiro Ishiguro.

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

#ifndef _ZEBRA_VTY_H
#define _ZEBRA_VTY_H

#define VTY_BUFSIZ 512
#define VTY_MAXHIST 20

enum vty_type {VTY_TERM, VTY_FILE, VTY_SHELL, VTY_SHELL_SERV};

/* There are some command levels which called from command node. */
enum node_type 
{
  AUTH_NODE,			/* Authentication mode of vty interface. */
  VIEW_NODE,			/* View node. Default mode of vty interface. */
  AUTH_ENABLE_NODE,		/* Authentication mode for change enable. */
  ENABLE_NODE,			/* Enable node. */
  CONFIG_NODE,			/* Config node. Default mode of config file. */
  DEBUG_NODE,			/* Debug node. */
  AAA_NODE,			/* AAA node. */
  KEYCHAIN_NODE,		/* Key-chain node. */
  KEYCHAIN_KEY_NODE,		/* Key-chain key node. */
  INTERFACE_NODE,		/* Interface mode node. */
  ZEBRA_NODE,			/* zebra connection node. */
  TABLE_NODE,			/* rtm_table selection node. */
  RIP_NODE,			/* RIP protocol mode node. */ 
  RIPNG_NODE,			/* RIPng protocol mode node. */
  BGP_NODE,			/* BGP protocol mode which includes BGP4+ */
  BGP_VPNV4_NODE,		/* BGP MPLS-VPN PE exchange. */
  BGP_IPV4_NODE,		/* BGP IPv4 unicast address family.  */
  BGP_IPV4M_NODE,		/* BGP IPv4 multicast address family.  */
  BGP_IPV6_NODE,		/* BGP IPv6 address family */
  OSPF_NODE,			/* OSPF protocol mode */
  OSPF6_NODE,			/* OSPF protocol for IPv6 mode */
  OLSR6_NODE,			/* OLSR protocol for IPv6 mode */
  SMF6_NODE,                    /* SMF for IPv6 mode */
  MASC_NODE,			/* MASC for multicast.  */
  IRDP_NODE,			/* ICMP Router Discovery Protocol mode. */ 
  IP_NODE,			/* Static ip route node. */
  ACCESS_NODE,			/* Access list node. */
  PREFIX_NODE,			/* Prefix list node. */
  ACCESS_IPV6_NODE,		/* Access list node. */
  PREFIX_IPV6_NODE,		/* Prefix list node. */
  AS_LIST_NODE,			/* AS list node. */
  COMMUNITY_LIST_NODE,		/* Community list node. */
  RMAP_NODE,			/* Route map node. */
  SMUX_NODE,			/* SNMP configuration node. */
  DUMP_NODE,			/* Packet dump node. */
  FORWARDING_NODE,		/* IP forwarding node. */
  VTY_NODE,			/* Vty node. */
  MNDP_NODE,			/* MNDP node. */
};

enum vty_status {VTY_NORMAL, VTY_CLOSE, VTY_MORE, VTY_MORELINE,
		 VTY_START, VTY_CONTINUE};

/* VTY struct. */
struct vty 
{
  /* File descripter of this vty. */
  int fd;

  /* Is this vty connect to file or not */
  enum vty_type type;

  /* Node status of this vty */
  enum node_type node;
  //int node;

  /* What address is this vty comming from. */
  char *address;

  /* Privilege level of this vty. */
  int privilege;

  /* Failure count */
  int fail;

  /* Output buffer. */
  struct buffer *obuf;

  /* Command input buffer */
  char *buf;

  /* Command cursor point */
  int cp;

  /* Command length */
  int length;

  /* Command max length. */
  int max;

  /* Histry of command */
  char *hist[VTY_MAXHIST];

  /* History lookup current point */
  int hp;

  /* History insert end point */
  int hindex;

  /* For current referencing point of interface, route-map,
     access-list etc... */
  void *index;

  /* For multiple level index treatment such as key chain and key. */
  void *index_sub;

  /* For escape character. */
  unsigned char escape;

  /* Current vty status. */
  enum vty_status status;

  /* IAC handling */
  unsigned char iac;

  /* IAC SB handling */
  unsigned char iac_sb_in_progress;
  struct buffer *sb_buffer;

  /* Window width/height. */
  int width;
  int height;

  int scroll_one;

  /* Configure lines. */
  int lines;

  /* Current executing function pointer. */
  int (*func) (struct vty *, void *arg);

  /* Terminal monitor. */
  int monitor;

  /* In configure mode. */
  int config;

  /* Read and write thread. */
  struct thread *t_read;
  struct thread *t_write;

  /* Timeout seconds and thread. */
  unsigned long v_timeout;
  struct thread *t_timeout;

  /* Thread output function. */
  struct thread *t_output;

  /* Output data pointer. */
  int (*output_func) (struct vty *, int);
  void (*output_clean) (struct vty *);
  void *output_rn;
  unsigned long output_count;
  int output_type;
  void *output_arg;
};

/* Integrated configuration file. */
#define INTEGRATE_DEFAULT_CONFIG "Zebra.conf"

/* Small macro to determine newline is newline only or linefeed needed. */
#define VTY_NEWLINE  ((vty->type == VTY_TERM) ? "\r\n" : "\n")

/* Default time out value */
#define VTY_TIMEOUT_DEFAULT 600

/* Vty read buffer size. */
#define VTY_READ_BUFSIZ 512

/* Directory separator. */
#ifndef DIRECTORY_SEP
#define DIRECTORY_SEP '/'
#endif /* DIRECTORY_SEP */

#ifndef IS_DIRECTORY_SEP
#define IS_DIRECTORY_SEP(c) ((c) == DIRECTORY_SEP)
#endif

/* GCC have printf type attribute check.  */
#ifdef __GNUC__
#define PRINTF_ATTRIBUTE(a,b) __attribute__ ((__format__ (__printf__, a, b)))
#else
#define PRINTF_ATTRIBUTE(a,b)
#endif /* __GNUC__ */

/* Utility macro to convert VTY argument to unsigned integer.  */
#define VTY_GET_INTEGER(NAME,V,STR)                              \
{                                                                \
  char *endptr = NULL;                                           \
  (V) = strtoul ((STR), &endptr, 10);                            \
  if ((V) == ULONG_MAX || *endptr != '\0')                       \
    {                                                            \
      vty_out (vty, "%% Invalid %s value%s", NAME, VTY_NEWLINE); \
      return CMD_WARNING;                                        \
    }                                                            \
}

#define VTY_GET_INTEGER_MIN_RANGE(NAME,V,STR,MIN)                \
{                                                                \
  char *endptr = NULL;                                           \
  (V) = strtoul ((STR), &endptr, 10);                            \
  if (*endptr != '\0'                                            \
      || (V) < (MIN))                                            \
    {                                                            \
      vty_out (vty, "%% Invalid %s value%s", NAME, VTY_NEWLINE); \
      return CMD_WARNING;                                        \
    }                                                            \
}

#define VTY_GET_INTEGER_WITHOUT_CHECK(NAME,V,STR)                \
{                                                                \
  char *endptr = NULL;                                           \
  (V) = strtoul ((STR), &endptr, 10);                            \
  if (*endptr != '\0')                                           \
    {                                                            \
      vty_out (vty, "%% Invalid %s value%s", NAME, VTY_NEWLINE); \
      return CMD_WARNING;                                        \
    }                                                            \
}

#define VTY_GET_INTEGER_RANGE(NAME,V,STR,MIN,MAX)                \
{                                                                \
  char *endptr = NULL;                                           \
  (V) = strtoul ((STR), &endptr, 10);                            \
  if ((V) == ULONG_MAX || *endptr != '\0'                        \
      || (V) < (MIN) || (V) > (MAX))                             \
    {                                                            \
      vty_out (vty, "%% Invalid %s value%s", NAME, VTY_NEWLINE); \
      return CMD_WARNING;                                        \
    }                                                            \
}

/* Exported variables */
extern char integrate_default[];

/* Prototypes. */
void vty_init (void);
void vty_init_vtysh (void);
void vty_reset (void);
void vty_finish (void);
struct vty *vty_new (void);
int vty_out (struct vty *, const char *, ...) PRINTF_ATTRIBUTE(2, 3);
void vty_read_config (char *, char *, char *);
void vty_time_print (struct vty *, int);
void vty_serv_sock (const char *, unsigned short, char *);
void vty_close (struct vty *);
char *vty_get_cwd (void);
void vty_log (const char *, const char *, va_list);
int vty_config_lock (struct vty *);
int vty_config_unlock (struct vty *);
int vty_shell (struct vty *);
int vty_shell_serv (struct vty *);
void vty_hello (struct vty *);

#endif /* _ZEBRA_VTY_H */
