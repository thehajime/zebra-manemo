/* 
 * API interface for external application
 *
 * $Id: td_api.c,v 405be77ba4f3 2009/03/19 14:38:58 tazaki $
 *
 * Copyright (c) 2008 {TBD}
 *
 * Author: Hajime TAZAKI  (tazaki@sfc.wide.ad.jp)
 *
 */

#include <zebra.h>
#include <sys/un.h>

#ifdef HAVE_SHISA
#include "linklist.h"
#include "thread.h"
#include "log.h"
#include "vty.h"
#include "if.h"
#include "prefix.h"

#include "rib.h"
#include "td.h"
#include "td_api.h"

int api_sock = 0;
extern struct thread_master *master;
extern struct prefix_ipv6 def_route;
static int peer_sock;

static int
api_notify_td_depth(int sock)
{
  char obuf[256];
  struct api_cmd *rep;
  int ret;

  rep = (struct api_cmd *)obuf;
  memset(rep, 0, sizeof(struct api_cmd));
  rep->cmd = MNDP_API_TD_GET_MR_DEPTH;
  rep->len = sizeof(struct api_cmd) + sizeof(td->tio.depth);

  memcpy(obuf + sizeof(struct api_cmd), &td->tio.depth, sizeof(td->tio.depth));

  ret = write(sock, obuf, rep->len);
  if(ret < 0)
    {
      zlog_warn("api: write %s", strerror(errno));
      return -1;
    }
  return 0;
}

int
api_notify_td_depth_all()
{
  /* fixme */
  api_notify_td_depth(peer_sock);
  return 0;
}

static int
api_parse(int sock, char *buf, int len)
{
  struct api_cmd *req;
  char abuf[INET6_ADDRSTRLEN];
  int ifindex;

  req = (struct api_cmd *)buf;

  switch(req->cmd)
    {
    case MNDP_API_TD_GET_MR_DEPTH:
      api_notify_td_depth(sock);
      break;
    case MNDP_API_TD_SET_HOA:
      memcpy(td->tio.tree_id, (buf + sizeof(struct api_cmd)), 
             sizeof(td->tio.tree_id));
      zlog_info("Notified HoA as TreeID (%s)", 
           inet_ntop(AF_INET6, &td->tio.tree_id, abuf, sizeof(abuf)));
      break;
    case MNDP_API_TD_ADD_ROUTE:
	    ifindex = *(int *)(buf + sizeof(struct api_cmd));
	    rib_add_ipv6(ZEBRA_ROUTE_SHISA, 0, &def_route, NULL,
		ifindex, 0);
	    zlog_info("SHISA route add ifindex=%d", ifindex);
      break;
    case MNDP_API_TD_DEL_ROUTE:
	    ifindex = *(int *)(buf + sizeof(struct api_cmd));
	    rib_delete_ipv6(ZEBRA_ROUTE_SHISA, 0, &def_route, NULL,
		ifindex, 0);
	    zlog_info("SHISA route delete ifindex=%d", ifindex);
      break;
    default:
      break;
    }

  return 0;
}

int
api_read(struct thread *thread)
{
  int sock;
  char buf[256];
  int ret;

  sock = thread->u.fd;

  ret = read(sock, buf, sizeof(buf));
  if(ret <= 0)
    {
      if(ret != 0)
        zlog_warn("api sock broken. %s", strerror(errno));
      close(sock);
      return 0;
    }

  thread_add_read(master, api_read, NULL, sock);

  api_parse(sock, buf, ret);

  return 0;
}


int
api_accept(struct thread *thread)
{
  int api_sock;
  struct sockaddr_un addr;
  socklen_t len;

  api_sock = thread->u.fd;
  thread_add_read(master, api_accept, NULL, api_sock);

  len = sizeof(addr);
  peer_sock = accept(api_sock, (struct sockaddr *)&addr, &len);
  if(peer_sock < 0)
    {
      zlog_warn("api: accept failed(%s)", strerror(errno));
      return -1;
    }

  thread_add_read(master, api_read, NULL, peer_sock);

  return 0;
}

int
api_init(char *path)
{
  struct sockaddr_un serv;
  mode_t old_mask;
  size_t len;
  int ret;

  unlink(path);
  old_mask = umask(0077);

  api_sock = socket(AF_UNIX, SOCK_STREAM, 0);
  if(!api_sock)
    {
      zlog_warn("socket %s", strerror(errno));
      return -1;
    }

  memset(&serv, 0, sizeof(struct sockaddr_un));
  serv.sun_family = AF_UNIX;
  strncpy(serv.sun_path, path, strlen(path));
#if 0
#ifdef HAVE_SUN_LEN
  len = serv.sun_len = SUN_LEN(&serv);
#else
  len = sizeof (serv.sun_family) + strlen (serv.sun_path);
#endif /* HAVE_SUN_LEN */
#endif
#ifdef HAVE_SUN_LEN
  len = serv.sun_len = SUN_LEN(&serv);
#else
  len = sizeof (serv.sun_family) + strlen (serv.sun_path);
#endif /* HAVE_SUN_LEN */

  ret = bind(api_sock, (struct sockaddr *)&serv, len);
  if(ret < 0)
    {
      zlog_warn("bind %s", strerror(errno));
      close(api_sock);
      return -1;
    }

  ret = listen(api_sock, 5);
  if(ret < 0)
    {
      zlog_warn("listen %s", strerror(errno));
      close(api_sock);
      return -1;
    }

  umask(old_mask);

  thread_add_read(master, api_accept, NULL, api_sock);

  return 0;
}

int
api_term()
{
  return 0;
}

#endif /* HAVE_SHISA */
