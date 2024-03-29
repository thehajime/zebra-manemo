/* Thread management routine header.
   Copyright (C) 1998 Kunihiro Ishiguro.

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

#ifndef _ZEBRA_THREAD_H
#define _ZEBRA_THREAD_H

#ifdef HAVE_RUSAGE
#define RUSAGE_T        struct rusage
#define GETRUSAGE(X)    getrusage (RUSAGE_SELF, X);
#else
#define RUSAGE_T        struct timeval
#define GETRUSAGE(X)    gettimeofday (X, NULL);
#endif /* HAVE_RUSAGE */

/* Linked list of thread. */
struct thread_list
{
  struct thread *head;
  struct thread *tail;
  int count;
};

/* Master of the theads. */
struct thread_master
{
  struct thread_list read;
  struct thread_list write;
  struct thread_list timer;
  struct thread_list event;
  struct thread_list ready;
  struct thread_list unuse;
  fd_set readfd;
  fd_set writefd;
  fd_set exceptfd;
  unsigned long alloc;
};

/* Thread itself. */
struct thread
{
  unsigned char type;		/* thread type */
  struct thread *next;		/* next pointer of the thread */
  struct thread *prev;		/* previous pointer of the thread */
  struct thread_master *master;	/* pointer to the struct thread_master. */
  int (*func) (struct thread *); /* event function */
  void *arg;			/* event argument */
  union {
    int val;			/* second argument of the event. */
    int fd;			/* file descriptor in case of read/write. */
    struct timeval sands;	/* rest of time sands value. */
  } u;
  RUSAGE_T ru;			/* Indepth usage info.  */
};

/* Thread types. */
#define THREAD_READ           0
#define THREAD_WRITE          1
#define THREAD_TIMER          2
#define THREAD_EVENT          3
#define THREAD_READY          4
#define THREAD_UNUSED         5

/* Thread yield time.  */
#define THREAD_YIELD_TIME_SLOT     100 * 1000L /* 100ms */

/* Macros. */
#define THREAD_ARG(X) ((X)->arg)
#define THREAD_FD(X)  ((X)->u.fd)
#define THREAD_VAL(X) ((X)->u.val)

#define THREAD_READ_ON(master,thread,func,arg,sock) \
  do { \
    if (! thread) \
      thread = thread_add_read (master, func, arg, sock); \
  } while (0)

#define THREAD_WRITE_ON(master,thread,func,arg,sock) \
  do { \
    if (! thread) \
      thread = thread_add_write (master, func, arg, sock); \
  } while (0)

#define THREAD_TIMER_ON(master,thread,func,arg,time) \
  do { \
    if (! thread) \
      thread = thread_add_timer (master, func, arg, time); \
  } while (0)

#define THREAD_OFF(thread) \
  do { \
    if (thread) \
      { \
        thread_cancel (thread); \
        thread = NULL; \
      } \
  } while (0)

#define THREAD_READ_OFF(thread)  THREAD_OFF(thread)
#define THREAD_WRITE_OFF(thread)  THREAD_OFF(thread)
#define THREAD_TIMER_OFF(thread)  THREAD_OFF(thread)

/* Prototypes. */
struct thread_master *thread_master_create ();
struct thread *thread_add_read (struct thread_master *, 
				int (*)(struct thread *), void *, int);
struct thread *thread_add_write (struct thread_master *,
				 int (*)(struct thread *), void *, int);
struct thread *thread_add_timer (struct thread_master *,
				 int (*)(struct thread *), void *, long);
struct thread *thread_add_event (struct thread_master *,
				 int (*)(struct thread *), void *, int );
void thread_cancel (struct thread *);
void thread_cancel_event (struct thread_master *, void *);

struct thread *thread_fetch (struct thread_master *, struct thread *);
struct thread *thread_execute (struct thread_master *,
			       int (*)(struct thread *), void *, int);
void thread_call (struct thread *);
char *thread_timer_remain_second (struct thread *);

#endif /* _ZEBRA_THREAD_H */
