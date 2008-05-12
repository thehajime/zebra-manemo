/* Generic linked list.
   Copyright (C) 1997, 2000 Kunihiro Ishiguro.

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

#ifndef _ZEBRA_LINKLIST_H
#define _ZEBRA_LINKLIST_H

struct listnode 
{
  struct listnode *next;
  struct listnode *prev;
  void *data;
};

struct list 
{
  struct listnode *head;
  struct listnode *tail;
  unsigned int count;
  int (*cmp) (void *val1, void *val2);
  void (*del) (void *val);
};

#define listnextnode(X) ((X)->next)
#define nextnode(X) ((X) = (X)->next)
#define listhead(X) ((X)->head)
#define listcount(X) ((X)->count)
#define list_isempty(X) ((X)->head == NULL && (X)->tail == NULL)
#define listgetdata(X) (assert((X)->data != NULL), (X)->data)
#define getdata(X) ((X)->data)

/* Prototypes. */
struct list *list_new();
void list_free (struct list *);

void listnode_add (struct list *, void *);
void listnode_add_sort (struct list *, void *);
void listnode_add_after (struct list *, struct listnode *, void *);
void listnode_delete (struct list *, void *);
struct listnode *listnode_lookup (struct list *, void *);
void *listnode_head (struct list *);

void list_delete (struct list *);
void list_delete_all_node (struct list *);

/* For ospfd and ospf6d. */
void list_delete_node (struct list *, struct listnode *);

/* For ospf_spf.c */
void list_add_node_prev (struct list *, struct listnode *, void *);
void list_add_node_next (struct list *, struct listnode *, void *);
void list_add_list (struct list *, struct list *);

/* List iteration macro. 
 * Usage: for (ALL_LIST_ELEMENTS (...) { ... }
 * It is safe to delete the listnode using this macro.
 */
#define ALL_LIST_ELEMENTS(list,node,nextnode,data) \
  (node) = listhead(list); \
  (node) != NULL && \
    ((data) = listgetdata(node),(nextnode) = listnextnode(node), 1); \
  (node) = (nextnode)

/* List iteration macro. */
#define LIST_LOOP(L,V,N) \
  for ((N) = (L)->head; (N); (N) = (N)->next) \
    if (((V) = (N)->data) != NULL)

/* List node add macro.  */
#define LISTNODE_ADD(L,N) \
  do { \
    (N)->prev = (L)->tail; \
    if ((L)->head == NULL) \
      (L)->head = (N); \
    else \
      (L)->tail->next = (N); \
    (L)->tail = (N); \
  } while (0)

/* List node delete macro.  */
#define LISTNODE_DELETE(L,N) \
  do { \
    if ((N)->prev) \
      (N)->prev->next = (N)->next; \
    else \
      (L)->head = (N)->next; \
    if ((N)->next) \
      (N)->next->prev = (N)->prev; \
    else \
      (L)->tail = (N)->prev; \
  } while (0)

#endif /* _ZEBRA_LINKLIST_H */
