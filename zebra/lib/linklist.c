/* Generic linked list routine.
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

#include <zebra.h>

#include "linklist.h"
#include "memory.h"

/* Allocate new list. */
struct list *
list_new ()
{
  struct list *list;

  list = (struct list *) XMALLOC (MTYPE_LINK_LIST, sizeof (struct list));
  memset (list, 0, sizeof (struct list));
  return list;
}

/* Free list. */
void
list_free (struct list *l)
{
  XFREE (MTYPE_LINK_LIST, l);
}

/* Allocate new listnode.  Internal use only. */
static struct listnode *
listnode_new ()
{
  struct listnode *node;

  node = (struct listnode *) XMALLOC (MTYPE_LINK_NODE,
				      sizeof (struct listnode));
  memset (node, 0, sizeof (struct listnode));
  return node;
}

/* Free listnode. */
static void
listnode_free (struct listnode *node)
{
  XFREE (MTYPE_LINK_NODE, node);
}

/* Add new data to the list. */
void
listnode_add (struct list *list, void *val)
{
  struct listnode *node;

  node = listnode_new ();

  node->prev = list->tail;
  node->data = val;

  if (list->head == NULL)
    list->head = node;
  else
    list->tail->next = node;
  list->tail = node;

  list->count++;
}

/* Add new node with sort function. */
void
listnode_add_sort (struct list *list, void *val)
{
  struct listnode *n;
  struct listnode *alloc;

  alloc = listnode_new ();
  alloc->data = val;

  if (list->cmp)
    {
      for (n = list->head; n; n = n->next)
	{
	  if ((*list->cmp) (val, n->data) < 0)
	    {	    
	      alloc->next = n;
	      alloc->prev = n->prev;

	      if (n->prev)
		n->prev->next = alloc;
	      else
		list->head = alloc;
	      n->prev = alloc;
	      list->count++;
	      return;
	    }
	}
    }

  alloc->prev = list->tail;

  if (list->tail)
    list->tail->next = alloc;
  else
    list->head = alloc;

  list->tail = alloc;
  list->count++;
}

void
listnode_add_after (struct list *list, struct listnode *pp, void *val)
{
  struct listnode *nn;

  nn = listnode_new ();
  nn->data = val;

  if (pp == NULL)
    {
      if (list->head)
	list->head->prev = nn;
      else
	list->tail = nn;

      nn->next = list->head;
      nn->prev = pp;

      list->head = nn;
    }
  else
    {
      if (pp->next)
	pp->next->prev = nn;
      else
	list->tail = nn;

      nn->next = pp->next;
      nn->prev = pp;

      pp->next = nn;
    }
}


/* Delete specific date pointer from the list. */
void
listnode_delete (struct list *list, void *val)
{
  struct listnode *node;

  for (node = list->head; node; node = node->next)
    {
      if (node->data == val)
	{
	  if (node->prev)
	    node->prev->next = node->next;
	  else
	    list->head = node->next;

	  if (node->next)
	    node->next->prev = node->prev;
	  else
	    list->tail = node->prev;

	  list->count--;
	  listnode_free (node);
	  return;
	}
    }
}

/* Return first node's data if it is there.  */
void *
listnode_head (struct list *list)
{
  struct listnode *node;

  node = list->head;

  if (node)
    return node->data;
  return NULL;
}

/* Delete all listnode from the list. */
void
list_delete_all_node (struct list *list)
{
  struct listnode *node;
  struct listnode *next;

  for (node = list->head; node; node = next)
    {
      next = node->next;
      if (list->del)
	(*list->del) (node->data);
      listnode_free (node);
    }
  list->head = list->tail = NULL;
  list->count = 0;
}

/* Delete all listnode then free list itself. */
void
list_delete (struct list *list)
{
  struct listnode *node;
  struct listnode *next;

  for (node = list->head; node; node = next)
    {
      next = node->next;
      if (list->del)
	(*list->del) (node->data);
      listnode_free (node);
    }
  list_free (list);
}

/* Lookup the node which has given data. */
struct listnode *
listnode_lookup (struct list *list, void *data)
{
  struct listnode *node;

  for (node = list->head; node; nextnode (node))
    if (data == getdata (node))
      return node;
  return NULL;
}

/* Delete the node from list.  For ospfd and ospf6d. */
void
list_delete_node (struct list *list, struct listnode *node)
{
  if (node->prev)
    node->prev->next = node->next;
  else
    list->head = node->next;
  if (node->next)
    node->next->prev = node->prev;
  else
    list->tail = node->prev;
  list->count--;
  listnode_free (node);
}

/* ospf_spf.c */
void
list_add_node_prev (struct list *list, struct listnode *current, void *val)
{
  struct listnode *node;

  node = listnode_new ();
  node->next = current;
  node->data = val;

  if (current->prev == NULL)
    list->head = node;
  else
    current->prev->next = node;

  node->prev = current->prev;
  current->prev = node;

  list->count++;
}

/* ospf_spf.c */
void
list_add_node_next (struct list *list, struct listnode *current, void *val)
{
  struct listnode *node;

  node = listnode_new ();
  node->prev = current;
  node->data = val;

  if (current->next == NULL)
    list->tail = node;
  else
    current->next->prev = node;

  node->next = current->next;
  current->next = node;

  list->count++;
}

/* ospf_spf.c */
void
list_add_list (struct list *l, struct list *m)
{
  struct listnode *n;

  for (n = listhead (m); n; nextnode (n))
    listnode_add (l, n->data);
}
