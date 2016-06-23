/*
 * Copyright (c) 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)queue.h	8.5 (Berkeley) 8/20/94
 */

#ifndef	_SYS_QUEUE_H_
#define	_SYS_QUEUE_H_

#include "platform.h"
#include "rna_common_logging.h"

/*
 * This file defines five types of data structures: singly-linked lists,
 * lists, simple queues, tail queues, and circular queues.
 *
 * A singly-linked list is headed by a single forward pointer. The
 * elements are singly linked for minimum space and pointer manipulation
 * overhead at the expense of O(n) removal for arbitrary elements. New
 * elements can be added to the list after an existing element or at the
 * head of the list.  Elements being removed from the head of the list
 * should use the explicit macro for this purpose for optimum
 * efficiency. A singly-linked list may only be traversed in the forward
 * direction.  Singly-linked lists are ideal for applications with large
 * datasets and few or no removals or for implementing a LIFO queue.
 *
 * A list is headed by a single forward pointer (or an array of forward
 * pointers for a hash table header). The elements are doubly linked
 * so that an arbitrary element can be removed without a need to
 * traverse the list. New elements can be added to the list before
 * or after an existing element or at the head of the list. A list
 * may only be traversed in the forward direction.
 *
 * A simple queue is headed by a pair of pointers, one the head of the
 * list and the other to the tail of the list. The elements are singly
 * linked to save space, so elements can only be removed from the
 * head of the list. New elements can be added to the list after
 * an existing element, at the head of the list, or at the end of the
 * list. A simple queue may only be traversed in the forward direction.
 *
 * A tail queue is headed by a pair of pointers, one to the head of the
 * list and the other to the tail of the list. The elements are doubly
 * linked so that an arbitrary element can be removed without a need to
 * traverse the list. New elements can be added to the list before or
 * after an existing element, at the head of the list, or at the end of
 * the list. A tail queue may be traversed in either direction.
 *
 * A circle queue is headed by a pair of pointers, one to the head of the
 * list and the other to the tail of the list. The elements are doubly
 * linked so that an arbitrary element can be removed without a need to
 * traverse the list. New elements can be added to the list before or after
 * an existing element, at the head of the list, or at the end of the list.
 * A circle queue may be traversed in either direction, but has a more
 * complex end of list detection.
 *
 * For details on the use of these macros, see the queue(3) manual page.
 */

/*
 * List definitions.
 */
#define	LIST_HEAD(name, type)						\
struct name {								\
	struct type *lh_first;	/* first element */			\
}

#define	LIST_HEAD_INITIALIZER(head)					\
	{ NULL }

#define	LIST_ENTRY(type)						\
struct {								\
	struct type *le_next;	/* next element */			\
	struct type **le_prev;	/* address of previous next element */	\
}

#define LIST_ENTRY_EMPTY(elm, field) \
    ((NULL == (elm)->field.le_next && (NULL == (elm)->field.le_prev)))

/*
 * List functions.
 */
#define	LIST_INIT(head) do {						\
	(head)->lh_first = NULL;					\
} while (/*CONSTCOND*/0)

#define	LIST_INSERT_AFTER(listelm, elm, field) do {			\
	rna_debug_log_assert((elm) != (listelm));   \
	if (((elm)->field.le_next = (listelm)->field.le_next) != NULL)	\
		(listelm)->field.le_next->field.le_prev =		\
		    &(elm)->field.le_next;				\
	(listelm)->field.le_next = (elm);				\
	(elm)->field.le_prev = &(listelm)->field.le_next;		\
} while (/*CONSTCOND*/0)

#define	LIST_INSERT_BEFORE(listelm, elm, field) do {			\
	rna_debug_log_assert((elm) != (listelm));   \
	(elm)->field.le_prev = (listelm)->field.le_prev;		\
	(elm)->field.le_next = (listelm);				\
	*(listelm)->field.le_prev = (elm);				\
	(listelm)->field.le_prev = &(elm)->field.le_next;		\
} while (/*CONSTCOND*/0)

#define	LIST_INSERT_HEAD(head, elm, field) do {				\
	rna_debug_log_assert((head)->lh_first != (elm));		\
	if (((elm)->field.le_next = (head)->lh_first) != NULL)		\
		(head)->lh_first->field.le_prev = &(elm)->field.le_next;\
	(head)->lh_first = (elm);					\
	(elm)->field.le_prev = &(head)->lh_first;			\
} while (/*CONSTCOND*/0)

#define	LIST_REMOVE(elm, field) do {					\
	if ((elm)->field.le_next != NULL)				\
		(elm)->field.le_next->field.le_prev = 			\
		    (elm)->field.le_prev;				\
	*(elm)->field.le_prev = (elm)->field.le_next;			\
	(elm)->field.le_prev = NULL;    \
    (elm)->field.le_next = NULL;	\
} while (/*CONSTCOND*/0)

#if defined(_RNA_DBG_ASSERT_)
#define	LIST_FOREACH(var, head, field)					\
	for ((var) = ((head)->lh_first);				\
		(var);							\
		rna_debug_log_assert((var) != ((var)->field.le_next)),	\
		(var) = ((var)->field.le_next))
#else
#define	LIST_FOREACH(var, head, field)					\
	for ((var) = ((head)->lh_first);				\
		(var);							\
		(var) = ((var)->field.le_next))
#endif

#define	LIST_FOREACH_SAFE(var, next_var, head, field)                       \
	for ((var) = ((head)->lh_first),                                        \
         (next_var) = (NULL == (var))?NULL:(var)->field.le_next;           \
		 (var);                                                             \
		 (var) = (next_var),                                                \
         (next_var) = (NULL == (next_var))?NULL:(next_var)->field.le_next)

/*
 * List access methods.
 */
#define	LIST_EMPTY(head)		((head)->lh_first == NULL)
#define	LIST_FIRST(head)		((head)->lh_first)
#define	LIST_NEXT(elm, field)	((elm)->field.le_next)


/*
 * Singly-linked List definitions.
 */
#define	SLIST_HEAD(name, type)						\
struct name {								\
	struct type *slh_first;	/* first element */			\
}

#define	SLIST_HEAD_INITIALIZER(head)					\
	{ NULL }

#define	SLIST_ENTRY(type)						\
struct {								\
	struct type *sle_next;	/* next element */			\
}

/*
 * Singly-linked List functions.
 */
#define	SLIST_INIT(head) do {						\
	(head)->slh_first = NULL;					\
} while (/*CONSTCOND*/0)

#define	SLIST_INSERT_AFTER(slistelm, elm, field) do {			\
	(elm)->field.sle_next = (slistelm)->field.sle_next;		\
	(slistelm)->field.sle_next = (elm);				\
} while (/*CONSTCOND*/0)

#define	SLIST_INSERT_HEAD(head, elm, field) do {			\
	(elm)->field.sle_next = (head)->slh_first;			\
	(head)->slh_first = (elm);					\
} while (/*CONSTCOND*/0)

#define	SLIST_REMOVE_HEAD(head, field) do {				\
	(head)->slh_first = (head)->slh_first->field.sle_next;		\
} while (/*CONSTCOND*/0)

#define	SLIST_REMOVE(head, elm, type, field) do {			\
	if ((head)->slh_first == (elm)) {				\
		SLIST_REMOVE_HEAD((head), field);			\
	}								\
	else {								\
		struct type *curelm = (head)->slh_first;		\
		while(curelm->field.sle_next != (elm))			\
			curelm = curelm->field.sle_next;		\
		curelm->field.sle_next =				\
		    curelm->field.sle_next->field.sle_next;		\
	}								\
} while (/*CONSTCOND*/0)

#define	SLIST_FOREACH(var, head, field)					\
	for((var) = (head)->slh_first; (var); (var) = (var)->field.sle_next)

/*
 * Singly-linked List access methods.
 */
#define	SLIST_EMPTY(head)	((head)->slh_first == NULL)
#define	SLIST_FIRST(head)	((head)->slh_first)
#define	SLIST_NEXT(elm, field)	((elm)->field.sle_next)


/*
 * Singly-linked Tail queue declarations.
 */
#define	STAILQ_HEAD(name, type)					\
struct name {								\
	struct type *stqh_first;	/* first element */			\
	struct type **stqh_last;	/* addr of last next element */		\
}

#define	STAILQ_HEAD_INITIALIZER(head)					\
	{ NULL, &(head).stqh_first }

#define	STAILQ_ENTRY(type)						\
struct {								\
	struct type *stqe_next;	/* next element */			\
}

/*
 * Singly-linked Tail queue functions.
 */
#define	STAILQ_INIT(head) do {						\
	(head)->stqh_first = NULL;					\
	(head)->stqh_last = &(head)->stqh_first;				\
} while (/*CONSTCOND*/0)

#define	STAILQ_INSERT_HEAD(head, elm, field) do {			\
	if (((elm)->field.stqe_next = (head)->stqh_first) == NULL)	\
		(head)->stqh_last = &(elm)->field.stqe_next;		\
	(head)->stqh_first = (elm);					\
} while (/*CONSTCOND*/0)

#define	STAILQ_INSERT_TAIL(head, elm, field) do {			\
	(elm)->field.stqe_next = NULL;					\
	*(head)->stqh_last = (elm);					\
	(head)->stqh_last = &(elm)->field.stqe_next;			\
} while (/*CONSTCOND*/0)

#define	STAILQ_INSERT_AFTER(head, listelm, elm, field) do {		\
	if (((elm)->field.stqe_next = (listelm)->field.stqe_next) == NULL)\
		(head)->stqh_last = &(elm)->field.stqe_next;		\
	(listelm)->field.stqe_next = (elm);				\
} while (/*CONSTCOND*/0)

#define	STAILQ_REMOVE_HEAD(head, field) do {				\
	if (((head)->stqh_first = (head)->stqh_first->field.stqe_next) == NULL) \
		(head)->stqh_last = &(head)->stqh_first;			\
} while (/*CONSTCOND*/0)

#define	STAILQ_REMOVE(head, elm, type, field) do {			\
	if ((head)->stqh_first == (elm)) {				\
		STAILQ_REMOVE_HEAD((head), field);			\
	} else {							\
		struct type *curelm = (head)->stqh_first;		\
		while (curelm->field.stqe_next != (elm))			\
			curelm = curelm->field.stqe_next;		\
		if ((curelm->field.stqe_next =				\
			curelm->field.stqe_next->field.stqe_next) == NULL) \
			    (head)->stqh_last = &(curelm)->field.stqe_next; \
	}								\
} while (/*CONSTCOND*/0)

#define	STAILQ_FOREACH(var, head, field)				\
	for ((var) = ((head)->stqh_first);				\
		(var);							\
		(var) = ((var)->field.stqe_next))

/*
 * Singly-linked Tail queue access methods.
 */
#define	STAILQ_EMPTY(head)	((head)->stqh_first == NULL)
#define	STAILQ_FIRST(head)	((head)->stqh_first)
#define	STAILQ_NEXT(elm, field)	((elm)->field.stqe_next)


/*
 * Simple queue definitions.
 */
#define	SIMPLEQ_HEAD(name, type)					\
struct name {								\
	struct type *sqh_first;	/* first element */			\
	struct type **sqh_last;	/* addr of last next element */		\
}

#define	SIMPLEQ_HEAD_INITIALIZER(head)					\
	{ NULL, &(head).sqh_first }

#define	SIMPLEQ_ENTRY(type)						\
struct {								\
	struct type *sqe_next;	/* next element */			\
}

/*
 * Simple queue functions.
 */
#define	SIMPLEQ_INIT(head) do {						\
	(head)->sqh_first = NULL;					\
	(head)->sqh_last = &(head)->sqh_first;				\
} while (/*CONSTCOND*/0)

#define	SIMPLEQ_INSERT_HEAD(head, elm, field) do {			\
	if (((elm)->field.sqe_next = (head)->sqh_first) == NULL)	\
		(head)->sqh_last = &(elm)->field.sqe_next;		\
	(head)->sqh_first = (elm);					\
} while (/*CONSTCOND*/0)

#define	SIMPLEQ_INSERT_TAIL(head, elm, field) do {			\
	(elm)->field.sqe_next = NULL;					\
	*(head)->sqh_last = (elm);					\
	(head)->sqh_last = &(elm)->field.sqe_next;			\
} while (/*CONSTCOND*/0)

#define	SIMPLEQ_INSERT_AFTER(head, listelm, elm, field) do {		\
	if (((elm)->field.sqe_next = (listelm)->field.sqe_next) == NULL)\
		(head)->sqh_last = &(elm)->field.sqe_next;		\
	(listelm)->field.sqe_next = (elm);				\
} while (/*CONSTCOND*/0)

#define	SIMPLEQ_REMOVE_HEAD(head, field) do {				\
	if (((head)->sqh_first = (head)->sqh_first->field.sqe_next) == NULL) \
		(head)->sqh_last = &(head)->sqh_first;			\
} while (/*CONSTCOND*/0)

#define	SIMPLEQ_REMOVE(head, elm, type, field) do {			\
	if ((head)->sqh_first == (elm)) {				\
		SIMPLEQ_REMOVE_HEAD((head), field);			\
	} else {							\
		struct type *curelm = (head)->sqh_first;		\
		while (curelm->field.sqe_next != (elm))			\
			curelm = curelm->field.sqe_next;		\
		if ((curelm->field.sqe_next =				\
			curelm->field.sqe_next->field.sqe_next) == NULL) \
			    (head)->sqh_last = &(curelm)->field.sqe_next; \
	}								\
} while (/*CONSTCOND*/0)

#define	SIMPLEQ_FOREACH(var, head, field)				\
	for ((var) = ((head)->sqh_first);				\
		(var);							\
		(var) = ((var)->field.sqe_next))

/*
 * Simple queue access methods.
 */
#define	SIMPLEQ_EMPTY(head)		((head)->sqh_first == NULL)
#define	SIMPLEQ_FIRST(head)		((head)->sqh_first)
#define	SIMPLEQ_NEXT(elm, field)	((elm)->field.sqe_next)


/*
 * Tail queue definitions.
 */
#define	_TAILQ_HEAD(name, type, qual)					\
struct name {								\
	qual type *tqh_first;		/* first element */		\
	qual type *qual *tqh_last;	/* addr of last next element */	\
}
#define TAILQ_HEAD(name, type)	_TAILQ_HEAD(name, struct type,)

#define	TAILQ_HEAD_INITIALIZER(head)					\
	{ NULL, &(head).tqh_first }

#define	_TAILQ_ENTRY(type, qual)					\
struct {								\
	qual type *tqe_next;		/* next element */		\
	qual type *qual *tqe_prev;	/* address of previous next element */\
}
#define TAILQ_ENTRY(type)	_TAILQ_ENTRY(struct type,)

/*
 * Tail queue functions.
 */
#define	TAILQ_INIT(head) do {						\
	(head)->tqh_first = NULL;					\
	(head)->tqh_last = &(head)->tqh_first;				\
} while (/*CONSTCOND*/0)

#define	TAILQ_INSERT_HEAD(head, elm, field) do {			\
	if (((elm)->field.tqe_next = (head)->tqh_first) != NULL)	\
		(head)->tqh_first->field.tqe_prev =			\
		    &(elm)->field.tqe_next;				\
	else								\
		(head)->tqh_last = &(elm)->field.tqe_next;		\
	(head)->tqh_first = (elm);					\
	(elm)->field.tqe_prev = &(head)->tqh_first;			\
} while (/*CONSTCOND*/0)

#define	TAILQ_INSERT_TAIL(head, elm, field) do {			\
	(elm)->field.tqe_next = NULL;					\
	(elm)->field.tqe_prev = (head)->tqh_last;			\
	*(head)->tqh_last = (elm);					\
	(head)->tqh_last = &(elm)->field.tqe_next;			\
} while (/*CONSTCOND*/0)

#define	TAILQ_INSERT_AFTER(head, listelm, elm, field) do {		\
	if (((elm)->field.tqe_next = (listelm)->field.tqe_next) != NULL)\
		(elm)->field.tqe_next->field.tqe_prev = 		\
		    &(elm)->field.tqe_next;				\
	else								\
		(head)->tqh_last = &(elm)->field.tqe_next;		\
	(listelm)->field.tqe_next = (elm);				\
	(elm)->field.tqe_prev = &(listelm)->field.tqe_next;		\
} while (/*CONSTCOND*/0)

#define	TAILQ_INSERT_BEFORE(listelm, elm, field) do {			\
	(elm)->field.tqe_prev = (listelm)->field.tqe_prev;		\
	(elm)->field.tqe_next = (listelm);				\
	*(listelm)->field.tqe_prev = (elm);				\
	(listelm)->field.tqe_prev = &(elm)->field.tqe_next;		\
} while (/*CONSTCOND*/0)

#define	TAILQ_REMOVE(head, elm, field) do {				\
	if (((elm)->field.tqe_next) != NULL)				\
		(elm)->field.tqe_next->field.tqe_prev = 		\
		    (elm)->field.tqe_prev;				\
	else								\
		(head)->tqh_last = (elm)->field.tqe_prev;		\
	*(elm)->field.tqe_prev = (elm)->field.tqe_next;			\
	(elm)->field.tqe_prev = NULL;   \
	(elm)->field.tqe_next = NULL;   \
} while (/*CONSTCOND*/0)

#define	TAILQ_FOREACH(var, head, field)					\
	for ((var) = ((head)->tqh_first);				\
		(var);							\
		(var) = ((var)->field.tqe_next))

/* This macro is safe to use for loops that may remove (var) from the list
 * TAILQ's forward links are NULL terminated.  So when this macro
 * advances the next_var, it must check for NULL.
 */
#define	TAILQ_FOREACH_SAFE(var, next_var, head, field)                        \
	for ((var) = ((head)->tqh_first),                                         \
         (next_var) = (NULL == (var))?NULL:(var)->field.tqe_next;             \
		 (var);                                                               \
		 (var) = (next_var),                                                  \
         (next_var) = (NULL == (next_var))?NULL:(next_var)->field.tqe_next)   \


#define	TAILQ_FOREACH_REVERSE(var, head, headname, field)		\
	for ((var) = (*(((struct headname *)((head)->tqh_last))->tqh_last));	\
		(var);							\
		(var) = (*(((struct headname *)((var)->field.tqe_prev))->tqh_last)))

/*
 * Tail queue access methods.
 */
#define	TAILQ_EMPTY(head)		((head)->tqh_first == NULL)
#define	TAILQ_FIRST(head)		((head)->tqh_first)
#define	TAILQ_NEXT(elm, field)		((elm)->field.tqe_next)

#define	TAILQ_LAST(head, headname) \
	(*(((struct headname *)((head)->tqh_last))->tqh_last))
#define	TAILQ_PREV(elm, headname, field) \
	(*(((struct headname *)((elm)->field.tqe_prev))->tqh_last))


/*
 * Circular queue definitions.
 */
#define	CIRCLEQ_HEAD(name, type)					\
struct name {								\
	struct type *cqh_first;		/* first element */		\
	struct type *cqh_last;		/* last element */		\
}

#define	CIRCLEQ_HEAD_INITIALIZER(head)					\
	{ (void *)&head, (void *)&head }

#define	CIRCLEQ_ENTRY(type)						\
struct {								\
	struct type *cqe_next;		/* next element */		\
	struct type *cqe_prev;		/* previous element */		\
}

/*
 * Circular queue functions.
 */
#define	CIRCLEQ_INIT(head) do {						\
	(head)->cqh_first = (void *)(head);				\
	(head)->cqh_last = (void *)(head);				\
} while (/*CONSTCOND*/0)

#define	CIRCLEQ_INSERT_AFTER(head, listelm, elm, field) do {		\
	(elm)->field.cqe_next = (listelm)->field.cqe_next;		\
	(elm)->field.cqe_prev = (listelm);				\
	if ((listelm)->field.cqe_next == (void *)(head))		\
		(head)->cqh_last = (elm);				\
	else								\
		(listelm)->field.cqe_next->field.cqe_prev = (elm);	\
	(listelm)->field.cqe_next = (elm);				\
} while (/*CONSTCOND*/0)

#define	CIRCLEQ_INSERT_BEFORE(head, listelm, elm, field) do {		\
	(elm)->field.cqe_next = (listelm);				\
	(elm)->field.cqe_prev = (listelm)->field.cqe_prev;		\
	if ((listelm)->field.cqe_prev == (void *)(head))		\
		(head)->cqh_first = (elm);				\
	else								\
		(listelm)->field.cqe_prev->field.cqe_next = (elm);	\
	(listelm)->field.cqe_prev = (elm);				\
} while (/*CONSTCOND*/0)

#define	CIRCLEQ_INSERT_HEAD(head, elm, field) do {			\
	(elm)->field.cqe_next = (head)->cqh_first;			\
	(elm)->field.cqe_prev = (void *)(head);				\
	if ((head)->cqh_last == (void *)(head))				\
		(head)->cqh_last = (elm);				\
	else								\
		(head)->cqh_first->field.cqe_prev = (elm);		\
	(head)->cqh_first = (elm);					\
} while (/*CONSTCOND*/0)

#define	CIRCLEQ_INSERT_TAIL(head, elm, field) do {			\
	(elm)->field.cqe_next = (void *)(head);				\
	(elm)->field.cqe_prev = (head)->cqh_last;			\
	if ((head)->cqh_first == (void *)(head))			\
		(head)->cqh_first = (elm);				\
	else								\
		(head)->cqh_last->field.cqe_next = (elm);		\
	(head)->cqh_last = (elm);					\
} while (/*CONSTCOND*/0)

#define	CIRCLEQ_REMOVE(head, elm, field) do {				\
	if ((elm)->field.cqe_next == (void *)(head))			\
		(head)->cqh_last = (elm)->field.cqe_prev;		\
	else								\
		(elm)->field.cqe_next->field.cqe_prev =			\
		    (elm)->field.cqe_prev;				\
	if ((elm)->field.cqe_prev == (void *)(head))			\
		(head)->cqh_first = (elm)->field.cqe_next;		\
	else								\
		(elm)->field.cqe_prev->field.cqe_next =			\
		    (elm)->field.cqe_next;				\
} while (/*CONSTCOND*/0)

#define	CIRCLEQ_FOREACH(var, head, field)				\
	for ((var) = ((head)->cqh_first);				\
		(var) != (const void *)(head);				\
		(var) = ((var)->field.cqe_next))

#define	CIRCLEQ_FOREACH_REVERSE(var, head, field)			\
	for ((var) = ((head)->cqh_last);				\
		(var) != (const void *)(head);				\
		(var) = ((var)->field.cqe_prev))

/*
 * Circular queue access methods.
 */
#define	CIRCLEQ_EMPTY(head)		((head)->cqh_first == (void *)(head))
#define	CIRCLEQ_FIRST(head)		((head)->cqh_first)
#define	CIRCLEQ_LAST(head)		((head)->cqh_last)
#define	CIRCLEQ_NEXT(elm, field)	((elm)->field.cqe_next)
#define	CIRCLEQ_PREV(elm, field)	((elm)->field.cqe_prev)

#define CIRCLEQ_LOOP_NEXT(head, elm, field)				\
	(((elm)->field.cqe_next == (void *)(head))			\
	    ? ((head)->cqh_first)					\
	    : (elm->field.cqe_next))
#define CIRCLEQ_LOOP_PREV(head, elm, field)				\
	(((elm)->field.cqe_prev == (void *)(head))			\
	    ? ((head)->cqh_last)					\
	    : (elm->field.cqe_prev))


/*
 * Macros to support doubly-linked circular queues.
 *
 * Apologies in advance for introducing yet another set of queuing macros.
 * Sometimes a need arises (as in rna_service) to be able to remove an element
 * from a list when it doesn't know what the head of the list is (so the TAILQ
 * macros aren't suitable), to insert an item either at the head or tail of a
 * list (so the LIST macros aren't suitable), and to merge the content of two
 * queues without traversing either queue (so again, the LIST macros aren't
 * suitable).
 *
 * When traversing a queue, one should always begin at its head, since the head
 * of a queue is indistinguishable from its elements, and one doesn't want to
 * inadvertently apply YAQ_OBJECT to a queue head rather than a queue
 * element.
 */


/*
 * A queue element serves as both the head of a queue and the linkage field
 * in a struct to be linked into a queue.
 */
typedef struct yaq_link_s {
    struct yaq_link_s *qe_next;
    struct yaq_link_s *qe_prev;
} yaq_link_t;


/*
 * Type for the head of a queue.
 */
#define YAQ_HEAD  yaq_link_t


/*
 * Type for a linkage element (embedded in a struct to be added to a queue).
 */
#define YAQ_LINK  yaq_link_t

/* This file is included at both user and kernel level */
#ifdef __KERNEL__
#define YAQ_DEBUG_ASSERT(expr)  BUG_ON(!(expr))
#else
#define YAQ_DEBUG_ASSERT(expr)  rna_debug_log_assert(expr)
#endif


/*
 * Static initialization for a queue head.
 *
 * Arguments:
 *    headp    Pointer to the head of a queue.
 */
#define YAQ_INITIALIZER(headp)  \
    {(headp), (headp)}


/*
 * Initialize the head of a queue or a link field embedded in a struct to be
 * inserted into a queue. (Note that a queue link field is internally
 * identical to a list head).
 *
 * Arguments:
 *    headp   Pointer to either the head of a queue or a queue element embedded
 *            in a struct
 */
#define YAQ_INIT(headp)           \
    (headp)->qe_next = (headp);   \
    (headp)->qe_prev = (headp);


/*
 * Return the pointer to the struct that the specified link field
 * (yaq_link_t) is embedded in.
 *
 * NOTE: be careful not to use this function on a queue head.  A queue head
 * is indistinguishable from a link field, both are yaq_link_t.
 *
 * Arguments:
 *    type    The type of the struct of which 'field' is a field
 *    field   The link field (yaq_link_t) in the above struct.
 *    lnkp    Pointer to a link field (yaq_link_t), which was
 *            presumably retrieved from YAQ_LAST, YAQ_NEXT,
 *            or YAQ_PREV.
 */
#ifdef WINDOWS_KERNEL
#define YAQ_OBJECT(type, field, lnkp)                                      \
    ((NULL == (lnkp))                                                      \
            ? NULL                                                         \
            : ((type *) ((char *)(lnkp) - FIELD_OFFSET(type, field))))

#else

#define YAQ_OBJECT(type, field, lnkp)                                      \
    ((NULL == (lnkp))                                                      \
            ? NULL                                                         \
            : ((type *) ((char *)(lnkp) - offsetof(type, field))))
#endif /* WINDOWS_KERNEL */


/*
 * Check either whether a queue is empty or whether a queue element is linked
 * into a queue (depending on whether this function is called for a queue head
 * or a link).  (Note that a queue link is internally identical to a list
 * head, so a queue element that's not linked into a queue is identical to an
 * empty queue).
 *
 * Argument:
 *    headp   Pointer to either the head of a queue or a queue element embedded
 *            in a struct
 */
#define YAQ_EMPTY(headp)                                                  \
    ((((headp)->qe_next == (headp)) && ((headp)->qe_prev == (headp)))     \
      || (NULL == ((headp)->qe_next))                                     \
      || (NULL == ((headp)->qe_prev)))


/*
 * Retrieve the first entry in a queue.
 *
 * Argument:
 *    headp    Pointer to the head of a queue
 *
 * Returns a pointer to the first element in the specified queue, or NULL if
 * the queue is empty.
 */
#define YAQ_FIRST(headp)                                                  \
    (YAQ_EMPTY(headp) ? NULL : ((headp)->qe_next))


/*
 * Retrieve the first object in a queue.  This convenience macros combines
 * YAQ_FIRST with YAQ_OBJECT.
 *
 * Returns a pointer to the first object in the specified queue, or NULL if
 * the queue is empty.
 *
 * Arguments:
 *    headp   Pointer to the head of a queue
 *    type    The type of the struct of which 'field' is a field
 *    field   The name of the queue link field (yaq_link_t) in the
 *            above struct.
 */
#define YAQ_FIRST_OBJECT(type, field, headp)                              \
    YAQ_OBJECT(type, field, YAQ_FIRST((headp)))


/*
 * Retrieve the last entry in a queue.
 *
 * Argument:
 *    headp    Pointer to the head of a queue
 *
 * Returns a pointer to the last element in the specified queue, or NULL if
 * the queue is empty.
 */
#define YAQ_LAST(headp)                                                  \
    (YAQ_EMPTY(headp) ? NULL : ((headp)->qe_prev))


/*
 * Retrieve the last object in a queue.  This convenience macros combines
 * YAQ_LAST with YAQ_OBJECT.
 *
 * Returns a pointer to the last object in the specified queue, or NULL if
 * the queue is empty.
 *
 * Arguments:
 *    headp    Pointer to the head of a queue
 *    type    The type of the struct of which 'field' is a field
 *    field   The name of the queue link field (yaq_link_t) in the
 *            above struct.
 */
#define YAQ_LAST_OBJECT(type, field, objectp)                              \
    YAQ_OBJECT(type, field, YAQ_LAST((headp)))


/*
 * Retrieve the next entry in a queue.
 *
 * Argument:
 *    headp   Pointer to the head of a queue
 *    lnkp    Pointer to the link field (yaq_link_t) embedded in the
 *            struct.  lnkp may have been retrieved using YAQ_FIRST, YAQ_NEXT,
 *            or YAQ_PREV.
 *
 * Returns a pointer to the next element in the specified queue, or NULL if
 * the queue is empty.
 */
#define YAQ_NEXT(headp, lnkp)                                               \
    ((((lnkp) == (headp)) || YAQ_EMPTY(lnkp)) ? NULL : ((lnkp)->qe_next))



/*
 * Retrieve the next object in a queue.  This convenience macros combines
 * YAQ_NEXT with YAQ_OBJECT.
 *
 * Returns a pointer to the next object in the specified queue, or NULL if
 * the queue is empty.
 *
 * Arguments:
 *    type    The type of the struct of which 'field' is a field
 *    field   The name of the queue link field (yaq_link_t) in the
 *            above struct.
 *    headp   Pointer to the head of a queue
 *    objectp Pointer to an object on the queue.
 */
#define YAQ_NEXT_OBJECT(type, field, headp, objectp)                       \
    YAQ_OBJECT(type, field, YAQ_NEXT((headp), &((objectp)->field)))


/*
 * Retrieve the previous entry in a queue.
 *
 * Argument:
 *    headp   Pointer to the head of a queue
 *    lnkp    Pointer to the link field (yaq_link_t) embedded in the
 *            struct.  lnkp may have been retrieved using YAQ_FIRST, YAQ_NEXT,
 *            or YAQ_PREV.
 *
 * Returns a pointer to the previous element in the specified queue, or NULL if
 * the queue is empty.
 */
#define YAQ_PREV(headp, lnkp)                                               \
    ((((lnkp) == (headp)) || YAQ_EMPTY(lnkp)) ? NULL : ((lnkp)->qe_prev))



/*
 * Retrieve the previous object in a queue.  This convenience macros combines
 * YAQ_PREV with YAQ_OBJECT.
 *
 * Returns a pointer to the previous object in the specified queue, or NULL if
 * the queue is empty.
 *
 * Arguments:
 *    type    The type of the struct of which 'field' is a field
 *    field   The name of the queue link field (yaq_link_t) in the
 *            above struct.
 *    headp   Pointer to the head of a queue
 *    objectp Pointer to an object on the queue
 */
#define YAQ_PREV_OBJECT(type, field, headp, objectp)                       \
    YAQ_OBJECT(type, field, YAQ_PREV((headp), &((objectp)->field)))


/*
 * Insert an element at the head of a queue.
 *
 * Argument:
 *    headp   Pointer to the head of a queue
 *    lnkp    Pointer to the link field (yaq_link_t) embedded in the
 *            struct to be added to the above queue
 */
#define YAQ_INSERT_HEAD(headp, lnkp)                                     \
    if (!YAQ_EMPTY(lnkp)) {                                              \
        rna_dbg_log(RNA_DBG_WARN,"queue element %p appears to "          \
                    "already be linked into a queue.\n",                 \
                    lnkp);                                               \
    }                                                                    \
    (lnkp)->qe_next = (headp)->qe_next;                                  \
    (lnkp)->qe_prev = (headp);                                           \
    (headp)->qe_next->qe_prev = (lnkp);                                  \
    (headp)->qe_next = (lnkp);

/*
 * Insert an element at the tail of a queue.
 *
 * Argument:
 *    headp    Pointer to the head of a queue
 *    lnkp     Pointer to the link field (yaq_link_t) embedded in the
 *             struct to be added to the above queue
 */
#define YAQ_INSERT_TAIL(headp, lnkp)                                     \
    if (!YAQ_EMPTY(lnkp)) {                                              \
        rna_dbg_log(RNA_DBG_ERR,"queue element %p appears to "           \
                    "already be linked into a queue.\n",                 \
                    lnkp);                                               \
    }                                                                    \
    (lnkp)->qe_prev = (headp)->qe_prev;                                  \
    (lnkp)->qe_next = (headp);                                           \
    (headp)->qe_prev->qe_next = (lnkp);                                  \
    (headp)->qe_prev = (lnkp);


/*
 * Remove an element from a queue.
 *
 * Argument:
 *    lnkp    Pointer to an yaq_link_t, which is embedded in the struct
 *            to be removed from its queue
 */
#define YAQ_REMOVE(lnkp)                                                 \
    YAQ_DEBUG_ASSERT(NULL != (lnkp)->qe_prev);                   \
    YAQ_DEBUG_ASSERT(NULL != (lnkp)->qe_next);                   \
    (lnkp)->qe_prev->qe_next = (lnkp)->qe_next;                          \
    (lnkp)->qe_next->qe_prev = (lnkp)->qe_prev;                          \
    YAQ_INIT((lnkp));                                                    \


/*
 * Iterate through the elements of a queue.
 *
 * Arguments:
 *    headp   Pointer to the head of a queue
 *    lnkp    Iteratively set to point to the link field of each element in
 *            the queue.  Use YAQ_OBJECT on lnkp to get a pointer to the
 *            queued struct.
 */
#define YAQ_FOREACH(headp, lnkp)                                         \
    YAQ_DEBUG_ASSERT(NULL != (headp)->qe_next);                  \
    for ((lnkp) = (headp)->qe_next;                                      \
         (lnkp) != (headp);                                              \
         (lnkp) = (lnkp)->qe_next)


/*
 * Merge the content of two queues by removing all the elements from queue
 * 'merge_from' and inserting them at the head of 'merge_to'.
 *
 * Arguments:
 *    merge_into  Pointer to the head of the queue to which elements will be
 *                added at its head.  After this operation, this queue will
 *                contain all the elements from both queues.
 *    merge_from  Pointer to the head of the queue from which elements will be
 *                taken and placed at the head of the above queue.  After this
 *                operation, this queue will be empty.
 */
#define YAQ_MERGE_HEAD(merge_into, merge_from)                          \
    if (!YAQ_EMPTY((merge_from))) {                                     \
        (merge_into)->qe_next->qe_prev = (merge_from)->qe_prev;         \
        (merge_from)->qe_prev->qe_next = (merge_into)->qe_next;         \
        (merge_from)->qe_next->qe_prev = (merge_into);                  \
        (merge_into)->qe_next = (merge_from)->qe_next;                  \
        YAQ_INIT((merge_from));                                         \
    }


/*
 * Merge the content of two queues by removing all the elements from queue
 * 'merge_from' and inserting them at the tail of 'merge_to'.
 *
 * Arguments:
 *    merge_into  Pointer to the head of the queue to which elements will be
 *                added at its tail.  After this operation, this queue will
 *                contain all the elements from both queues.
 *    merge_from  Pointer to the head of the queue from which elements will be
 *                taken and placed at the tail of the above queue.  After this
 *                operation, this queue will be empty.
 */
#define YAQ_MERGE_TAIL(merge_into, merge_from)                          \
    if (!YAQ_EMPTY((merge_from))) {                                     \
        (merge_into)->qe_prev->qe_next = (merge_from)->qe_next;         \
        (merge_from)->qe_prev->qe_next = (merge_into);                  \
        (merge_from)->qe_next->qe_prev = (merge_into)->qe_prev;         \
        (merge_into)->qe_prev = (merge_from)->qe_prev;                  \
        YAQ_INIT((merge_from));                                         \
    }

#endif	/* sys/queue.h */
