#ifndef __KINETIC_LIST_H__
#define __KINETIC_LIST_H__


#include <stdbool.h>

struct kinetic_list_node {
	struct kinetic_list_node *next;
	struct kinetic_list_node *prev;
};

struct kinetic_list_head {
	struct kinetic_list_node n;
};

#define KINETIC_LIST_HEAD_INIT(name) { { &(name.n), &(name.n) } }
#define KINETIC_LIST_NODE_INIT { NULL, NULL }

#define KINETIC_LIST_HEAD(name) \
	struct kinetic_list_head name = KINETIC_LIST_HEAD_INIT(name)
#define KINETIC_LIST_NODE(name) \
	struct kinetic_list_node name = KINETIC_LIST_NODE_INIT

inline void init_kinetic_list_head(struct kinetic_list_head *kinetic_list)
{
	kinetic_list->n.next = &kinetic_list->n;
	kinetic_list->n.prev = &kinetic_list->n;
}

inline void INIT_KINETIC_LIST_NODE(struct kinetic_list_node *kinetic_list)
{
	kinetic_list->next = NULL;
	kinetic_list->prev = NULL;
}

#define kinetic_list_first_entry(head, type, member) \
	kinetic_list_entry((head)->n.next, type, member)

static inline bool kinetic_list_empty(const struct kinetic_list_head *head)
{
	return head->n.next == &head->n;
}

static inline bool kinetic_list_linked(const struct kinetic_list_node *node)
{
	return node->next != NULL;
}

#define kinetic_list_entry(ptr, type, member) \
	container_of(ptr, type, member)

#define kinetic_list_for_each(pos, head)					\
	for (typeof(pos) LOCAL(n) = (pos = (head)->n.next, pos->next);	\
	     pos != &(head)->n;						\
	     pos = LOCAL(n), LOCAL(n) = pos->next)

#define kinetic_list_for_each_entry(pos, head, member)				\
	for (typeof(pos) LOCAL(n) = (pos = kinetic_list_entry((head)->n.next,	\
						      typeof(*pos),	\
						      member),		\
				     kinetic_list_entry(pos->member.next,	\
						typeof(*pos),		\
						member));		\
	     &pos->member != &(head)->n;				\
	     pos = LOCAL(n), LOCAL(n) = kinetic_list_entry(LOCAL(n)->member.next, \
						   typeof(*LOCAL(n)),	\
						   member))

static inline void __kinetic_list_add(struct kinetic_list_node *new,
			      struct kinetic_list_node *prev,
			      struct kinetic_list_node *next)
{
	next->prev = new;
	new->next = next;
	new->prev = prev;
	prev->next = new;
}

static inline void kinetic_list_add(struct kinetic_list_node *new, struct kinetic_list_head *head)
{
	__kinetic_list_add(new, &head->n, head->n.next);
}

static inline void kinetic_list_add_tail(struct kinetic_list_node *new, struct kinetic_list_head *head)
{
	__kinetic_list_add(new, head->n.prev, &head->n);
}

static inline void __kinetic_list_del(struct kinetic_list_node *prev, struct kinetic_list_node *next)
{
	next->prev = prev;
	prev->next = next;
}

static inline void __kinetic_list_del_entry(struct kinetic_list_node *entry)
{
	__kinetic_list_del(entry->prev, entry->next);
}

static inline void kinetic_list_del(struct kinetic_list_node *entry)
{
	__kinetic_list_del(entry->prev, entry->next);
	entry->next = entry->prev = NULL;
}

static inline void kinetic_list_move(struct kinetic_list_node *kinetic_list, struct kinetic_list_head *head)
{
	__kinetic_list_del_entry(kinetic_list);
	kinetic_list_add(kinetic_list, head);
}

static inline void kinetic_list_move_tail(struct kinetic_list_node *kinetic_list,
				  struct kinetic_list_head *head)
{
	__kinetic_list_del_entry(kinetic_list);
	kinetic_list_add_tail(kinetic_list, head);
}

static inline void __kinetic_list_splice(const struct kinetic_list_head *kinetic_list,
				 struct kinetic_list_node *prev,
				 struct kinetic_list_node *next)
{
	struct kinetic_list_node *first = kinetic_list->n.next;
	struct kinetic_list_node *last = kinetic_list->n.prev;

	first->prev = prev;
	prev->next = first;

	last->next = next;
	next->prev = last;
}

static inline void kinetic_list_splice_init(struct kinetic_list_head *kinetic_list,
				    struct kinetic_list_head *head)
{
	if (!kinetic_list_empty(kinetic_list)) {
		__kinetic_list_splice(kinetic_list, &head->n, head->n.next);
		init_kinetic_list_head(kinetic_list);
	}
}

static inline void kinetic_list_splice_tail_init(struct kinetic_list_head *kinetic_list,
					 struct kinetic_list_head *head)
{
	if (!kinetic_list_empty(kinetic_list)) {
		__kinetic_list_splice(kinetic_list, head->n.prev, &head->n);
		init_kinetic_list_head(kinetic_list);
	}
}


#define KINETIC_LIST_POISON1 ((void *) 0x00100100)
#define KINETIC_LIST_POISON2 ((void *) 0x00200200)

struct hash_kinetic_list_head {
	struct hash_kinetic_list_node *first;
};

struct hash_kinetic_list_node {
	struct hash_kinetic_list_node *next, **pprev;
};

#define INIT_HKINETIC_LIST_HEAD(ptr) ((ptr)->first = NULL)
#define HKINETIC_LIST_HEAD_INIT { .first = NULL }
#define HKINETIC_LIST_HEAD(name) struct hash_kinetic_list_head name = {  .first = NULL }


static inline bool hash_kinetic_list_unhashed(const struct hash_kinetic_list_node *h)
{
	return !h->pprev;
}
static inline void INIT_HKINETIC_LIST_NODE(struct hash_kinetic_list_node *h)
{
	h->next = NULL;
	h->pprev = NULL;
}


static inline bool hash_kinetic_list_empty(const struct hash_kinetic_list_head *h)
{
	return !h->first;
}

static inline void __hash_kinetic_list_del(struct hash_kinetic_list_node *n)
{
	struct hash_kinetic_list_node *next = n->next;
	struct hash_kinetic_list_node **pprev = n->pprev;
	*pprev = next;
	if (next)
		next->pprev = pprev;
}

static inline void hash_kinetic_list_del(struct hash_kinetic_list_node *n)
{
	__hash_kinetic_list_del(n);
	n->next = KINETIC_LIST_POISON1;
	n->pprev = KINETIC_LIST_POISON2;
}


static inline void hash_kinetic_list_add_before(struct hash_kinetic_list_node *n,
		struct hash_kinetic_list_node *next)
{
	n->pprev = next->pprev;
	n->next = next;
	next->pprev = &n->next;
	*(n->pprev) = n;
}

static inline void hash_kinetic_list_add_head(struct hash_kinetic_list_node *n, struct hash_kinetic_list_head *h)
{
	struct hash_kinetic_list_node *first = h->first;
	n->next = first;
	if (first)
		first->pprev = &n->next;
	h->first = n;
	n->pprev = &h->first;
}


static inline void hash_kinetic_list_add_after(struct hash_kinetic_list_node *n,
		struct hash_kinetic_list_node *next)
{
	next->next = n->next;
	n->next = next;
	next->pprev = &n->next;

	if (next->next)
		next->next->pprev  = &next->next;
}

#define hash_kinetic_list_entry(ptr, type, member) container_of(ptr, type, member)

#define hash_kinetic_list_for_each(pos, head)					\
	for (typeof(pos) LOCAL(n) = (pos = (head)->first, NULL);	\
	     pos && (LOCAL(n) = pos->next, 1);				\
	     pos = LOCAL(n))						\

#define hash_kinetic_list_for_each_entry(tpos, pos, head, member)			\
	for (typeof(pos) LOCAL(n) = (pos = (head)->first, NULL);	\
	     pos && (LOCAL(n) = pos->next, 1) &&			\
		     (tpos = hash_kinetic_list_entry(pos, typeof(*tpos), member), 1); \
	     pos = LOCAL(n))

void kinetic_list_sort(void *priv, struct kinetic_list_head *head,
	       int (*cmp)(void *priv, struct kinetic_list_node *a,
			  struct kinetic_list_node *b));
#endif	/* __KINETIC_LIST_H__ */
