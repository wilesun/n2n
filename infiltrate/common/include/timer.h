#ifndef __TIMER_H__
#define __TIMER_H__

#include <stdio.h>
#include "list.h"

struct timer_list {
	struct list_head	list;
	unsigned long		expires;
	void			(*function)(unsigned long);
	unsigned long		data;
};

unsigned long jiffies_get(void);
void init_timer_module(void);
int mod_timer(struct timer_list * timer, unsigned long expires);
void add_timer(struct timer_list * timer);
void run_timer_list(void);


#define jiffies jiffies_get()

static inline void init_timer(struct timer_list * timer)
{
	timer->list.next = timer->list.prev = NULL;
	timer->data = 0;
	timer->function = NULL;
	timer->expires = 0;
}

#ifdef HZ
#undef HZ
#endif

#define HZ 1000

#endif
