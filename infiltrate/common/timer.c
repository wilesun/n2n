#include <sys/time.h>
#include <time.h>
#include <stdlib.h>


#include "debug.h"
#include "timer.h"

/* 
* Event timer code 
*/ 
#define TVN_BITS 6 
#define TVR_BITS 8 
#define TVN_SIZE (1 << TVN_BITS) 
#define TVR_SIZE (1 << TVR_BITS) 
#define TVN_MASK (TVN_SIZE - 1) 
#define TVR_MASK (TVR_SIZE - 1) 

struct timer_vec { 
	int index; 
	struct list_head vec[TVN_SIZE]; 
}; 

struct timer_vec_root { 
	int index; 
	struct list_head vec[TVR_SIZE]; 
}; 

static struct timer_vec tv5; 
static struct timer_vec tv4; 
static struct timer_vec tv3; 
static struct timer_vec tv2; 
static struct timer_vec_root tv1; 

static struct timeval __start;
static unsigned long timer_jiffies;

static struct timer_vec * const tvecs[] = { 
	(void *)&tv1, &tv2, &tv3, &tv4, &tv5 
}; 
#define NOOF_TVECS (sizeof(tvecs) / sizeof(tvecs[0]))

void init_jiffies(void)
{
	// TODO: 系统时间修改之后……咳咳
	gettimeofday(&__start,NULL);
}

unsigned long jiffies_get(void)
{
	struct timeval now_tm;
	gettimeofday(&now_tm, NULL);
	return (now_tm.tv_sec - __start.tv_sec)*1000 + (now_tm.tv_usec - __start.tv_usec)/1000;
}

static inline int timer_pending(const struct timer_list * timer)
{
	return timer->list.next != NULL;
}

void init_timervecs(void)
{
	int i; 

	for (i = 0; i < TVN_SIZE; i++) {
		INIT_LIST_HEAD(tv5.vec + i);
		INIT_LIST_HEAD(tv4.vec + i);
		INIT_LIST_HEAD(tv3.vec + i);
		INIT_LIST_HEAD(tv2.vec + i);
	}

	for (i = 0; i < TVR_SIZE; i++)
		INIT_LIST_HEAD(tv1.vec + i);
}

void init_timer_module(void)
{
	init_jiffies();
	init_timervecs();
	srand(time(NULL));
}

static inline void internal_add_timer(struct timer_list *timer)
{
	unsigned long expires = timer->expires;
	unsigned long idx = expires - jiffies;
	struct list_head * vec;
	if (idx < TVR_SIZE) {
		int i = expires & TVR_MASK;
		vec = tv1.vec + i;
	} else if (idx < 1 << (TVR_BITS + TVN_BITS)) {
		int i = (expires >> TVR_BITS) & TVN_MASK;
		 vec = tv2.vec + i;
	} else if (idx < 1 << (TVR_BITS + 2 * TVN_BITS)) {
		int i = (expires >> (TVR_BITS + TVN_BITS)) & TVN_MASK;
		vec = tv3.vec + i;
	} else if (idx < 1 << (TVR_BITS + 3 * TVN_BITS)) {
		int i = (expires >> (TVR_BITS + 2 * TVN_BITS)) & TVN_MASK;
		vec = tv4.vec + i;
	} else if ((signed long) idx < 0) {
		vec = tv1.vec + tv1.index;
	} else if (idx <= 0xffffffffUL) {
		int i = (expires >> (TVR_BITS + 3 * TVN_BITS)) & TVN_MASK;
		vec = tv5.vec + i;
	} else {
		INIT_LIST_HEAD(&timer->list);
		return;
	}

	list_add(&timer->list, vec->prev);
}

void add_timer(struct timer_list *timer) 
{
	if (timer_pending(timer))
	{
		CYM_LOG(LV_WARNING, "add timer failed, timer is pending\n");
		return;
	}

	internal_add_timer(timer);
}

static inline int detach_timer(struct timer_list *timer)
{
	if (!timer_pending(timer))
		return 0;

	list_del(&timer->list);
	return 1;
}

int mod_timer(struct timer_list *timer, unsigned long expires)
{
	int ret;
	timer->expires = expires;
	ret = detach_timer(timer);
	internal_add_timer(timer);
	return ret;
}

int del_timer(struct timer_list * timer)
{
	int ret;

	ret = detach_timer(timer); 
	timer->list.next = timer->list.prev = NULL;
	return ret;
}

static inline void cascade_timers(struct timer_vec *tv)
{
	struct list_head *head, *curr, *next; 

	head = tv->vec + tv->index; 
	curr = head->next; 

	while (curr != head) {
		struct timer_list *tmp;

		tmp = list_entry(curr, struct timer_list, list);
		next = curr->next;
		list_del(curr);
		internal_add_timer(tmp);
		curr = next;
	}
	INIT_LIST_HEAD(head);
	tv->index = (tv->index + 1) & TVN_MASK;
}

void run_timer_list(void)
{
	unsigned long _jiffies = jiffies;
	while ((long)(_jiffies - timer_jiffies) >= 0) {
		struct list_head *head, *curr;
		if (!tv1.index) {
			int n = 1;
			do {
				cascade_timers(tvecs[n]);
			} while (tvecs[n]->index == 1 && ++n < NOOF_TVECS);
		}
	repeat:
		head = tv1.vec + tv1.index;
		curr = head->next;
		if (curr != head) {
			struct timer_list *timer;
			void (*fn)(unsigned long);
			unsigned long data;

			timer = list_entry(curr, struct timer_list, list);
			fn = timer->function;
			data= timer->data;

			detach_timer(timer);
			timer->list.next = timer->list.prev = NULL;
			fn(data);
			goto repeat;
		}
		++timer_jiffies;
		tv1.index = (tv1.index + 1) & TVR_MASK;
	}
}

#define TIMER_TEST 0
#if TIMER_TEST
#include <unistd.h>

int debug_level = 0;
#define TIME_TEST_SIZE 2
struct timer_list test_arr[TIME_TEST_SIZE];

void test_timeout(unsigned long data)
{
	printf("%lu\n", data);
	mod_timer(&test_arr[data-1], jiffies + data * HZ);
}

void timer_test_init(struct timer_list *timer, int i)
{
	timer->data = i;
	timer->function = test_timeout;
	timer->expires = 0;
	add_timer(timer);
}

int main(int argc, char **argv)
{
	int i;

	init_timer_module();

	for(i = 0; i < TIME_TEST_SIZE; i++)
	{
		init_timer(&test_arr[i]);
		timer_test_init(&test_arr[i], i+1);
	}

	while(1)
	{
		usleep(50);
		run_timer_list();
	}

	return 0;
}
#endif

