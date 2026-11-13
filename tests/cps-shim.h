// SPDX-License-Identifier: GPL-2.0

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <assert.h>
#define U16_MAX 65535U
struct iphdr { char bytes[20]; };
struct udphdr { char bytes[8]; };
static int allocations, fail_at;
static int allocation_fails(void) { return ++allocations == fail_at; }
#include <arpa/inet.h>
typedef uint8_t u8;
typedef uint32_t u32;
#define GFP_KERNEL 0
struct mutex { int unused; };
static void mutex_lock(struct mutex *p) { (void)p; }
static void mutex_unlock(struct mutex *p) { (void)p; }
static void *kmalloc(size_t n, int f) { (void)f; return allocation_fails() ? NULL : malloc(n ? n : 1); }
static void *kzalloc(size_t n, int f) { (void)f; return allocation_fails() ? NULL : calloc(1, n ? n : 1); }
static void kfree(void *p) { free(p); }
static char *kstrdup(const char *s, int f) { (void)f; return allocation_fails() ? NULL : strdup(s); }
static int kstrtoint(const char *s, unsigned int b, int *out) {
 char *e; errno=0; long n=strtol(s,&e,b);
 if(errno || *e || n<INT_MIN || n>INT_MAX) return -EINVAL;
 *out=n; return 0;
}
static int kstrtou8(const char *s, unsigned int b, u8 *out) {
 char *e; errno=0; unsigned long n=strtoul(s,&e,b);
 if(errno || *e || n>255) return -EINVAL;
 *out=n; return 0;
}
static void get_random_bytes(void *p, int n) { memset(p, 0x55, (size_t)n); }
static u32 get_random_u32(void) { return 5; }
static uint64_t ktime_get_real_seconds(void) { return 100; }
typedef int atomic_t;
static int atomic_read(const atomic_t *p) { return *p; }
struct wg_peer { atomic_t jp_packet_counter; };
struct list_head { struct list_head *next, *prev; };
#define LIST_HEAD(name) struct list_head name = { &(name), &(name) }
static void list_add(struct list_head *n, struct list_head *h) {
 n->next=h->next; n->prev=h; h->next->prev=n; h->next=n;
}
static void list_del(struct list_head *n) { n->next->prev=n->prev; n->prev->next=n->next; }
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define list_entry(p,t,m) container_of(p,t,m)
#define list_for_each_entry(p,h,m) \
 for(p=list_entry((h)->next,__typeof__(*p),m); &p->m!=(h); p=list_entry(p->m.next,__typeof__(*p),m))
#define list_for_each_entry_reverse(p,h,m) \
 for(p=list_entry((h)->prev,__typeof__(*p),m); &p->m!=(h); p=list_entry(p->m.prev,__typeof__(*p),m))
#define list_for_each_entry_safe(p,n,h,m) \
 for(p=list_entry((h)->next,__typeof__(*p),m),n=list_entry(p->m.next,__typeof__(*p),m); \
 &p->m!=(h); p=n,n=list_entry(n->m.next,__typeof__(*n),m))

static void *kcalloc(size_t n, size_t s, int f) { (void)f; if(s && n>SIZE_MAX/s) return NULL; return allocation_fails() ? NULL : calloc(n ? n : 1,s ? s : 1); }
