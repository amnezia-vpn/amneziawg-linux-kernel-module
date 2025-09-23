#ifndef _AWG_JUNK_H
#define _AWG_JUNK_H

#include <linux/list.h>
#include <linux/mutex.h>

struct wg_peer;

typedef void(*jp_modifier_func)(char*, int, struct wg_peer*);

struct jp_tag
{
    u8* pkt;
    jp_modifier_func func;
    struct list_head head;
    int pkt_size;
};

void jp_tag_free(struct jp_tag* tag);
int jp_parse_tags(char* str, struct list_head* head);

struct jp_modifier
{
    jp_modifier_func func;
    char* buf;
    int buf_len;
};

struct jp_spec
{
    char* desc;
    u8* pkt;
    struct jp_modifier* mods;
    struct mutex lock;
    int pkt_size;
    int mods_size;
};

void jp_spec_free(struct jp_spec* spec);
int jp_spec_setup(struct jp_spec* spec);
void jp_spec_applymods(struct jp_spec* spec, struct wg_peer* peer);

#endif