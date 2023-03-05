#ifndef __FILE_H__
#define __FILE_H__
#include "vm/page.h"
#include "threads/palloc.h"
#include <list.h>
void lru_list_init(void);
struct page *alloc_get_page(enum palloc_flags alloc_flag);
void alloc_free_page(void *free_page_address);
static struct list_elem *next_clock_list_page(void);
void evict_clock_page(enum palloc_flags alloc_flag);
#endif
