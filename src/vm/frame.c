#include <debug.h>
#include <inttypes.h>
#include <debug.h>
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "vm/frame.h"
#include "vm/page.h"
#include "vm/swap.h"

struct frame_entry *frame_find(void *);
struct lock frame_lock;
struct list frame_table;

static struct frame_entry *frame_find_and_remove_victim(void);

void
frame_lock_ac(void)
{
  lock_acquire(&frame_lock);
}

void
frame_lock_rl(void)
{
  lock_release(&frame_lock);
}

bool
frame_lock_held_by_curr(void)
{
  return lock_held_by_current_thread(&frame_lock);
}

void
frame_init(void)
{
  lock_init(&frame_lock);
  list_init(&frame_table);
}

struct frame_entry *
frame_alloc(struct spte *spte, bool zero_flag)
{
  ASSERT(frame_lock_held_by_curr());
  ASSERT(spte != NULL);
  struct frame_entry *f;
  uint8_t *kpage = zero_flag ? palloc_get_page(PAL_USER | PAL_ZERO) : palloc_get_page(PAL_USER);

  if(kpage){
    f = (struct frame_entry *)malloc(sizeof(struct frame_entry));
    f->frame_addr = kpage;
  }
  else{
    /* all page is allocated. */
    f = frame_find_and_remove_victim();
    swap_out(f);
    if(zero_flag)
      memset(f->frame_addr, 0, PGSIZE);
  }
  f->spte = spte;
  spte->frame_entry = f;
  list_push_back(&frame_table, &f->elem);

  return f;
}

void
frame_free(struct frame_entry *f)
{
  ASSERT(frame_lock_held_by_curr());
  list_remove(&f->elem);
  free(f);
}

static struct frame_entry *
frame_find_and_remove_victim(void)
{
  ASSERT(frame_lock_held_by_curr());
  ASSERT(!list_empty(&frame_table));
  struct list_elem *e = list_pop_front(&frame_table);
  return list_entry(e, struct frame_entry, elem);
}
