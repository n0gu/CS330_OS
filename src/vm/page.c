#include <hash.h>
#include <stddef.h>
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "vm/frame.h"
#include "vm/page.h"
#include "vm/swap.h"

static unsigned spt_hash(const struct hash_elem *, void *);
static bool spt_less(const struct hash_elem *, const struct hash_elem *, void *);
static void spt_free(struct hash_elem *, void *);

/* functions to manage whole spTable. */
void
spt_init(void)
{
  hash_init(&thread_current()->spt, spt_hash, spt_less, NULL);
}

void
spt_destroy(void)
{
  ASSERT(frame_lock_held_by_curr());
  hash_destroy(&thread_current()->spt, spt_free);
}

struct spte *
spt_find(void *page_addr)
{
  struct spte p;
  struct hash_elem *e;
  p.page_addr = page_addr;
  e = hash_find(&thread_current()->spt, &p.hash_elem);
  return e != NULL ? hash_entry(e, struct spte, hash_elem) : NULL;
}


/* functions that manage individual sptEntry. */
struct spte *
spte_create(void *page_addr, struct frame_entry *f, enum spte_status status)
{
  ASSERT(page_addr < PHYS_BASE);
  struct thread *curr = thread_current();

  struct spte *spte = (struct spte *)malloc(sizeof(struct spte));
  spte->page_addr = page_addr;
  spte->frame_entry = f;
  spte->swap_addr = 0;
  spte->status = status;
  spte->thread = curr;
  hash_insert(&curr->spt, &spte->hash_elem);

  return spte;
}

void
spte_free(struct spte *spte)
{
  hash_delete(&thread_current()->spt, &spte->hash_elem);
  free(spte);
}

int
spte_status(struct spte *spte)
{
  return spte->status;
}

void
spte_mark(struct spte *spte, int mask)
{
  spte->status |= mask;
}

void
spte_unmark(struct spte *spte, int mask)
{
  spte->status &= (~mask);
}


/* for use in iteration, etc. */
static unsigned
spt_hash(const struct hash_elem *p_, void *aux UNUSED)
{
  const struct spte *p = hash_entry(p_, struct spte, hash_elem);
  return hash_bytes(&p->page_addr, sizeof p->page_addr);
}

static bool
spt_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED)
{
  const struct spte *a = hash_entry(a_, struct spte, hash_elem);
  const struct spte *b = hash_entry(b_, struct spte, hash_elem);
  return a->page_addr < b->page_addr;
}

static void
spt_free(struct hash_elem *elem, void *aux)
{
  ASSERT(frame_lock_held_by_curr());
  struct spte *p = hash_entry(elem, struct spte, hash_elem);
  int status = p->status;

  if(!(status & P_LAZY)){
    if(status & P_INSWAP){
      swap_free(p->swap_addr);
    }
    else{
      ASSERT(p->frame_entry != NULL);
      ASSERT(p->frame_entry->spte == p);
      frame_free(p->frame_entry);
    }
  }
  free(p);
}
