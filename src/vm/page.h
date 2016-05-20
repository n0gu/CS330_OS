#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include <stddef.h>

enum spte_status
  {
    P_WRITABLE = 1,
    P_INSWAP = 2
  };

struct spte
  {
    void *page_addr;
    struct frame_entry *frame_entry;
    size_t swap_addr;
    enum spte_status status;
    struct thread *thread;
    struct hash_elem hash_elem;
  };

void spt_init(void);
void spt_destroy(void);
struct spte *spt_find(void *);

struct spte *spte_insert(void *, struct frame_entry *, enum spte_status);
void spte_free(struct spte *);
int spte_status(struct spte *);
void spte_mark(struct spte *, int);
void spte_unmark(struct spte *, int);

#endif
