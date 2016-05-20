#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <list.h>

struct frame_entry
  {
    void* frame_addr;
    struct spte *spte;
    struct list_elem elem;
  };

void frame_lock_ac(void);
void frame_lock_rl(void);
bool frame_lock_held_by_curr(void);
void frame_init(void);
struct frame_entry *frame_alloc(struct spte *, bool);
void frame_free(struct frame_entry *);

#endif
