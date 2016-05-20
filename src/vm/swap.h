#ifndef VM_SWAP_H
#define VM_SWAP_H

void swap_init(void);
void swap_in(struct spte *);
void swap_out(struct frame_entry *);
void swap_free(size_t);

#endif
