#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
struct spte *alloc_user_page(void *, bool, bool);
bool install_page (void *upage, void *kpage, bool writable);
bool grow_stack(void *);
bool load_lazy(struct spte *);
void destroy_both_entry(struct spte *);

#endif /* userprog/process.h */
