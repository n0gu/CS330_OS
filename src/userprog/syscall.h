#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);
void mmap_free(struct thread_mmap *);
void file_out(struct spte *);
void file_in(struct spte *, struct frame_entry *);
#endif /* userprog/syscall.h */
