#include <bitmap.h>
#include "devices/disk.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "userprog/syscall.h"
#include "vm/frame.h"
#include "vm/page.h"
#include "vm/swap.h"

#define PAGE_NUM_SECTORS (PGSIZE / DISK_SECTOR_SIZE)

struct disk *swap_disk;
struct bitmap *swap_table;

void
swap_init(void)
{
  swap_disk = disk_get(1, 1);
  disk_sector_t cnt = disk_size(swap_disk);
  swap_table = bitmap_create(cnt);
}


void
swap_in(struct spte *p)
{
  ASSERT(frame_lock_held_by_curr());
  ASSERT(p->status & P_INSWAP);
  struct frame_entry *fe = frame_alloc(p, false);
  int i;

  if(p->status & P_MMAP){
    file_in(p, fe);
  }
  else{
    for(i = 0; i < PAGE_NUM_SECTORS; i++)
      disk_read(swap_disk, p->swap_addr + i, (uint8_t *)fe->frame_addr + DISK_SECTOR_SIZE * i);
    bitmap_set_multiple(swap_table, p->swap_addr, PAGE_NUM_SECTORS, false);
  }
  spte_unmark(p, P_INSWAP);
  ASSERT(p->frame_entry == fe);
  ASSERT(fe->spte == p);
  if(!install_page(p->page_addr, fe->frame_addr, (p->status & P_WRITABLE)))
    PANIC("install page fail at swap_in\n");
}


void
swap_out(struct frame_entry *victim)
{
  ASSERT(frame_lock_held_by_curr());
  struct spte *vic_spte = victim->spte;
  ASSERT(!(vic_spte->status & P_INSWAP));
  ASSERT(vic_spte->frame_entry == victim);
  int i,  swap_idx;
  bool dirty = pagedir_is_dirty(vic_spte->thread->pagedir, vic_spte->page_addr);

  pagedir_clear_page(vic_spte->thread->pagedir, vic_spte->page_addr);
  spte_mark(vic_spte, P_INSWAP);

  if(vic_spte->status & P_MMAP){
    if(dirty) file_out(vic_spte);
  }
  else{
    swap_idx = bitmap_scan_and_flip(swap_table, 0, PAGE_NUM_SECTORS, false);
    if(swap_idx == BITMAP_ERROR)
      PANIC("NOT ENOUGH MEMORY IN SWAP SPACE");
    vic_spte->swap_addr = swap_idx;
    for(i = 0; i < PAGE_NUM_SECTORS; i++)
      disk_write(swap_disk, swap_idx + i, (uint8_t *)victim->frame_addr + DISK_SECTOR_SIZE * i);
  }
}

void
swap_free(size_t disk_idx)
{
  ASSERT(frame_lock_held_by_curr());
  bitmap_set_multiple(swap_table, disk_idx, PAGE_NUM_SECTORS, false);
}
