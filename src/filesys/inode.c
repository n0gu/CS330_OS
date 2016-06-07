#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "filesys/cache.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/synch.h"


/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, DISK_SECTOR_SIZE);
}

/* In-memory inode. */

static bool install_sector(disk_sector_t idx_lv1, off_t start, off_t end);
static void destroy_sector(struct inode *inode);
static void dump_idx(disk_sector_t idx_lv1, off_t length);

/* Returns the disk sector that contains byte offset POS within
   INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static disk_sector_t
byte_to_sector (const struct inode *inode, off_t pos) 
{
  ASSERT (inode != NULL);
  if (pos < inode->length){
    disk_sector_t buffer[128];
    disk_sector_t sec_no = pos / DISK_SECTOR_SIZE;
    int lv1_idx = sec_no / 128;
    int lv2_idx = sec_no % 128;

    disk_read_with_cache(inode->idx_lv1, buffer);
    disk_sector_t lv2_sector = buffer[lv1_idx];
    disk_read_with_cache(lv2_sector, buffer);
    return buffer[lv2_idx];
  }
  else
    return -1;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;
static struct lock inode_lock;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
  lock_init (&inode_lock);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   disk.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (disk_sector_t sector, off_t length)
{
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == DISK_SECTOR_SIZE);
//  printf("creating inode at %d -- length %d\n", sector, length);
  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      size_t sectors_left = bytes_to_sectors (length);
      size_t num_idx_lv2 = DIV_ROUND_UP(sectors_left, DISK_SECTOR_SIZE / 4);
      ASSERT(num_idx_lv2 <= 128);

      disk_inode->length = length;
      disk_inode->magic = INODE_MAGIC;

      if (free_map_allocate (1, &disk_inode->idx_lv1))
        {
          success = install_sector(disk_inode->idx_lv1, 0, length);
          disk_write_with_cache(sector, disk_inode);
        }
      free (disk_inode);
    }
//  printf("inode create finished.\n");
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (disk_sector_t sector) 
{
  struct list_elem *e;
  struct inode *inode;
  struct inode_disk d;

  lock_acquire(&inode_lock);
  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          lock_release(&inode_lock);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;

  disk_read_with_cache(sector, &d);
  inode->length = d.length;
  inode->idx_lv1 = d.idx_lv1;

  lock_init(&inode->lock);
  sema_init(&inode->in_read, 1);
  inode->read_cnt = 0;
  lock_release(&inode_lock);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL){
    lock_acquire(&inode->lock);
    inode->open_cnt++;
    lock_release(&inode->lock);
  }
  return inode;
}

/* Returns INODE's inode number. */
disk_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;
  /* Release resources if this was the last opener. */

  lock_acquire(&inode_lock);
  lock_acquire(&inode->lock);
  int open_cnt = --inode->open_cnt;
  lock_release(&inode->lock);
  if (open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          destroy_sector(inode);
        }
      free (inode); 
    }
  lock_release(&inode_lock);
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t *bounce = NULL;

  lock_acquire(&inode->lock);
  if(++inode->read_cnt == 1)
    sema_down(&inode->in_read);
  lock_release(&inode->lock);
  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      disk_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % DISK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = DISK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == DISK_SECTOR_SIZE) 
        {
          /* Read full sector directly into caller's buffer. */
          disk_read_with_cache(sector_idx, buffer + bytes_read); 
        }
      else 
        {
          /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (DISK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }
          disk_read_with_cache(sector_idx, bounce);
          memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
        }
      
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  free (bounce);

//  disk_sector_t next_sector = byte_to_sector(inode, DISK_SECTOR_SIZE * DIV_ROUND_UP(size + offset, DISK_SECTOR_SIZE));
//  if(next_sector != -1)
//    send_request(next_sector);

  lock_acquire(&inode->lock);
  if(--inode->read_cnt == 0)
    sema_up(&inode->in_read);
  lock_release(&inode->lock);

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;
  bool extend = false;

  if (inode->deny_write_cnt)
    return 0;
//  printf("inode write at begin at inode %08x to %08x\n", inode, buffer);
  if(inode->length < size + offset)
  {
    extend = true;
    sema_down(&inode->in_read);
    struct inode_disk d;
    install_sector(inode->idx_lv1, inode->length, size + offset);
    inode->length = size + offset;
    disk_read_with_cache(inode->sector, &d);
    d.length = size + offset;
    disk_write_with_cache(inode->sector, &d);
  }

  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      disk_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % DISK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = DISK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == DISK_SECTOR_SIZE) 
        {
          /* Write full sector directly to disk. */
          disk_write_with_cache(sector_idx, buffer + bytes_written); 
        }
      else 
        {
          /* We need a bounce buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (DISK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }

          /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
          if (sector_ofs > 0 || chunk_size < sector_left) 
            disk_read_with_cache(sector_idx, bounce);
          else
            memset (bounce, 0, DISK_SECTOR_SIZE);
          memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
          disk_write_with_cache(sector_idx, bounce); 
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  free (bounce);

  if(extend)
    sema_up(&inode->in_read);

//  printf("inode write at finish at inode %08x to %08x\n", inode, buffer);
  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  lock_acquire(&inode->lock);
  inode->deny_write_cnt--;
  lock_release(&inode->lock);
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  return inode->length;
}


static bool
install_sector(disk_sector_t idx_lv1, off_t start, off_t end)
{
  /* start greater or equal , end less */
  /* inode's index block level 1 should be already exist */
  /* start = previous length, end = new length ex) 0, 143 */
  ASSERT(start <= end);

  disk_sector_t start_sectors = bytes_to_sectors(start);
  disk_sector_t end_sectors = bytes_to_sectors(end);

//  printf("installing byte %d-%d, sector %d-%d\nidx sector %d\n", start, end, start_sectors, end_sectors, idx_lv1);
  if(start_sectors == end_sectors) return true;

  off_t sectors_left = end_sectors - start_sectors;
  int end_lv1_num = DIV_ROUND_UP(end_sectors, 128);

  disk_sector_t buf[128];
  disk_read_with_cache(idx_lv1, buf);

  int lv1_idx = start_sectors / 128;
  int lv2_idx = start_sectors % 128;
  while(lv1_idx < end_lv1_num)
  {
    disk_sector_t buf2[128];
    if(lv2_idx == 0){
      if(!free_map_allocate(1, &buf[lv1_idx])) return false;
//      printf("at idx_1 : installing new block\n");
    }
    else{
      disk_read_with_cache(buf[lv1_idx], buf2);
//      printf("at idx_1 : already exist, read from disk\n");
    }
    while(lv2_idx < 128)
    {
      if(sectors_left == 0){
        buf2[lv2_idx] = 0;
      }
      else{
        if(!free_map_allocate(1, &buf2[lv2_idx])) return false;
//        printf("installing %dth sector fin\n", lv1_idx * 128 + lv2_idx + 1);
        sectors_left--;
      }
      lv2_idx++;
    }
    disk_write_with_cache(buf[lv1_idx], buf2);
    lv2_idx = 0;
    lv1_idx++;
  }
  disk_write_with_cache(idx_lv1, buf);

//  printf("installing sector finished\n");
//  dump_idx(idx_lv1, end);
  return true;
}

static void
destroy_sector(struct inode *inode)
{
  off_t length = inode->length;
  int sectors = bytes_to_sectors(length);
  int lv1_num = DIV_ROUND_UP(sectors, 128);

  int i, j;
  disk_sector_t buf[128];
  disk_read_with_cache(inode->idx_lv1, buf);
  for(i = 0; i < lv1_num; i++)
  {
    disk_sector_t buf2[128];
    disk_read_with_cache(buf[i], buf2);
    j = 0;
    while(j < 128 && sectors > 0)
    {
      free_map_release(buf2[j], 1);
      j++;
      sectors--;
    }
    free_map_release(buf[i], 1);
    i++;
  }
  free_map_release(inode->idx_lv1, 1);
  free_map_release(inode->sector, 1);
}

static void
dump_idx(disk_sector_t idx_lv1, off_t length)
{
  disk_sector_t buf[128];
  disk_read_with_cache(idx_lv1, buf);
  int i, j;
  printf("==================================\n");
  for(i = 0; i < 8; i++){
    for(j = 0; j < 16; j++){
      printf("%d ", buf[16*i + j]);
    }
    printf("\n");
  }
  printf("==================================\n");

  int k, max_idx1 = DIV_ROUND_UP(bytes_to_sectors(length), 128);
  disk_sector_t buf2[128];
  for(k = 0; k < max_idx1; k++)
  {
    disk_read_with_cache(buf[k], buf2);
    printf("=============  at %d  ============\n", buf[k]);
    for(i = 0; i < 8; i++){
      for(j = 0; j < 16; j++){
        printf("%d ", buf2[16*i + j]);
      }
      printf("\n");
    }
    printf("==================================\n");
  }
}

