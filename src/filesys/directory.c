#include "filesys/directory.h"
#include <stdio.h>
#include <string.h>
#include <list.h>
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "filesys/cache.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "threads/thread.h"

/* A directory. */
struct dir 
  {
    struct inode *inode;                /* Backing store. */
    off_t pos;                          /* Current position. */
  };

/* A single directory entry. */
struct dir_entry 
  {
    disk_sector_t inode_sector;         /* Sector number of header. */
    char name[NAME_MAX + 1];            /* Null terminated file name. */
    bool in_use;                        /* In use or free? */
  };

/* Creates a directory with space for ENTRY_CNT entries in the
   given SECTOR.  Returns true if successful, false on failure. */
bool
dir_create (disk_sector_t sector, size_t entry_cnt, disk_sector_t parent)
{
  bool success = inode_create (sector, entry_cnt * sizeof (struct dir_entry), true);
  if(success){
    struct dir *dir = dir_open(inode_open(sector));
    dir_add(dir, ".", sector);
    dir_add(dir, "..", parent);
    dir_close(dir);
  }
  return success;
}

/* Opens and returns the directory for the given INODE, of which
   it takes ownership.  Returns a null pointer on failure. */
struct dir *
dir_open (struct inode *inode) 
{
  struct dir *dir = calloc (1, sizeof *dir);
  if (inode != NULL && dir != NULL && inode->is_dir)
    {
      dir->inode = inode;
      dir->pos = 0;
      return dir;
    }
  else
    {
      inode_close (inode);
      free (dir);
      return NULL; 
    }
}

/* Opens the root directory and returns a directory for it.
   Return true if successful, false on failure. */
struct dir *
dir_open_root (void)
{
  return dir_open (inode_open (ROOT_DIR_SECTOR));
}

/* Opens and returns a new directory for the same inode as DIR.
   Returns a null pointer on failure. */
struct dir *
dir_reopen (struct dir *dir) 
{
  return dir_open (inode_reopen (dir->inode));
}

/* Destroys DIR and frees associated resources. */
void
dir_close (struct dir *dir) 
{
  if (dir != NULL)
    {
      inode_close (dir->inode);
      free (dir);
    }
}

/* Returns the inode encapsulated by DIR. */
struct inode *
dir_get_inode (struct dir *dir) 
{
  return dir->inode;
}

/* Searches DIR for a file with the given NAME.
   If successful, returns true, sets *EP to the directory entry
   if EP is non-null, and sets *OFSP to the byte offset of the
   directory entry if OFSP is non-null.
   otherwise, returns false and ignores EP and OFSP. */
static bool
lookup (const struct dir *dir, const char *name,
        struct dir_entry *ep, off_t *ofsp) 
{
  struct dir_entry e;
  size_t ofs;
  
  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e) 
    if (e.in_use && !strcmp (name, e.name)) 
      {
        if (ep != NULL)
          *ep = e;
        if (ofsp != NULL)
          *ofsp = ofs;
        return true;
      }
  return false;
}

/* Searches DIR for a file with the given NAME
   and returns true if one exists, false otherwise.
   On success, sets *INODE to an inode for the file, otherwise to
   a null pointer.  The caller must close *INODE. */
bool
dir_lookup (const struct dir *dir, const char *name,
            struct inode **inode) 
{
  struct dir_entry e;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  if(name[0] == '\0'){
    *inode = inode_reopen(dir->inode);
    return inode != NULL;
  }

  if (lookup (dir, name, &e, NULL))
    *inode = inode_open (e.inode_sector);
  else
    *inode = NULL;

  return *inode != NULL;
}

/* Adds a file named NAME to DIR, which must not already contain a
   file by that name.  The file's inode is in sector
   INODE_SECTOR.
   Returns true if successful, false on failure.
   Fails if NAME is invalid (i.e. too long) or a disk or memory
   error occurs. */
bool
dir_add (struct dir *dir, const char *name, disk_sector_t inode_sector) 
{
  struct dir_entry e;
  off_t ofs;
  bool success = false;
  
  ASSERT (dir != NULL);
  ASSERT (name != NULL);

/*  if(dir->inode->removed)
    return false;*/

  /* Check NAME for validity. */
  if (*name == '\0' || strlen (name) > NAME_MAX)
    return false;

  /* Check that NAME is not in use. */
  if (lookup (dir, name, NULL, NULL))
    goto done;

  /* Set OFS to offset of free slot.
     If there are no free slots, then it will be set to the
     current end-of-file.
     
     inode_read_at() will only return a short read at end of file.
     Otherwise, we'd need to verify that we didn't get a short
     read due to something intermittent such as low memory. */
  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e) 
    if (!e.in_use)
      break;

  /* Write slot. */
  e.in_use = true;
  strlcpy (e.name, name, sizeof e.name);
  e.inode_sector = inode_sector;
  success = inode_write_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
  if(success){
    lock_acquire(&dir->inode->lock);
    struct inode_disk *d = malloc(sizeof(struct inode_disk));
    if(d == NULL) PANIC("malloc fail at dir_add");
    disk_read_with_cache(dir->inode->sector, d);
    d->entry_cnt++;
    disk_write_with_cache(dir->inode->sector, d);
    dir->inode->entry_cnt++;
    lock_release(&dir->inode->lock);
    free(d);
  }
 done:
  return success;
}

/* Removes any entry for NAME in DIR.
   Returns true if successful, false on failure,
   which occurs only if there is no file with the given NAME. */
bool
dir_remove (struct dir *dir, const char *name) 
{
  struct dir_entry e;
  struct inode *inode = NULL;
  bool success = false;
  off_t ofs;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* Find directory entry. */
  if (!lookup (dir, name, &e, &ofs))
    goto done;

  /* Open inode. */
  inode = inode_open (e.inode_sector);
  if (inode == NULL)
    goto done;

  if(inode->is_dir && inode->entry_cnt > 2)
    goto done;

  /* Erase directory entry. */
  e.in_use = false;
  if (inode_write_at (dir->inode, &e, sizeof e, ofs) != sizeof e) 
    goto done;

  /* Remove inode. */
  inode_remove (inode);
  success = true;
  struct inode_disk *d = malloc(sizeof(struct inode_disk));
  if(d == NULL) PANIC("malloc fail at dir_remove");
  disk_read_with_cache(dir->inode->sector, d);
  d->entry_cnt--;
  disk_write_with_cache(dir->inode->sector, d);
  dir->inode->entry_cnt--;
  free(d);

/*  if(inode->is_dir){
    struct dir_entry erase_rel = {0,};
    inode_write_at(inode, &erase_rel, sizeof e, 0);
    inode_write_at(inode, &erase_rel, sizeof e, sizeof e);
  }*/

 done:
  inode_close (inode);
  return success;
}

/* Reads the next directory entry in DIR and stores the name in
   NAME.  Returns true if successful, false if the directory
   contains no more entries. */
bool
dir_readdir (struct dir *dir, char name[NAME_MAX + 1])
{
  struct dir_entry e;

  while (inode_read_at (dir->inode, &e, sizeof e, dir->pos) == sizeof e) 
    {
      dir->pos += sizeof e;
      if (e.in_use)
        {
          strlcpy (name, e.name, NAME_MAX + 1);
          return true;
        } 
    }
  return false;
}


struct dir *
dir_open_path(const char *dir, char *fname_save)
{
  if(strlen(dir) == 0) return NULL;
//  printf("@dir_open_path: full path name %s\n", dir);
  struct thread *curr = thread_current();
  struct dir *path;

  char dir_copy[PATH_MAX + 1];
  strlcpy(dir_copy, dir, PATH_MAX + 1);
  if(dir_copy[0] == '/')
    path = dir_open_root();
  else
    path = curr->wd ? dir_reopen(curr->wd) : dir_open_root();

  if(path->inode->removed){
    dir_close(path);
    return NULL;
  }

  int i;
  for(i = strlen(dir_copy); i >= 0; i--){
    if(dir_copy[i] == '/'){
      dir_copy[i] = '\0';
      break;
    }
  }

  if(strlen(&dir_copy[i + 1]) > NAME_MAX) return NULL;

  strlcpy(fname_save, &dir_copy[i + 1], NAME_MAX);
  if(i == -1){
//    printf("@dir_open_path: no slash_single word input %s\n", &dir_copy[i + 1]);
    return path;
  }

//  printf("@dir_open_path: pathname %s, filename %s\n", dir_copy, &dir_copy[i + 1]);
  char *token, *save_ptr;
  for(token = strtok_r(dir_copy, "/", &save_ptr); token != NULL; token = strtok_r(NULL, "/", &save_ptr)){
    struct inode *inode;
    bool success = dir_lookup(path, token, &inode);
    dir_close(path);
    path = dir_open(inode);
    if(path == NULL) return NULL;
  }
  return path;
}

bool
change_dir(const char *dir)
{
  struct thread *curr = thread_current();
  char dirname[NAME_MAX + 1];
  struct dir *path = dir_open_path(dir, dirname);
  struct inode *inode;

  bool success = (path != NULL
                  && dir_lookup(path, dirname, &inode)
                  && inode->is_dir);
  if(success){
    dir_close(curr->wd);
    curr->wd = dir_open(inode);
  }

  return success;
}

bool
make_dir(const char *dir)
{
//  printf("@make_dir: full path %s\n", dir);
  char name[NAME_MAX + 1];
  struct dir *path = dir_open_path(dir, name);
//  printf("@make_dir: name %s\n", name);
  disk_sector_t inode_sector = 0;

  bool success = (path != NULL
                  && free_map_allocate (1, &inode_sector)
                  && dir_create(inode_sector, 16, path->inode->sector)
                  && dir_add (path, name, inode_sector));
  if (!success && inode_sector != 0)
    free_map_release (inode_sector, 1);
  dir_close (path);

//  printf("@make_dir: finished\n");
  return success;
}

bool
read_dir(struct dir *dir, char *name)
{
  char save[NAME_MAX +1];
  bool success;
  while(success = dir_readdir(dir, save)){
    if(strcmp(save, ".") != 0 && strcmp(save, "..") != 0)
      break;
  }
  if(success) strlcpy(name, save, NAME_MAX + 1);

  return success;
}
