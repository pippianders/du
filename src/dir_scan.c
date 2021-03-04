/* ncdu - NCurses Disk Usage

  Copyright (c) 2007-2020 Yoran Heling

  Permission is hereby granted, free of charge, to any person obtaining
  a copy of this software and associated documentation files (the
  "Software"), to deal in the Software without restriction, including
  without limitation the rights to use, copy, modify, merge, publish,
  distribute, sublicense, and/or sell copies of the Software, and to
  permit persons to whom the Software is furnished to do so, subject to
  the following conditions:

  The above copyright notice and this permission notice shall be included
  in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
  CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
  TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
  SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*/

#include "global.h"

#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>

#if HAVE_SYS_ATTR_H && HAVE_GETATTRLIST && HAVE_DECL_ATTR_CMNEXT_NOFIRMLINKPATH
#include <sys/attr.h>
#endif

#if HAVE_LINUX_MAGIC_H && HAVE_SYS_STATFS_H && HAVE_FSTATFS
#include <sys/statfs.h>
#include <linux/magic.h>
#endif


/* set S_BLKSIZE if not defined already in sys/stat.h */
#ifndef S_BLKSIZE
# define S_BLKSIZE 512
#endif


int dir_scan_smfs; /* Stay on the same filesystem */

static uint64_t curdev;   /* current device we're scanning on */

/* scratch space */
static struct dir    *buf_dir;
static struct dir_ext buf_ext[1];


#if HAVE_LINUX_MAGIC_H && HAVE_SYS_STATFS_H && HAVE_FSTATFS
int exclude_kernfs; /* Exclude Linux pseudo filesystems */

static int is_kernfs(unsigned long type) {
  if(
#ifdef BINFMTFS_MAGIC
     type == BINFMTFS_MAGIC ||
#endif
#ifdef BPF_FS_MAGIC
     type == BPF_FS_MAGIC ||
#endif
#ifdef CGROUP_SUPER_MAGIC
     type == CGROUP_SUPER_MAGIC ||
#endif
#ifdef CGROUP2_SUPER_MAGIC
     type == CGROUP2_SUPER_MAGIC||
#endif
#ifdef DEBUGFS_MAGIC
     type == DEBUGFS_MAGIC ||
#endif
#ifdef DEVPTS_SUPER_MAGIC
     type == DEVPTS_SUPER_MAGIC ||
#endif
#ifdef PROC_SUPER_MAGIC
     type == PROC_SUPER_MAGIC ||
#endif
#ifdef PSTOREFS_MAGIC
     type == PSTOREFS_MAGIC ||
#endif
#ifdef SECURITYFS_MAGIC
     type == SECURITYFS_MAGIC ||
#endif
#ifdef SELINUX_MAGIC
     type == SELINUX_MAGIC ||
#endif
#ifdef SYSFS_MAGIC
     type == SYSFS_MAGIC ||
#endif
#ifdef TRACEFS_MAGIC
     type == TRACEFS_MAGIC ||
#endif
     0
    )
    return 1;

  return 0;
}
#endif

/* Populates the buf_dir and buf_ext with information from the stat struct.
 * Sets everything necessary for output_dir.item() except FF_ERR and FF_EXL. */
static void stat_to_dir(struct stat *fs) {
  buf_dir->flags |= FF_EXT; /* We always read extended data because it doesn't have an additional cost */
  buf_dir->ino = (uint64_t)fs->st_ino;
  buf_dir->dev = (uint64_t)fs->st_dev;

  if(S_ISREG(fs->st_mode))
    buf_dir->flags |= FF_FILE;
  else if(S_ISDIR(fs->st_mode))
    buf_dir->flags |= FF_DIR;

  if(!S_ISDIR(fs->st_mode) && fs->st_nlink > 1)
    buf_dir->flags |= FF_HLNKC;

  if(dir_scan_smfs && curdev != buf_dir->dev)
    buf_dir->flags |= FF_OTHFS;

  if(!(buf_dir->flags & (FF_OTHFS|FF_EXL|FF_KERNFS))) {
    buf_dir->size = fs->st_blocks * S_BLKSIZE;
    buf_dir->asize = fs->st_size;
  }

  buf_ext->mode  = fs->st_mode;
  buf_ext->mtime = fs->st_mtime;
  buf_ext->uid   = (int)fs->st_uid;
  buf_ext->gid   = (int)fs->st_gid;
}


static int dir_walk(int);


/* Scans and adds a single item. Recurses into dir_walk() again if this is a
 * directory. */
static int dir_scan_item(int parfd, const char *name) {
  static struct stat st, stl;
  int fail = 0, dirfd = -1;

#ifdef __CYGWIN__
  /* /proc/registry names may contain slashes */
  if(strchr(name, '/') || strchr(name,  '\\')) {
    buf_dir->flags |= FF_ERR;
    dir_setlasterr(dir_curpath);
  }
#endif

  if(exclude_match(dir_curpath))
    buf_dir->flags |= FF_EXL;

  if(!(buf_dir->flags & (FF_ERR|FF_EXL)) && fstatat(parfd, name, &st, AT_SYMLINK_NOFOLLOW)) {
    buf_dir->flags |= FF_ERR;
    dir_setlasterr(dir_curpath);
  }

  if(!(buf_dir->flags & (FF_ERR|FF_EXL)) && S_ISDIR(st.st_mode) && (dirfd = openat(parfd, name, O_RDONLY|O_DIRECTORY)) < 0) {
    buf_dir->flags |= FF_ERR;
    dir_setlasterr(dir_curpath);
  }

#if HAVE_LINUX_MAGIC_H && HAVE_SYS_STATFS_H && HAVE_FSTATFS
  if(exclude_kernfs && dirfd >= 0) {
    struct statfs fst;
    if(fstatfs(dirfd, &fst)) {
      buf_dir->flags |= FF_ERR;
      dir_setlasterr(dir_curpath);
    } else if(is_kernfs(fst.f_type))
      buf_dir->flags |= FF_KERNFS;
  }
#endif

  /* TODO: Completely broken; prolly needs absolute path lookup */
#if 0 && HAVE_SYS_ATTR_H && HAVE_GETATTRLIST && HAVE_DECL_ATTR_CMNEXT_NOFIRMLINKPATH
  if(!follow_firmlinks) {
    struct attrlist list = {
      .bitmapcount = ATTR_BIT_MAP_COUNT,
      .forkattr = ATTR_CMNEXT_NOFIRMLINKPATH,
    };
    struct {
      uint32_t length;
      attrreference_t reference;
      char extra[PATH_MAX];
    } __attribute__((aligned(4), packed)) attributes;
    if (getattrlist(name, &list, &attributes, sizeof(attributes), FSOPT_ATTR_CMN_EXTENDED) == -1) {
      buf_dir->flags |= FF_ERR;
      dir_setlasterr(dir_curpath);
    } else if (strcmp(dir_curpath, (char *)&attributes.reference + attributes.reference.attr_dataoffset))
      buf_dir->flags |= FF_FRMLNK;
  }
#endif

  if(!(buf_dir->flags & (FF_ERR|FF_EXL))) {
    if(follow_symlinks && S_ISLNK(st.st_mode) && !fstatat(parfd, name, &stl, 0) && !S_ISDIR(stl.st_mode))
      stat_to_dir(&stl);
    else
      stat_to_dir(&st);
  }

  if(cachedir_tags && dirfd >= 0 && !(buf_dir->flags & (FF_ERR|FF_EXL|FF_OTHFS|FF_KERNFS|FF_FRMLNK)))
    if(has_cachedir_tag(dirfd)) {
      buf_dir->flags |= FF_EXL;
      buf_dir->size = buf_dir->asize = 0;
    }

  if(dir_output.item(buf_dir, name, buf_ext)) {
    dir_seterr("Output error: %s", strerror(errno));
    fail = 1;
  }

  if(!fail && dirfd >= 0 && !(buf_dir->flags & (FF_ERR|FF_EXL|FF_OTHFS|FF_KERNFS|FF_FRMLNK))) {
    /* XXX: Can't do anything with the return value, since we've already outputted our dir entry item.
     * So errors reading dir items will be silently ignored. Not great. */
    dir_walk(dirfd);
    dirfd = -1;
  }

  if(!fail && (buf_dir->flags & FF_DIR) && dir_output.item(NULL, 0, NULL)) {
    dir_seterr("Output error: %s", strerror(errno));
    fail = 1;
  }

  if(dirfd >= 0)
    close(dirfd);

  return fail || input_handle(1);
}


/* Recursively walks through the directory descriptor. Will close() the given dirfd. */
static int dir_walk(int dirfd) {
  int fail = 0;
  DIR *dir;
  struct dirent *item;

  /* Illegal behavior: We're giving dirfd to fdopendir(), which in turn takes
   * control of the fd and we shouldn't be using it again. Yet we do use it
   * later on for openat() calls. I doubt this will be a problem, but may need
   * further testing. The alternative is to dup(), but that makes us run out of
   * descriptors twice as fast... */
  if((dir = fdopendir(dirfd)) == NULL) {
    close(dirfd);
    return -1;
  }

  while((item = readdir(dir)) != NULL) {
    if(item->d_name[0] == '.' && (item->d_name[1] == 0 || (item->d_name[1] == '.' && item->d_name[2] == 0)))
      continue;
    dir_curpath_enter(item->d_name);
    memset(buf_dir, 0, offsetof(struct dir, name));
    memset(buf_ext, 0, sizeof(struct dir_ext));
    fail |= dir_scan_item(dirfd, item->d_name);
    dir_curpath_leave();
  }

  if(errno)
    fail = 1;
  if(closedir(dir) < 0)
    fail = 1;
  return fail;
}


static int process(void) {
  char *path;
  int fail = 0, dirfd = -1;
  struct stat fs;

  memset(buf_dir, 0, offsetof(struct dir, name));
  memset(buf_ext, 0, sizeof(struct dir_ext));

  if((path = path_real(dir_curpath)) == NULL)
    dir_seterr("Error obtaining full path: %s", strerror(errno));
  else {
    dir_curpath_set(path);
    free(path);
  }

  if(!dir_fatalerr && path_chdir(dir_curpath) < 0)
    dir_seterr("Error changing directory: %s", strerror(errno));

  if(!dir_fatalerr && (dirfd = open(".", O_RDONLY|O_DIRECTORY)) < 0)
    dir_seterr("Error reading directory: %s", strerror(errno));

  if(!dir_fatalerr && fstat(dirfd, &fs) != 0)
    dir_seterr("Error obtaining directory information: %s", strerror(errno));

  if(!dir_fatalerr) {
    curdev = (uint64_t)fs.st_dev;
    if(fail)
      buf_dir->flags |= FF_ERR;
    stat_to_dir(&fs);

    if(dir_output.item(buf_dir, dir_curpath, buf_ext)) {
      dir_seterr("Output error: %s", strerror(errno));
      fail = 1;
    }
    if(!fail) {
      fail = dir_walk(dirfd);
      dirfd = -1;
    }
    if(!fail && dir_output.item(NULL, 0, NULL)) {
      dir_seterr("Output error: %s", strerror(errno));
      fail = 1;
    }
  }

  if(dirfd >= 0)
      close(dirfd);

  while(dir_fatalerr && !input_handle(0))
    ;
  return dir_output.final(dir_fatalerr || fail);
}


void dir_scan_init(const char *path) {
  dir_curpath_set(path);
  dir_setlasterr(NULL);
  dir_seterr(NULL);
  dir_process = process;
  if (!buf_dir)
    buf_dir = xmalloc(dir_memsize(""));
  pstate = ST_CALC;
}
