/*
 * AUthor: G.Cabodi
 * Very simple implementation of sys_read and sys_write.
 * just works (partially) on stdin/stdout
 */

#include <types.h>
#include <kern/unistd.h>
#include <kern/errno.h>
#include <clock.h>
#include <syscall.h>
#include <current.h>
#include <lib.h>

#if OPT_FILE

#include <copyinout.h>
#include <vnode.h>
#include <vfs.h>
#include <limits.h>
#include <uio.h>
#include <proc.h>
#include <kern/seek.h>
#include <kern/stat.h>
#include <kern/fcntl.h>

/* max num of system wide open files */
#define SYSTEM_OPEN_MAX (10*OPEN_MAX)

#define USE_KERNEL_BUFFER 0

/* system open file table */
struct openfile {
  struct vnode *vn;
  off_t offset;	
  unsigned int countRef;
};

struct openfile systemFileTable[SYSTEM_OPEN_MAX];

void openfileIncrRefCount(struct openfile *of) {
  if (of!=NULL)
    of->countRef++;
}

#if USE_KERNEL_BUFFER

static int
file_read(int fd, userptr_t buf_ptr, size_t size, int *retval) {
  struct iovec iov;
  struct uio ku;
  int result, nread;
  struct vnode *vn;
  struct openfile *of;
  void *kbuf;

  if (fd < 0 || fd > OPEN_MAX)
    return EBADF;
  
  spinlock_acquire(&curproc->fileTable_spinlock);
  of = curproc->fileTable[fd];
  if (of==NULL) {
    spinlock_release(&curproc->fileTable_spinlock);
    return EBADF;
  }
  vn = of->vn;
  if (vn==NULL) {
    spinlock_release(&curproc->fileTable_spinlock);
    return EBADF;
  }

  kbuf = kmalloc(size);
  uio_kinit(&iov, &ku, kbuf, size, of->offset, UIO_READ);

  spinlock_release(&curproc->fileTable_spinlock);
  result = VOP_READ(vn, &ku);
  if (result) {
    return result;
  }

  spinlock_acquire(&curproc->fileTable_spinlock);

  of->offset = ku.uio_offset;

  spinlock_release(&curproc->fileTable_spinlock);

  nread = size - ku.uio_resid;
  copyout(kbuf,buf_ptr,nread);
  kfree(kbuf);

  *retval = (nread);
  return 0;
}

static int
file_write(int fd, userptr_t buf_ptr, size_t size, int *retval) {
  struct iovec iov;
  struct uio ku;
  int result, nwrite;
  struct vnode *vn;
  struct openfile *of;
  void *kbuf;

  if (fd < 0 || fd > OPEN_MAX)
    return EBADF;
  
  spinlock_acquire(&curproc->fileTable_spinlock);

  of = curproc->fileTable[fd];
  if (of == NULL) {
    spinlock_release(&curproc->fileTable_spinlock);
    return EBADF;
  }
  vn = of->vn;
  if (vn == NULL) {
    spinlock_release(&curproc->fileTable_spinlock);
    return EBADF;
  }

  kbuf = kmalloc(size);
  copyin(buf_ptr,kbuf,size);
  uio_kinit(&iov, &ku, kbuf, size, of->offset, UIO_WRITE);

  spinlock_release(&curproc->fileTable_spinlock);
  result = VOP_WRITE(vn, &ku);
  if (result) {
    return result;
  }
  kfree(kbuf);

  spinlock_acquire(&curproc->fileTable_spinlock);
  
  of->offset = ku.uio_offset;

  spinlock_release(&curproc->fileTable_spinlock);

  nwrite = size - ku.uio_resid;

  *retval = nwrite;
  return 0;
}

#else

static int
file_read(int fd, userptr_t buf_ptr, size_t size, int *retval) {
  struct iovec iov;
  struct uio u;
  int result;
  struct vnode *vn;
  struct openfile *of;

  if (fd < 0 || fd > OPEN_MAX)
    return EBADF;
  
  spinlock_acquire(&curproc->fileTable_spinlock);
  of = curproc->fileTable[fd];
  if (of==NULL) {
    spinlock_release(&curproc->fileTable_spinlock);
    return EBADF;
  }
  vn = of->vn;
  if (vn==NULL) {
    spinlock_release(&curproc->fileTable_spinlock);
    return EBADF;
  }

  iov.iov_ubase = buf_ptr;
  iov.iov_len = size;

  u.uio_iov = &iov;
  u.uio_iovcnt = 1;
  u.uio_resid = size;          // amount to read from the file
  u.uio_offset = of->offset;
  u.uio_segflg =UIO_USERISPACE;
  u.uio_rw = UIO_READ;
  u.uio_space = curproc->p_addrspace;

  spinlock_release(&curproc->fileTable_spinlock);
  result = VOP_READ(vn, &u);
  if (result) {
    return result;
  }

  spinlock_acquire(&curproc->fileTable_spinlock);

  of->offset = u.uio_offset;

  spinlock_release(&curproc->fileTable_spinlock);

  *retval = (size - u.uio_resid);
  return 0;
}

static int
file_write(int fd, userptr_t buf_ptr, size_t size, int *retval) {
  struct iovec iov;
  struct uio u;
  int result, nwrite;
  struct vnode *vn;
  struct openfile *of;

  if (fd < 0 || fd > OPEN_MAX)
    return EBADF;
  
  spinlock_acquire(&curproc->fileTable_spinlock);

  of = curproc->fileTable[fd];
  if (of == NULL) {
    spinlock_release(&curproc->fileTable_spinlock);
    return EBADF;
  }
  vn = of->vn;
  if (vn == NULL) {
    spinlock_release(&curproc->fileTable_spinlock);
    return EBADF;
  }

  iov.iov_ubase = buf_ptr;
  iov.iov_len = size;

  u.uio_iov = &iov;
  u.uio_iovcnt = 1;
  u.uio_resid = size;          // amount to read from the file
  u.uio_offset = of->offset;
  u.uio_segflg =UIO_USERISPACE;
  u.uio_rw = UIO_WRITE;
  u.uio_space = curproc->p_addrspace;

  spinlock_release(&curproc->fileTable_spinlock);
  result = VOP_WRITE(vn, &u);
  if (result) {
    return result;
  }

  spinlock_acquire(&curproc->fileTable_spinlock);

  of->offset = u.uio_offset;

  spinlock_release(&curproc->fileTable_spinlock);

  nwrite = size - u.uio_resid;

  *retval = nwrite;
  return 0;
}

#endif

/*
 * file system calls for open/close
 */
int
sys_open(userptr_t path, int openflags, mode_t mode, int *errp)
{
  int fd, i;
  struct vnode *v;
  struct openfile *of = NULL;
  char *kbuf;
  struct stat statbuf;
  int result;

  if(path == NULL) {
    *errp = EFAULT;
    return -1;
  }

  /* O_ACCMODE is a mask for O_RDONLY/O_WRONLY/O_RDWR */
  if((openflags & O_ACCMODE) != O_RDONLY && (openflags & O_ACCMODE) != O_WRONLY && (openflags & O_ACCMODE) != O_RDWR) {
    *errp = EINVAL;
    return -1;
  }

  if((kbuf = (char *)kmalloc(PATH_MAX)) == NULL) {
    *errp = ENOMEM;
    return -1;
  }

  result = copyinstr(path, kbuf, PATH_MAX, NULL);
  if(result) {
    kfree(kbuf);
    return result;
  }

  result = vfs_open((char *)path, openflags, mode, &v);
  if (result) {
    *errp = result;
    return -1;
  }
  /* search system open file table */
  for (i=0; i<SYSTEM_OPEN_MAX; i++) {
    if (systemFileTable[i].vn==NULL) {
      of = &systemFileTable[i];
      of->vn = v;
      of->offset = 0;
      of->countRef = 1;
      break;
    }
  }
  if (of==NULL) { 
    // no free slot in system open file table
    *errp = ENFILE;
  }
  else {
    if((openflags & O_APPEND) == O_APPEND) {
      VOP_STAT(of->vn, &statbuf);
      of->offset = statbuf.st_size;
    }

    spinlock_acquire(&curproc->fileTable_spinlock);
    for (fd=STDERR_FILENO+1; fd<OPEN_MAX; fd++) {
      if (curproc->fileTable[fd] == NULL) {
        curproc->fileTable[fd] = of;
        spinlock_release(&curproc->fileTable_spinlock);
        return fd;
      }
    }
    // no free slot in process open file table
    *errp = EMFILE;
    spinlock_release(&curproc->fileTable_spinlock);
  }
  
  vfs_close(v);
  return -1;
}

/*
 * file system calls for open/close
 */
int
sys_close(int fd)
{
  struct openfile *of=NULL; 
  struct vnode *vn;

  if (fd < 0 || fd > OPEN_MAX) 
    return EBADF;
  
  spinlock_acquire(&curproc->fileTable_spinlock);

  of = curproc->fileTable[fd];
  if (of == NULL) {
    spinlock_release(&curproc->fileTable_spinlock);
    return EBADF;
  }
  KASSERT(of->countRef > 0);

  curproc->fileTable[fd] = NULL;

  if (--of->countRef > 0) { // just decrement ref cnt
    spinlock_release(&curproc->fileTable_spinlock);
    return 0;
  }
  vn = of->vn;
  of->vn = NULL;
  if (vn == NULL) {
    spinlock_release(&curproc->fileTable_spinlock);
    return -1;
  }

  spinlock_release(&curproc->fileTable_spinlock);
  vfs_close(vn);

  return 0;
}

#endif

/*
 * simple file system calls for write/read
 */
int
sys_write(int fd, userptr_t buf_ptr, size_t size, int *retval)
{
  int i;
  char *p = (char *)buf_ptr;

  *retval = -1;

  if(fd < 0 || fd > OPEN_MAX)
    return EBADF;

  if(buf_ptr == NULL)
    return EFAULT;

  if (fd!=STDOUT_FILENO && fd!=STDERR_FILENO) {
#if OPT_FILE
    return file_write(fd, buf_ptr, size, retval);
#else
    kprintf("sys_write supported only to stdout\n");
    return -1;
#endif
  }

  for (i=0; i<(int)size; i++) {
    putch(p[i]);
  }

  *retval = (int)size;
  return 0;
}

int
sys_read(int fd, userptr_t buf_ptr, size_t size, int *retval)
{
  int i;
  char *p = (char *)buf_ptr;

  *retval = -1;

  if(fd < 0 || fd > OPEN_MAX)
    return EBADF;

  if(buf_ptr == NULL)
    return EFAULT;

  if (fd!=STDIN_FILENO) {
#if OPT_FILE
    return file_read(fd, buf_ptr, size, retval);
#else
    kprintf("sys_read supported only to stdin\n");
    return -1;
#endif
  }

  for (i=0; i<(int)size; i++) {
    p[i] = getch();
    if (p[i] < 0) {
      *retval = i;
      return 0;
    }
  }

  *retval = (int)size;
  return 0;
}

int
sys_lseek(int fd, off_t pos, int whence, int32_t *retval, int32_t *retval2)
{
  struct openfile *of = NULL;
  off_t new_offset;
  struct stat statbuf;

  *retval = -1;

  // return EBADF if not a valid file handle
  if (fd < 0|| fd > OPEN_MAX)
    return EBADF;

  spinlock_acquire(&curproc->fileTable_spinlock);

  // return EBADF if not a valid file handle
  of = curproc->fileTable[fd];
  if (of == NULL) {
    spinlock_release(&curproc->fileTable_spinlock);
    return EBADF;
  }

  // return ESPIPE if fd refers to an object which does not support seeking
  if(!VOP_ISSEEKABLE(of->vn)) {
    spinlock_release(&curproc->fileTable_spinlock);
    return ESPIPE;
  }

  new_offset = of->offset;

  // the new position is pos
  if(whence == SEEK_SET) {
    new_offset = pos;
  }
  // the new position is the current position plus pos
  else if(whence == SEEK_CUR) {
    new_offset += pos;
  }
  else if(whence == SEEK_END) {
    spinlock_release(&curproc->fileTable_spinlock);
    // spinlock released because VOP_STAT will acquire another spinlock
    VOP_STAT(of->vn, &statbuf);
    spinlock_acquire(&curproc->fileTable_spinlock);

    new_offset = statbuf.st_size + pos;
  }
  else {
    spinlock_release(&curproc->fileTable_spinlock);
    return EINVAL;
  }

  // seek positions less than zero are invalid
  if(new_offset < 0) {
    spinlock_release(&curproc->fileTable_spinlock);
    return EINVAL;
  }

  of->offset = new_offset;
  spinlock_release(&curproc->fileTable_spinlock);

  *retval = (int32_t)(new_offset >> 32); /* most significant bits */
  *retval2 = (int32_t)(new_offset & 0x00000000FFFFFFFF); /* least significant bits */

  return 0;
}

int 
sys_dup2(int oldfd, int newfd, int *retval)
{
  struct openfile *old_of = NULL, *new_of = NULL;
  int i;

  if (newfd < 0|| newfd > OPEN_MAX)
  return EBADF;

  if (oldfd < 0|| oldfd > OPEN_MAX)
    return EBADF;

  spinlock_acquire(&curproc->fileTable_spinlock);

  for (i=0; i<SYSTEM_OPEN_MAX; i++) {
    if (systemFileTable[i].vn==NULL)
      break;
  }
  // the system's file table was full
  if(i == SYSTEM_OPEN_MAX)
    return ENFILE;

  for (i=STDERR_FILENO+1; i<OPEN_MAX; i++) {
    if (curproc->fileTable[i] == NULL)
      break;
  }
  // the process's file table was full
  if(i == OPEN_MAX)
    return EMFILE;

  old_of = curproc->fileTable[oldfd];
  if (old_of == NULL) {
    spinlock_release(&curproc->fileTable_spinlock);
    return EBADF;
  }

  // using dup2 to clone a file handle onto itself has no effect
  if(oldfd == newfd) {
    *retval = newfd;
    spinlock_release(&curproc->fileTable_spinlock);
    return 0;
  }

  // if newfd names an already-open file, that file is closed
  new_of = curproc->fileTable[newfd];
  if(new_of != NULL) {
    sys_close(newfd);
  }

  curproc->fileTable[newfd] = curproc->fileTable[oldfd];
  openfileIncrRefCount(curproc->fileTable[newfd]);
  
  spinlock_release(&curproc->fileTable_spinlock);

  *retval = newfd;

  return 0;
}

int
sys_chdir(const_userptr_t pathname)
{
  char *path;
  int result;

  if((path = (char *)kmalloc(PATH_MAX)) == NULL) {
    return ENOMEM;
  }

  result = copyinstr(pathname, path, PATH_MAX, NULL);
  if(result) {
    kfree(path);
    return result;
  }

  // the current directory of the current process is set to the directory named by pathname
  result = vfs_chdir(path);
  kfree(path);

  return result;
}

int 
sys___getcwd(userptr_t buf, size_t buflen, int *retval)
{
  struct uio u_uio;
  struct iovec u_iov;
  int result;

  if(curproc->p_cwd == NULL)
    return ENOENT;

  // the given pointer belongs to user space, so we cannot use uio_kinit() function
  u_iov.iov_ubase = buf;
  u_iov.iov_len = buflen;
  u_uio.uio_iov = &u_iov;
  u_uio.uio_iovcnt = 1;
  u_uio.uio_offset = 0;
  u_uio.uio_resid = buflen;
  u_uio.uio_rw = UIO_READ;
  u_uio.uio_segflg = UIO_USERSPACE;
  u_uio.uio_space = curproc->p_addrspace;

  result = vfs_getcwd(&u_uio);
  if(result)
    return result;

  *retval = buflen - u_uio.uio_offset;

  return 0;
}