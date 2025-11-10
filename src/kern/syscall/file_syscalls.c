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
#include <synch.h>

#define USE_KERNEL_BUFFER 0

struct openfile systemFileTable[SYSTEM_OPEN_MAX];
struct spinlock systemFileTable_spinlock = SPINLOCK_INITIALIZER;

void openfileIncrRefCount(struct openfile *of) {
  if (of != NULL) {
    lock_acquire(of->of_lock);
    of->countRef++;
    lock_release(of->of_lock);
  }
}


#if USE_KERNEL_BUFFER

/*
 * file_read - Read from a regular file using VFS layer and a kernel buffer
 *
 * Arguments:
 *   fd      - file descriptor (already validated by sys_read)
 *   buf_ptr - userspace pointer to buffer
 *   size    - number of bytes to read
 *   retval  - output parameter: bytes actually read
 *
 * Returns:
 *   0 on success (retval contains bytes read, may be < size if EOF)
 *   EBADF if fd is invalid, not open, or opened write-only
 *   ENOMEM if kernel buffer allocation fails
 *   EFAULT if copyout to userspace fails 
 */
static int
file_read(int fd, userptr_t buf_ptr, size_t size, int *retval) {
  struct iovec iov;
  struct uio ku;
  int result, nread;
  struct vnode *vn;
  struct openfile *of;
  void *kbuf;
  off_t offset;

  if (fd < 0 || fd >= OPEN_MAX)
    return EBADF;
  
  spinlock_acquire(&curproc->fileTable_spinlock);

  /* get openfile entry 
   * validation: check if openfile entry is null */
  of = curproc->fileTable[fd];
  if (of==NULL) {
    spinlock_release(&curproc->fileTable_spinlock);
    return EBADF;
  }

  /* get vnode entry 
   * validation: check if vnode is null */
  vn = of->vn;
  if (vn==NULL) {
    spinlock_release(&curproc->fileTable_spinlock);
    return EBADF;
  }

  spinlock_release(&curproc->fileTable_spinlock);

  spinlock_acquire(&of->of_lock);

  /* Check permission (O_WRONLY not allowed) */ 
  if ((of->openflags & O_ACCMODE) == O_WRONLY) {
    spinlock_release(&of->of_lock);
    return EBADF;
  }

  offset = of->offset;

  spinlock_release(&of->of_lock);

  /* Allocate kernel buffer for read */
  kbuf = kmalloc(size);
  if (kbuf == NULL) { 
    return ENOMEM;
  }

  /* Setup kernel space UIO for read */
  uio_kinit(&iov, &ku, kbuf, size, offset, UIO_READ);

  spinlock_release(&curproc->fileTable_spinlock);

  /* Perform read via VFS */
  result = VOP_READ(vn, &ku);
  if (result) {
    kfree(kbuf);
    return result;
  }

  /* Update file offset */
  spinlock_acquire(&curproc->fileTable_spinlock);
  of->offset = ku.uio_offset;
  spinlock_release(&curproc->fileTable_spinlock);

  /* Copy data from kernel buffer to userspace */
  nread = size - ku.uio_resid;
  result = copyout(kbuf,buf_ptr,nread);
  kfree(kbuf);

  if(result){
    return result;
  }

  *retval = (nread);
  return 0;
}

/*
 * file_write - Write to a regular file using kernel buffer
 * 
 * Arguments:
 *   fd - file descriptor (already validated by sys_write)
 *   buf_ptr - userspace pointer to buffer containing data
 *   size - number of bytes to write
 *   retval - output parameter: bytes actually written
 * 
 * Returns:
 *   0 on success (retval contains bytes written, may be < size)
 *   EBADF if fd is invalid, not open, or opened read-only
 *   ENOMEM if kernel buffer allocation fails
 *   EFAULT if buf_ptr points to invalid userspace memory
 *   Other error codes from VOP_WRITE()
 */
static int
file_write(int fd, userptr_t buf_ptr, size_t size, int *retval) {
  struct iovec iov;
  struct uio ku;
  int result, nwrite;
  struct vnode *vn;
  struct openfile *of;
  void *kbuf;

  if (fd < 0 || fd >= OPEN_MAX)
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

  if ((of->openflags & O_ACCMODE) == O_RDONLY) {
    spinlock_release(&curproc->fileTable_spinlock);
    return EBADF;
  }

  kbuf = kmalloc(size);
  if (kbuf == NULL) {
    spinlock_release(&curproc->fileTable_spinlock);
    return ENOMEM;
  }

  result = copyin(buf_ptr,kbuf,size);
  if (result) {
    kfree(kbuf);
    spinlock_release(&curproc->fileTable_spinlock);
    return result;
  }

  uio_kinit(&iov, &ku, kbuf, size, of->offset, UIO_WRITE);

  spinlock_release(&curproc->fileTable_spinlock);
  result = VOP_WRITE(vn, &ku);
  if (result) {
    kfree(kbuf);
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

/*
 * file_read - Read from a regular file using VFS layer
 * 
 * Arguments:
 *   fd - file descriptor (already validated by sys_read)
 *   buf_ptr - userspace pointer to buffer
 *   size - number of bytes to read
 *   retval - output parameter: bytes actually read
 * 
 * Returns:
 *   0 on success (retval contains bytes read, may be < size if EOF)
 *   EBADF if fd is invalid, not open, or opened write-only 
 */
static int
file_read(int fd, userptr_t buf_ptr, size_t size, int *retval) {
  struct iovec iov;
  struct uio u;
  int result;
  struct vnode *vn;
  struct openfile *of;

  if (fd < 0 || fd >= OPEN_MAX)
    return EBADF;
  
  spinlock_acquire(&curproc->fileTable_spinlock);

  /* get openfile entry 
   * validation: check if openfile entry is null */
  of = curproc->fileTable[fd];
  if (of==NULL) {
    spinlock_release(&curproc->fileTable_spinlock);
    return EBADF;
  }

  /* get vnode entry 
   * validation: check if vnode is null */
  vn = of->vn;
  if (vn==NULL) {
    spinlock_release(&curproc->fileTable_spinlock);
    return EBADF;
  }

  spinlock_release(&curproc->fileTable_spinlock);

  lock_acquire(of->of_lock);

  /* Check permission (O_WRONLY not allowed) */
  if ((of->openflags & O_ACCMODE) == O_WRONLY) {
    lock_release(of->of_lock);
    return EBADF; 
  }

  /* Setup UIO for direct userspace read 
   * - uio_iov: pointer to array of iovecs (scatter/gather I/O)
   * - uio_iovcnt: number of iovecs (we use just 1)
   * - uio_resid: residual count - bytes left to transfer (starts at size)
   * - uio_offset: file offset where to start reading
   * - uio_segflg: UIO_USERISPACE = buffer is in userspace
   * - uio_rw: UIO_READ = this is a read operation
   * - uio_space: address space of the buffer */
  iov.iov_ubase = buf_ptr;
  iov.iov_len = size;

  u.uio_iov = &iov;
  u.uio_iovcnt = 1;
  u.uio_resid = size;
  u.uio_offset = of->offset;
  u.uio_segflg =UIO_USERISPACE;
  u.uio_rw = UIO_READ;
  u.uio_space = curproc->p_addrspace;

  /* Perform read via VFS */
  result = VOP_READ(vn, &u);
  if (result) {
    lock_release(of->of_lock);
    return result;
  }

  /* Update file offset */

  of->offset = u.uio_offset;
  lock_release(of->of_lock);

  *retval = (size - u.uio_resid);
  return 0;
}


/*
 * file_write - Write to a regular file without kernel buffer
 * 
 * Arguments:
 *   fd - file descriptor (already validated by sys_write)
 *   buf_ptr - userspace pointer to buffer containing data
 *   size - number of bytes to write
 *   retval - output parameter: bytes actually written
 * 
 * Returns:
 *   0 on success (retval contains bytes written, may be < size)
 *   EBADF if fd is invalid, not open, or opened read-only
 *   Other error codes from VOP_WRITE()
 */
static int
file_write(int fd, userptr_t buf_ptr, size_t size, int *retval) {
  struct iovec iov;
  struct uio u;
  int result, nwrite;
  struct vnode *vn;
  struct openfile *of;

  if (fd < 0 || fd >= OPEN_MAX)
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

  spinlock_release(&curproc->fileTable_spinlock);

  lock_acquire(of->of_lock);

  if ((of->openflags & O_ACCMODE) == O_RDONLY) {
    lock_release(of->of_lock);
    return EBADF;  /* File aperto solo per lettura */
  }

  iov.iov_ubase = buf_ptr;
  iov.iov_len = size;

  u.uio_iov = &iov;
  u.uio_iovcnt = 1;
  u.uio_resid = size;
  u.uio_offset = of->offset;
  u.uio_segflg =UIO_USERISPACE;
  u.uio_rw = UIO_WRITE;
  u.uio_space = curproc->p_addrspace;

  result = VOP_WRITE(vn, &u);
  if (result) {
    lock_release(of->of_lock);
    return result;
  }

  of->offset = u.uio_offset;

  lock_release(of->of_lock);

  nwrite = size - u.uio_resid;
  *retval = nwrite;
  return 0;
}

#endif

/*
 * sys_open - Open a file and return a file descriptor
 * 
 * Arguments:
 *   path - userspace pointer to pathname string
 *   openflags - flags: O_RDONLY, O_WRONLY, O_RDWR, O_CREAT, O_EXCL, O_TRUNC, O_APPEND
 *   mode - permissions for newly created file (used only with O_CREAT)
 *   errp - output parameter for error code
 * 
 * Returns:
 *   >= 0: file descriptor on success
 *   -1: on error (errp contains error code)
 * 
 * Error codes:
 *   EFAULT - path is invalid pointer
 *   EINVAL - invalid openflags
 *   ENOMEM - out of memory
 *   ENOENT - file doesn't exist (without O_CREAT)
 *   ENFILE - system file table full
 *   EMFILE - process file table full
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

  if (path == NULL) {
    *errp = EFAULT;
    return -1;
  }

  /* Controllo modalità di apertura */
  if ((openflags & O_ACCMODE) != O_RDONLY && 
      (openflags & O_ACCMODE) != O_WRONLY && 
      (openflags & O_ACCMODE) != O_RDWR) {
    *errp = EINVAL;
    return -1;
  }

  /* Buffer kernel per il pathname */
  kbuf = (char *)kmalloc(PATH_MAX);
  if (kbuf == NULL) {
    *errp = ENOMEM;
    return -1;
  }

  /* Copia sicura da userspace */
  result = copyinstr(path, kbuf, PATH_MAX, NULL);
  if (result) {
    kfree(kbuf);
    *errp = result;
    return -1;
  }

  if (strlen(kbuf) == 0) {
    kfree(kbuf);
    *errp = EINVAL;
    return -1;
  }

  /* vfs_open: risolve il path e apre il file */
  result = vfs_open(kbuf, openflags, mode, &v);
  kfree(kbuf);

  if (result) {
    *errp = result;
    return -1;
  }

  /* Trova uno slot libero nella system file table */
  spinlock_acquire(&systemFileTable_spinlock);

  for (i = 0; i < SYSTEM_OPEN_MAX; i++) {
    if (systemFileTable[i].vn == NULL) {
      of = &systemFileTable[i];
      /* segnalino "occupato in init", per evitare reuse concorrente */
      of->vn = (struct vnode *)1;
      break;
    }
  }

  spinlock_release(&systemFileTable_spinlock);

  /* nessuno slot libero */
  if (of == NULL) {
    vfs_close(v);
    *errp = ENFILE;
    return -1;
  }

  /* Crea la lock dell'openfile */
  of->of_lock = lock_create("openfile_lock");
  if (of->of_lock == NULL) {
    spinlock_acquire(&systemFileTable_spinlock);
    of->vn = NULL;
    spinlock_release(&systemFileTable_spinlock);
    vfs_close(v);
    *errp = ENOMEM;
    return -1;
  }

  /* Inizializza l'openfile sotto il suo lock */
  lock_acquire(of->of_lock);

  of->vn = v;          /* sostituisce la sentinella */
  of->offset = 0;
  of->countRef = 1;
  of->openflags = openflags;

  /* Gestione O_APPEND: offset iniziale = file size */
  if ((openflags & O_APPEND) == O_APPEND) {
    result = VOP_STAT(of->vn, &statbuf);
    if (result) {
      of->vn = NULL;
      lock_release(of->of_lock);
      lock_destroy(of->of_lock);
      vfs_close(v);
      *errp = result;
      return -1;
    }
    of->offset = statbuf.st_size;
  }

  lock_release(of->of_lock);

  /* Inserisci of nella fileTable del processo */
  spinlock_acquire(&curproc->fileTable_spinlock);
  for (fd = STDERR_FILENO + 1; fd < OPEN_MAX; fd++) {
    if (curproc->fileTable[fd] == NULL) {
      curproc->fileTable[fd] = of;
      spinlock_release(&curproc->fileTable_spinlock);
      return fd;
    }
  }
  spinlock_release(&curproc->fileTable_spinlock);

  /* Nessun fd libero nel processo: pulizia */
  lock_acquire(of->of_lock);
  of->vn = NULL;
  of->countRef = 0;
  lock_release(of->of_lock);

  lock_destroy(of->of_lock);
  vfs_close(v);

  *errp = EMFILE;
  return -1;
}


/*
 * sys_close - Close a file descriptor
 * 
 * Arguments: 
 *  fd - file descriptor to close
 * 
 * Returns:
 *  0 on success
 *  EBADF if fd is invalid or not open    
 */
int
sys_close(int fd)
{
  struct openfile *of = NULL; 
  struct vnode *vn = NULL;
  struct lock *lock_to_destroy = NULL;

  /* Controllo fd */
  if (fd < 0 || fd >= OPEN_MAX) {
    return EBADF;
  }

  /* 1. Stacca il fd dalla file table del processo */
  spinlock_acquire(&curproc->fileTable_spinlock);

  of = curproc->fileTable[fd];
  if (of == NULL) {
    spinlock_release(&curproc->fileTable_spinlock);
    return EBADF;
  }

  curproc->fileTable[fd] = NULL;

  spinlock_release(&curproc->fileTable_spinlock);

  /* 2. Lavora sull'openfile sotto il suo lock */
  lock_acquire(of->of_lock);

  /* Se nel frattempo qualcuno ha "svuotato" l'openfile, tratti come EBADF */
  if (of->vn == NULL) {
    lock_release(of->of_lock);
    return EBADF;
  }

  vn = of->vn;

  KASSERT(of->countRef > 0);

  of->countRef--;

  if (of->countRef > 0) {
    /* altri riferimenti (altri fd/processi) usano ancora questo file */
    lock_release(of->of_lock);
    return 0;
  }

  /* 3. Ultimo riferimento: svuota l'openfile e prepara la chiusura reale */
  of->vn = NULL;        /* da qui in poi lo slot è "logicamente" libero */
  lock_to_destroy = of->of_lock;

  lock_release(of->of_lock);

  /* vfs_close chiude il vnode; nessun altro può più accedervi tramite questo of */
  vfs_close(vn);
  lock_destroy(lock_to_destroy);

  return 0;
}

#endif

/*
 * sys_write - Write data to a file descriptor
 *
 * Arguments:
 *   fd      - file descriptor to write to
 *   buf_ptr - userspace pointer to buffer containing data
 *   size    - number of bytes to write
 *   retval  - output parameter: number of bytes actually written
 *
 * Returns:
 *   0 on success (retval contains bytes written)
 *   EBADF if fd is invalid or not open
 *   EFAULT if buf_ptr is invalid userspace pointer
 *   EINVAL if file operations not supported (OPT_FILE not enabled) 
 */
int
sys_write(int fd, userptr_t buf_ptr, size_t size, int *retval)
{
  int i, result;
  char *kbuf;

  *retval = -1;

  if(fd < 0 || fd >= OPEN_MAX)
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

  kbuf = (char *)kmalloc(size);
  if (kbuf == NULL) {
    return ENOMEM;
  } 

  result = copyin(buf_ptr, kbuf, size);
  if (result) {
    kfree(kbuf);
    return result;
  } 

  for (i=0; i<(int)size; i++) {
    putch(kbuf[i]);
  }

  kfree(kbuf);
  *retval = (int)size;
  return 0;
}

/*
 * sys_read - Read data from a file descriptor
 * 
 * Arguments:
 *   fd - file descriptor to read from
 *   buf_ptr - userspace pointer to buffer where data will be stored
 *   size - number of bytes to read
 *   retval - output parameter: number of bytes actually read
 * 
 * Returns:
 *   0 on success (retval contains bytes read)
 *   EBADF if fd is invalid or not open
 *   EFAULT if buf_ptr is invalid userspace pointer
 *   ENOMEM if out of memory (kernel buffer allocation failed)
 *   EINVAL if file operations not supported (OPT_FILE not enabled) 
 */
int
sys_read(int fd, userptr_t buf_ptr, size_t size, int *retval)
{
  int i, result;
  char *kbuf;
  *retval = -1;

  if(fd < 0 || fd >= OPEN_MAX)
    return EBADF;

  if(buf_ptr == NULL)
    return EFAULT;

  /* For all file descriptors except stdin (fd=0),
   * use the full VFS-based file I/O system */  
  if (fd!=STDIN_FILENO) {
#if OPT_FILE
  return file_read(fd, buf_ptr, size, retval);
#else
  kprintf("sys_read supported only to stdin\n");
  return EINVAL;
#endif
  }

  /* Use kernel buffer for secure data transfer from kernel to userspace. */
  kbuf = (char *)kmalloc(size);
  if (kbuf == NULL) {
    return ENOMEM;
  }

  /* Read character-by-character from console
   * 
   * getch() behavior:
   * - Blocks waiting for keyboard input
   * - Returns character code (0-255) on success
   * - Returns negative value on EOF or error */
  for (i=0; i<(int)size; i++) {
    kbuf[i] = getch();
    if (kbuf[i] < 0) { /* EOF or error encountered - handle partial read */
      result = copyout(kbuf, buf_ptr, i);
      kfree(kbuf);
      if(result) /* copyout failed - buf_ptr was invalid */
        return result;
      *retval = i;
      return 0;
    }
  }

  /* Successfully read all requested bytes */
  result = copyout(kbuf, buf_ptr, size);
  kfree(kbuf);

  /* copyout failed - buf_ptr was invalid*/
  if(result)
    return result;

  *retval = (int)size;
  return 0;
}

/*
 * sys_lseek - Reposition read/write file offset
 * 
 * Arguments:
 *   fd - file descriptor to reposition
 *   pos - offset value (interpretation depends on whence)
 *   whence - how to interpret pos (SEEK_SET, SEEK_CUR, SEEK_END)
 *   retval - output parameter: high 32 bits of new offset
 *   retval2 - output parameter: low 32 bits of new offset
 * 
 * Returns:
 *   0 on success (retval/retval2 contain 64-bit offset split in two 32-bit values)
 *   EBADF if fd is invalid or not open
 *   ESPIPE if fd refers to non-seekable object (pipe, console, etc.)
 *   EINVAL if whence is invalid or resulting offset is negative*/
int
sys_lseek(int fd, off_t pos, int whence, int32_t *retval, int32_t *retval2)
{
  struct openfile *of = NULL;
  struct vnode *vn = NULL;
  off_t new_offset;
  struct stat statbuf;
  int result;

  *retval = -1;

  // return EBADF if not a valid file handle
  if (fd < 0|| fd >= OPEN_MAX)
    return EBADF;

  spinlock_acquire(&curproc->fileTable_spinlock);

  // return EBADF if not a valid file handle
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

  // return ESPIPE if fd refers to an object which does not support seeking
  if(!VOP_ISSEEKABLE(vn)) {
    spinlock_release(&curproc->fileTable_spinlock);
    return ESPIPE;
  }

  spinlock_release(&curproc->fileTable_spinlock);


  // the new position is pos
  switch (whence) {
      case SEEK_SET:
        new_offset = pos;
        break;
        
      case SEEK_CUR:
        lock_acquire(of->of_lock);
        
        if (of->vn != vn) {
          lock_release(of->of_lock);
          return EBADF;
        }
        
        new_offset = of->offset + pos;
        lock_release(of->of_lock);
        break;
        
      case SEEK_END:
        
        result = VOP_STAT(vn, &statbuf);
        if (result) {
          return result;
        }
        
        new_offset = statbuf.st_size + pos;
        break;
        
      default:
        return EINVAL;
    }

  // seek positions less than zero are invalid
  if(new_offset < 0) {
    return EINVAL;
  }

  lock_acquire(of->of_lock);
  if (of->vn != vn) {
    lock_release(of->of_lock);
    return EBADF;
  }

  of->offset = new_offset;
  lock_release(of->of_lock);


  *retval = (int32_t)(new_offset >> 32); /* most significant bits */
  *retval2 = (int32_t)(new_offset & 0x00000000FFFFFFFF); /* least significant bits */

  return 0;
}

/*
 * sys_dup2 - Duplicate a file descriptor to a specific descriptor number
 * 
 * Arguments:
 *   oldfd - existing file descriptor to duplicate
 *   newfd - target file descriptor number
 *   retval - output parameter: returns newfd on success
 * 
 * Returns:
 *   0 on success (retval contains newfd)
 *   EBADF if oldfd is not a valid open file descriptor
 *   EBADF if newfd is out of valid range [0, OPEN_MAX)
 */
int 
sys_dup2(int oldfd, int newfd, int *retval)
{
  struct openfile *old_of = NULL, *new_of = NULL;
  struct vnode *vn_to_close = NULL;
  struct lock *lock_to_destroy = NULL;

  if (newfd < 0|| newfd >= OPEN_MAX)
    return EBADF;

  if (oldfd < 0|| oldfd >= OPEN_MAX)
    return EBADF;

  spinlock_acquire(&curproc->fileTable_spinlock);

  old_of = curproc->fileTable[oldfd];
  if (old_of == NULL) {
    spinlock_release(&curproc->fileTable_spinlock);
    return EBADF;
  }

  if (oldfd == newfd) {
    *retval = newfd;
    spinlock_release(&curproc->fileTable_spinlock);
    return 0;
  }
  
  new_of = curproc->fileTable[newfd];
  curproc->fileTable[newfd] = old_of;

  spinlock_release(&curproc->fileTable_spinlock);

  lock_acquire(old_of->of_lock);
  old_of->countRef++;
  lock_release(old_of->of_lock);

  if (new_of != NULL) {
    lock_acquire(new_of->of_lock);
    
    KASSERT(new_of->countRef > 0);
    new_of->countRef--;
    
    if (new_of->countRef > 0) {
      /* Other processes still using this file - just release and continue */
      lock_release(new_of->of_lock);
    } else {
      /* countRef == 0 - we are the last one, cleanup needed */
      vn_to_close = new_of->vn;
      new_of->vn = NULL;
      lock_to_destroy = new_of->of_lock;
      
      lock_release(new_of->of_lock);
      
      /* Cleanup (outside lock - vfs_close can block) */
      vfs_close(vn_to_close);
      lock_destroy(lock_to_destroy);
    }
  }

  *retval = newfd;
  return 0;
}

/*
 * sys_chdir - Change current working directory
 * 
 * Arguments:
 *   pathname - userspace pointer to null-terminated path string
 * 
 * Returns:
 *   0 on success
 *   EFAULT if pathname is invalid userspace pointer
 *   ENAMETOOLONG if pathname exceeds PATH_MAX
 *   ENOENT if pathname does not exist
 *   ENOTDIR if pathname is not a directory
 *   ENOMEM if kernel memory allocation fails
 *   EIO on I/O error
 */
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


/*
 * sys___getcwd - Get current working directory pathname
 * 
 * Arguments:
 *   buf - userspace buffer to store the pathname
 *   buflen - size of the buffer in bytes
 *   retval - output parameter: actual length of pathname (including null terminator)
 * 
 * Returns:
 *   0 on success (retval contains pathname length)
 *   ENOENT if current directory no longer exists or is not reachable
 *   EFAULT if buf is invalid userspace pointer
 *   ERANGE if buflen is too small for the pathname
 *   EIO on I/O error
 */
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

  *retval = buflen - u_uio.uio_resid;

  return 0;
}