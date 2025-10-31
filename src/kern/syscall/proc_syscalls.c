#include <types.h>
#include <kern/unistd.h>
#include <kern/errno.h>
#include <kern/limits.h>
#include <clock.h>
#include <copyinout.h>
#include <syscall.h>
#include <limits.h>  
#include <lib.h>
#include <proc.h>
#include <thread.h>
#include <addrspace.h>
#include <mips/trapframe.h>
#include <current.h>
#include <synch.h>
#include <vfs.h>
#include <kern/fcntl.h>

#define MAX_PROC 100

/*
 * system calls for process management
 */
void
sys__exit(int status)
{
  KASSERT(curproc != NULL);

#if OPT_WAITPID
  struct proc *p = curproc;
  p->p_status = status & 0xff; /* just lower 8 bits returned */
  //proc_remthread(curthread);
  proc_signal_end(p);
#else
  /* get address space of current process and destroy */
  struct addrspace *as = proc_getas();
  as_destroy(as);
#endif
  thread_exit();

  panic("thread_exit returned (should not happen)\n");
  (void) status; // TODO: status handling
}

int
sys_waitpid(pid_t pid, userptr_t statusp, int options, int *retval)
{
  int result;
  int s;

  *retval = -1;

  if(pid < 0 || pid > MAX_PROC + 1)
    return ESRCH;
  
  if(options != 0)
    return EINVAL;

#if OPT_WAITPID
  struct proc *p = proc_search_pid(pid);

  if(p == NULL)
    return ESRCH;

  if(p == curproc)
    return EPERM;

  if(p == curproc->parent)
    return EPERM;

  if(p->parent != curproc)
    return ECHILD;

  s = proc_wait(p);

  if (statusp!=NULL) {
    result = copyout(&s, statusp, sizeof(int));
    if(result)
      return result;
  }

  *retval = pid;
  return 0;
#else
  (void)options; /* not handled */
  (void)pid;
  (void)statusp;
  return -1;
#endif
}

pid_t
sys_getpid(void)
{
#if OPT_WAITPID
  KASSERT(curproc != NULL);
  return curproc->p_pid;
#else
  return -1;
#endif
}

#if OPT_FORK
static void
call_enter_forked_process(void *tfv, unsigned long dummy) {
  struct trapframe *tf = (struct trapframe *)tfv;
  (void)dummy;
 
  enter_forked_process(tf); 
  panic("enter_forked_process returned (should not happen)\n");
}

int sys_fork(struct trapframe *ctf, pid_t *retval) {
  struct trapframe *tf_child;
  struct proc *newp;
  int result;

  KASSERT(curthread != NULL);
  KASSERT(curproc != NULL);
  KASSERT(curproc->p_pid < MAX_PROC);

  newp = proc_create_runprogram(curproc->p_name);
  if (newp == NULL) {
    return ENOMEM;
  }

#if OPT_FILE
  proc_addChild(curproc, newp->p_pid);
#endif

  result = as_copy(curproc->p_addrspace, &(newp->p_addrspace));
  if(result) {  
    proc_destroy(newp);
    return result;
  }  

  proc_file_table_copy(curproc, newp);

  /* we need a copy of the parent's trapframe */
  tf_child = kmalloc(sizeof(struct trapframe));
  if(tf_child == NULL){
    proc_destroy(newp);
    return ENOMEM; 
  }
  memcpy(tf_child, ctf, sizeof(struct trapframe));

  
  newp->parent = curproc;

  result = thread_fork(
		 curthread->t_name, newp,
		 call_enter_forked_process, 
		 (void *)tf_child, (unsigned long)0/*unused*/);

  if (result){
    proc_destroy(newp);
    kfree(tf_child);
    return ENOMEM;
  }

  *retval = newp->p_pid;
  return 0;
}
#endif

#if OPT_EXECV
int sys_execv(const char *program, char **args)
{
  int i, result, argc, arglen;
  char **kargs, **uargs;
  char *kprogname;
  struct vnode *v;
  struct addrspace *as;
  vaddr_t entrypoint, stackptr;


  if(program == NULL || args == NULL) {
    return EFAULT;
  }
  

  /* Count arguments */
  for(i=0; args[i]!=NULL; i++);

  KASSERT(args[i] == NULL);
  if(i >= ARG_MAX) {
    return E2BIG;
  }

  kargs = (char **) kmalloc(sizeof(char *) * i);
  if(kargs == NULL) {
    return ENOMEM;
  }

  /* Copy arguments */
  i = 0;
  while(args[i] != NULL) {
    kargs[i] = kmalloc(ARG_MAX);
    if(kargs[i] == NULL) {
      for(int j = 0; j < i; j++) kfree(kargs[j]);
      kfree(kargs);
      return ENOMEM;
    }

    result = copyinstr((userptr_t)args[i], kargs[i], ARG_MAX, NULL);
    if(result) {
      for(int j = 0; j <= i; j++) kfree(kargs[j]);
      kfree(kargs);
      return result;
    }
    i++;
  }
  
  argc = i;
  kargs[i] = NULL;

  /* Copy program name */
  kprogname = (char *)kmalloc(PATH_MAX);
  if(kprogname == NULL) {
    for(i = 0; i < argc; i++) kfree(kargs[i]);
    kfree(kargs);
    return ENOMEM;
  }

  result = copyinstr((userptr_t)program, kprogname, PATH_MAX, NULL);
  if(result) {
    for(i = 0; i < argc; i++) kfree(kargs[i]);
    kfree(kargs);
    kfree(kprogname);
    return result;
  }

  /* Open file */
  result = vfs_open(kprogname, O_RDONLY, 0, &v);
  if (result) {
    for(i = 0; i < argc; i++) kfree(kargs[i]);
    kfree(kargs);
    kfree(kprogname);
    return result;
  }

  /* Replace address space */ 
  proc_setas(NULL);
  KASSERT(proc_getas() == NULL);

  as = as_create();
  if (as == NULL) {
    vfs_close(v);
    for(i = 0; i < argc; i++) kfree(kargs[i]);
    kfree(kargs);
    kfree(kprogname);
    return ENOMEM;
  }

  proc_setas(as);
  as_activate();

  /* Load ELF */
  result = load_elf(v, &entrypoint);
  if (result) {
    vfs_close(v);
    for(i = 0; i < argc; i++) kfree(kargs[i]);
    kfree(kargs);
    kfree(kprogname);
    return result;
  }
  vfs_close(v);

  /* Set up stack */
  result = as_define_stack(as, &stackptr);
  if (result) {
    for(i = 0; i < argc; i++) kfree(kargs[i]);
    kfree(kargs);
    kfree(kprogname);
    return result;
  }

  /* Copy arguments to user stack */
  uargs = (char **)kmalloc(sizeof(char *) * argc);
  if(uargs == NULL) {
    for(i = 0; i < argc; i++) kfree(kargs[i]);
    kfree(kargs);
    kfree(kprogname);
    return ENOMEM;
  }
  uargs[argc] = NULL;

  for(i = 0; i < argc; i++) {
    arglen = strlen(kargs[i]) + 1;
    stackptr -= arglen;
    if(stackptr & 0x3)
      stackptr -= (stackptr & 0x3);

    result = copyoutstr(kargs[i], (userptr_t)stackptr, arglen, NULL);
    if(result) {
      for(int j = 0; j < argc; j++) kfree(kargs[j]);
      kfree(kargs);
      kfree(kprogname);
      kfree(uargs);
      return result;
    }
    uargs[i] = (char *)stackptr;
  }

  /* Copy argv array */
  stackptr -= sizeof(char *) * (argc + 1);

  result = copyout(uargs, (userptr_t)stackptr, sizeof(char *) * argc);
  if(result) {
    for(i = 0; i < argc; i++) kfree(kargs[i]);
    kfree(kargs);
    kfree(kprogname);
    kfree(uargs);
    return result;
  }

  /* Cleanup */
  for(i = 0; i < argc; i++) kfree(kargs[i]);
  kfree(kargs);
  kfree(kprogname);
  kfree(uargs);

  enter_new_process(argc, (userptr_t)stackptr, NULL, stackptr, entrypoint);
  
  panic("enter_new_process returned\n");
  return EINVAL;
}
#endif