/*
 * AUthor: G.Cabodi
 * Very simple implementation of sys__exit.
 * It just avoids crash/panic. Full process exit still TODO
 * Address space is released
 */

#include <types.h>
#include <kern/unistd.h>
#include <kern/errno.h>
#include <clock.h>
#include <copyinout.h>
#include <syscall.h>
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

  proc_addChild(curproc, newp->p_pid);

  /* done here as we need to duplicate the address space 
     of thbe current process */
  as_copy(curproc->p_addrspace, &(newp->p_addrspace));
  if(newp->p_addrspace == NULL){
    proc_destroy(newp);
    return ENOMEM; 
  }

  proc_file_table_copy(newp,curproc);

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
int
sys_execv(const char *program, char **args)
{
  int i, result, argc, arglen;
  char **kargs, **uargs;
  char *kprogname;
  struct vnode *v;
  struct addrspace *as;
  vaddr_t entrypoint, stackptr;
  size_t stackoffset = 0;

  if(program == NULL || args == NULL)
    return EFAULT;

  if(program == '\0')
    return ENOEXEC;
  
  /* The argument strings should be copied from user space to kernel */

  for(i=0;args[i]!=NULL;i++);
	KASSERT(args[i] == NULL);
	if(i >= ARG_MAX)
		return E2BIG;

	kargs = (char **) kmalloc(sizeof(char **) *i);
	if(kargs==NULL)
		return ENOMEM;

	i=0;
	while(args[i] != NULL) {
    kargs[i] = kmalloc(strlen(args[i])+1);
		if(kargs[i] == NULL)	
			return ENOMEM;

		result = copyinstr((userptr_t)args[i], kargs[i], strlen(args[i])+1, NULL);
		if(result) {
			kfree(kargs);
			return result;
		}
		i++;
	}
	argc = i;
	kargs[i] = NULL;

	kprogname = (char *)kmalloc(strlen(program)+1);
	if(kprogname == NULL)	
		return ENOMEM;
	result = copyinstr((userptr_t)program, kprogname, strlen(program)+1, NULL);
	if(result){
		kfree(kargs);
		kfree(kprogname);
		return result;
	}

  /* Open file, load elf into newly created address space */
	
	result = vfs_open(kprogname, O_RDONLY, 0, &v);
	if (result)
		return result;

  proc_setas(NULL);
	KASSERT(proc_getas() == NULL);

	as = as_create();
	if (as == NULL) {		
		vfs_close(v);
		return ENOMEM;
	}

	proc_setas(as);
	as_activate();

	result = load_elf(v, &entrypoint);
	if (result) {
		vfs_close(v);
		return result;
	}
	vfs_close(v);

	result = as_define_stack(as, &stackptr);
	if (result) {
		return result;
	}

	/* The argument strings should be copied into the new process as the new process's argv[] array */

	uargs = (char **)kmalloc(sizeof(char **) * argc);
	if(uargs == NULL)
		return ENOMEM;
	uargs[argc] = 0;

	for(i = 0; i < argc; ++i) {
		uargs[i] =(char*)kmalloc(sizeof(char*));
		if(uargs[i] == NULL)	
				return ENOMEM;
		arglen = strlen(kargs[i]) + 1;

		stackptr -= arglen;

		if(stackptr & 0x3)
			stackptr -= (stackptr & 0x3); //padding

		result = copyoutstr(kargs[i], (userptr_t)stackptr , arglen, NULL);
	
		if(result){
			kfree(kargs);
			return result;
		}

    // saving the address of the stackptr for each element
		uargs[i] = (char *)stackptr;
	}

  // adjusting stack head
	stackoffset += sizeof(char *)*(argc+1);
	stackptr = stackptr - stackoffset;

	result = copyout(uargs, (userptr_t) stackptr, sizeof(char *)*(argc));
	if(result){
		kfree(kargs);
		return result;
	}

	// return to user mode using enter_new_process
	enter_new_process(argc /*argc*/, (userptr_t)stackptr /*(void*)argsuserspace addr of argv*/,
			  NULL /*userspace addr of environment*/,
			  stackptr, entrypoint);
	
	panic("enter_new_process returned\n");
	return EINVAL;
}
#endif