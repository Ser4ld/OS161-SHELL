/*
 * Copyright (c) 2000, 2001, 2002, 2003, 2004, 2005, 2008, 2009
 *	The President and Fellows of Harvard College.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE UNIVERSITY AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE UNIVERSITY OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Sample/test code for running a user program.  You can use this for
 * reference when implementing the execv() system call. Remember though
 * that execv() needs to do more than runprogram() does.
 */

#include <types.h>
#include <kern/errno.h>
#include <kern/fcntl.h>
#include <kern/unistd.h> 
#include <lib.h>
#include <proc.h>
#include <current.h>
#include <addrspace.h>
#include <vm.h>
#include <vfs.h>
#include <syscall.h>
#include <test.h>
#include <copyinout.h>

/*
 * runprogram - Load and execute a user program
 *
 * This function:
 * 1. Opens stdin/stdout/stderr for the process (if not already open)
 * 2. Opens and loads the executable file
 * 3. Creates a new address space for the process
 * 4. Copies program arguments to the user stack
 * 5. Transfers control to user mode
 *
 * Arguments:
 *   progname - path to the executable file (e.g., "/bin/sh")
 *   argc - number of arguments (including program name)
 *   args - array of argument strings (e.g., ["ls", "-l", NULL])
 *
 * Returns:
 *   Does not return on success (transfers to user mode)
 *   Returns error code on failure 
 */
int
runprogram(char *progname, unsigned long argc, char **args)
{
	struct addrspace *as;
	struct vnode *v;
	vaddr_t entrypoint, stackptr;
	int result, i;
	size_t len;
	char **argvptr;
	vaddr_t uprogname[1];

	if (progname == NULL) {
		return EFAULT;
	}

#if OPT_FILE
	kprintf("RUNPROGRAM: OPT_FILE is ENABLED\n");
	/* Initialize console for stdin/stdout/stderr if not already open */
	if (curproc->fileTable[STDIN_FILENO] == NULL) {
		result = console_initialization("stdin_lock", curproc, STDIN_FILENO, O_RDONLY);
		if (result) {
			return result;
		}
		kprintf("DEBUG: stdin initialized successfully\n");
	}

	if (curproc->fileTable[STDOUT_FILENO] == NULL) {
		result = console_initialization("stdout_lock", curproc, STDOUT_FILENO, O_WRONLY);
		if (result) {
			return result;
		}
		kprintf("DEBUG: stdout initialized successfully\n");
	}

	if (curproc->fileTable[STDERR_FILENO] == NULL) {
		result = console_initialization("stderr_lock", curproc, STDERR_FILENO, O_WRONLY);
		if (result) {
			return result;
		}
		kprintf("DEBUG: stderr initialized successfully\n");
	}
#endif

	/* Open the file. */
	result = vfs_open(progname, O_RDONLY, 0, &v);
	if (result) {
		return result;
	}

	/* We should be a new process. */
	KASSERT(proc_getas() == NULL);

	/* Create a new address space. */
	as = as_create();
	if (as == NULL) {
		vfs_close(v);
		return ENOMEM;
	}

	/* Switch to it and activate it. */
	proc_setas(as);
	as_activate();

	/* Load the executable. */
	result = load_elf(v, &entrypoint);
	if (result) {
		/* p_addrspace will go away when curproc is destroyed */
		vfs_close(v);
		return result;
	}

	/* Done with the file now. */
	vfs_close(v);

	/* Define the user stack in the address space */
	result = as_define_stack(as, &stackptr);
	if (result) {
		/* p_addrspace will go away when curproc is destroyed */
		return result;
	}
   
	if (args != NULL && argc > 0) {
		/* Case 1: We have arguments - copy them all */
		argvptr = (char **) kmalloc(sizeof(char *) * (argc + 1));
		if (argvptr == NULL) {
			return ENOMEM;
		}
		
		/* Copy each argument string to user stack */
		for (i = argc - 1; i >= 0; i--) {
			len = strlen(args[i]) + 1;
			stackptr -= len;
			stackptr &= ~(vaddr_t)3;  
			
			result = copyoutstr(args[i], (userptr_t)stackptr, len, NULL);
			if (result) {
				kfree(argvptr);
				return result;
			}
			
			argvptr[i] = (char *)stackptr;
		}
		argvptr[argc] = NULL;
		
		/* Copy argv array to user stack */
		stackptr -= (argc + 1) * sizeof(char *);
		stackptr &= ~(vaddr_t)7; 
		
		result = copyout(argvptr, (userptr_t)stackptr, (argc + 1) * sizeof(char *));
		kfree(argvptr);
		if (result) {
			return result;
		}
		
		enter_new_process(argc, (userptr_t)stackptr, NULL, stackptr, entrypoint);
		
	} else {
		
		len = strlen(progname) + 1;
		stackptr -= len;
		stackptr &= ~(vaddr_t)3;  /* Align to 4 bytes */
		
		result = copyoutstr(progname, (userptr_t)stackptr, len, NULL);
		if (result) {
			return result;
		}
		
		uprogname[0] = stackptr;
		
		/* Copy argv array (just one pointer) to user stack */
		stackptr -= sizeof(vaddr_t);
		stackptr &= ~(vaddr_t)7;  /* Align to 8 bytes */
		
		result = copyout(uprogname, (userptr_t)stackptr, sizeof(vaddr_t));
		if (result) {
			return result;
		}
		
		enter_new_process(0, (userptr_t)stackptr, NULL, stackptr, entrypoint);
	}

	/* enter_new_process does not return. */
	panic("enter_new_process returned\n");
	return EINVAL;
}