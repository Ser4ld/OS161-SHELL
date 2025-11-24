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
 * Synchronization primitives.
 * The specifications of the functions are in synch.h.
 */

#include <types.h>
#include <lib.h>
#include <spinlock.h>
#include <wchan.h>
#include <thread.h>
#include <current.h>
#include <synch.h>

/* SEM implementation */

/*
 * sem_create - Create a new semaphore
 * 
 * Arguments:
 *   name - name for the semaphore (for debugging purposes)
 *   initial_count - initial value of the semaphore counter
 * 
 * Returns:
 *   Pointer to the newly created semaphore, or NULL on failure
 */
struct semaphore *
sem_create(const char *name, unsigned initial_count)
{
	struct semaphore *sem;

	sem = kmalloc(sizeof(*sem));
	if (sem == NULL) {
			return NULL;
	}

	sem->sem_name = kstrdup(name);
	if (sem->sem_name == NULL) {
			kfree(sem);
			return NULL;
	}

	sem->sem_wchan = wchan_create(sem->sem_name);
	if (sem->sem_wchan == NULL) {
		kfree(sem->sem_name);
		kfree(sem);
		return NULL;
	}

	spinlock_init(&sem->sem_lock);
	sem->sem_count = initial_count;

	return sem;
}

/*
 * sem_destroy - Destroy a semaphore
 * 
 * Arguments:
 *   sem - pointer to the semaphore to destroy
 * 
 * Returns:
 *   void
 * 
 * Notes:
 *   Panics if any threads are still waiting on the semaphore
 */
void
sem_destroy(struct semaphore *sem)
{
	KASSERT(sem != NULL);
	/* wchan_cleanup will assert if anyone's waiting on it */
	spinlock_cleanup(&sem->sem_lock);
	wchan_destroy(sem->sem_wchan);
	kfree(sem->sem_name);
	kfree(sem);
}

/*
 * P - Perform P (wait/down) operation on a semaphore
 * 
 * Arguments:
 *   sem - pointer to the semaphore
 * 
 * Returns:
 *   void
 * 
 * Notes:
 *   Blocks the calling thread if semaphore count is 0
 *   Decrements the semaphore count when acquired
 *   Cannot be called from interrupt context
 */
void
P(struct semaphore *sem)
{
	KASSERT(sem != NULL);
	KASSERT(curthread->t_in_interrupt == false);

	/* Use the semaphore spinlock to protect the wchan as well. */
	spinlock_acquire(&sem->sem_lock);
	while (sem->sem_count == 0) {
	wchan_sleep(sem->sem_wchan, &sem->sem_lock);
	}
	KASSERT(sem->sem_count > 0);
	sem->sem_count--;
	spinlock_release(&sem->sem_lock);
}

/*
 * V - Perform V (signal/up) operation on a semaphore
 * 
 * Arguments:
 *   sem - pointer to the semaphore
 * 
 * Returns:
 *   void
 * 
 * Notes:
 *   Increments the semaphore count
 *   Wakes up one waiting thread if any
 */
void
V(struct semaphore *sem)
{
	KASSERT(sem != NULL);

	spinlock_acquire(&sem->sem_lock);

	sem->sem_count++;
	KASSERT(sem->sem_count > 0);
	wchan_wakeone(sem->sem_wchan, &sem->sem_lock);

	spinlock_release(&sem->sem_lock);
}

/* Lock implementation */

/*
 * lock_create - Create a new lock
 * 
 * Arguments:
 *   name - name for the lock (for debugging purposes)
 * 
 * Returns:
 *   Pointer to the newly created lock, or NULL on failure
 */
struct lock *
lock_create(const char *name)
{
	struct lock *lock;

	lock = kmalloc(sizeof(*lock));
	if (lock == NULL) {
			return NULL;
	}

	lock->lk_name = kstrdup(name);
	if (lock->lk_name == NULL) {
			kfree(lock);
			return NULL;
	}

	HANGMAN_LOCKABLEINIT(&lock->lk_hangman, lock->lk_name);

#if OPT_SYNCH
#if USE_SEMAPHORE_FOR_LOCK
	lock->lk_sem = sem_create(name, 1);
	if (lock->lk_sem == NULL) {
		kfree(lock->lk_name);
		kfree(lock);
		return NULL;
	}
#else
	lock->lk_wchan = wchan_create(lock->lk_name);
	if (lock->lk_wchan == NULL) {
		kfree(lock->lk_name);
		kfree(lock);
		return NULL;
	}
#endif
	spinlock_init(&lock->lk_lock);
	lock->lk_owner = NULL;
#endif
	return lock;
}

/*
 * lock_destroy - Destroy a lock
 * 
 * Arguments:
 *   lock - pointer to the lock to destroy
 * 
 * Returns:
 *   void
 * 
 * Notes:
 *   Panics if the lock is still held by any thread
 */
void
lock_destroy(struct lock *lock)
{
	KASSERT(lock != NULL);
#if OPT_SYNCH
	KASSERT(lock->lk_owner == NULL);
#if USE_SEMAPHORE_FOR_LOCK
	sem_destroy(lock->lk_sem);
#else
	spinlock_cleanup(&lock->lk_lock);
	wchan_destroy(lock->lk_wchan);
#endif
#endif

	kfree(lock->lk_name);
	kfree(lock);
}

/*
 * lock_acquire - Acquire (lock) a lock
 * 
 * Arguments:
 *   lock - pointer to the lock to acquire
 * 
 * Returns:
 *   void
 * 
 * Notes:
 *   Blocks the calling thread until the lock is available
 *   Cannot be called from interrupt context
 */
void
lock_acquire(struct lock *lock)
{
#if OPT_SYNCH
	KASSERT(lock != NULL);
	KASSERT(curthread->t_in_interrupt == false);

#if USE_SEMAPHORE_FOR_LOCK
	P(lock->lk_sem);
	spinlock_acquire(&lock->lk_lock);
	lock->lk_owner = curthread;
	spinlock_release(&lock->lk_lock);
#else
	spinlock_acquire(&lock->lk_lock);
	while (lock->lk_owner != NULL) {
		wchan_sleep(lock->lk_wchan, &lock->lk_lock);
	}
	lock->lk_owner = curthread;
	spinlock_release(&lock->lk_lock);
#endif
#else
        (void)lock;
#endif
}

/*
 * lock_release - Release (unlock) a lock
 * 
 * Arguments:
 *   lock - pointer to the lock to release
 * 
 * Returns:
 *   void
 * 
 * Notes:
 *   Panics if the calling thread does not hold the lock
 *   Wakes up one waiting thread if any
 */
void
lock_release(struct lock *lock)
{
#if OPT_SYNCH
	KASSERT(lock != NULL);
	KASSERT(lock_do_i_hold(lock));

#if USE_SEMAPHORE_FOR_LOCK
	spinlock_acquire(&lock->lk_lock);
	lock->lk_owner = NULL;
	spinlock_release(&lock->lk_lock);
	V(lock->lk_sem);
#else
	spinlock_acquire(&lock->lk_lock);
	lock->lk_owner = NULL;
	wchan_wakeone(lock->lk_wchan, &lock->lk_lock);
	spinlock_release(&lock->lk_lock);
#endif
#else
        (void)lock;
#endif
}

/*
 * lock_do_i_hold - Check if current thread holds the lock
 * 
 * Arguments:
 *   lock - pointer to the lock to check
 * 
 * Returns:
 *   true if the current thread holds the lock, false otherwise
 */
bool
lock_do_i_hold(struct lock *lock)
{
#if OPT_SYNCH
	KASSERT(lock != NULL);
	
	bool result;
	spinlock_acquire(&lock->lk_lock);
	result = (lock->lk_owner == curthread);
	spinlock_release(&lock->lk_lock);
	
	return result;
#else
	(void)lock;
	return true;
#endif
}

/* CV implementation */

/*
 * cv_create - Create a new condition variable
 * 
 * Arguments:
 *   name - name for the condition variable (for debugging purposes)
 * 
 * Returns:
 *   Pointer to the newly created condition variable, or NULL on failure
 */
struct cv *
cv_create(const char *name)
{
	struct cv *cv;

	cv = kmalloc(sizeof(*cv));
	if (cv == NULL) {
			return NULL;
	}

	cv->cv_name = kstrdup(name);
	if (cv->cv_name==NULL) {
			kfree(cv);
			return NULL;
	}

#if OPT_SYNCH
	cv->cv_wchan = wchan_create(cv->cv_name);
	if (cv->cv_wchan == NULL) {
		kfree(cv->cv_name);
		kfree(cv);
		return NULL;
	}
	spinlock_init(&cv->cv_lock);
#endif

        return cv;
}

/*
 * cv_destroy - Destroy a condition variable
 * 
 * Arguments:
 *   cv - pointer to the condition variable to destroy
 * 
 * Returns:
 *   void
 * 
 * Notes:
 *   Panics if any threads are still waiting on the condition variable
 */
void
cv_destroy(struct cv *cv)
{
	KASSERT(cv != NULL);

#if OPT_SYNCH
	spinlock_cleanup(&cv->cv_lock);
	wchan_destroy(cv->cv_wchan);
#endif

	kfree(cv->cv_name);
	kfree(cv);
}

/*
 * cv_wait - Wait on a condition variable
 * 
 * Arguments:
 *   cv - pointer to the condition variable
 *   lock - pointer to the lock associated with the condition variable
 * 
 * Returns:
 *   void
 * 
 * Notes:
 *   Atomically releases the lock and blocks the calling thread
 *   Reacquires the lock before returning
 *   The calling thread must hold the lock when calling this function
 */
void
cv_wait(struct cv *cv, struct lock *lock)
{
#if OPT_SYNCH
	KASSERT(cv != NULL);
	KASSERT(lock != NULL);
	KASSERT(lock_do_i_hold(lock));

	spinlock_acquire(&cv->cv_lock);
	lock_release(lock);
	wchan_sleep(cv->cv_wchan, &cv->cv_lock);
	spinlock_release(&cv->cv_lock);
	lock_acquire(lock);
#else
        (void)cv;
        (void)lock;
#endif
}

/*
 * cv_signal - Signal (wake) one thread waiting on a condition variable
 * 
 * Arguments:
 *   cv - pointer to the condition variable
 *   lock - pointer to the lock associated with the condition variable
 * 
 * Returns:
 *   void
 * 
 * Notes:
 *   The calling thread must hold the lock when calling this function
 *   Wakes up at most one waiting thread
 */
void
cv_signal(struct cv *cv, struct lock *lock)
{
#if OPT_SYNCH
	KASSERT(cv != NULL);
	KASSERT(lock != NULL);
	KASSERT(lock_do_i_hold(lock));

	spinlock_acquire(&cv->cv_lock);
	wchan_wakeone(cv->cv_wchan, &cv->cv_lock);
	spinlock_release(&cv->cv_lock);
#else
	(void)cv;
	(void)lock; 
#endif
}

/*
 * cv_broadcast - Wake all threads waiting on a condition variable
 * 
 * Arguments:
 *   cv - pointer to the condition variable
 *   lock - pointer to the lock associated with the condition variable
 * 
 * Returns:
 *   void
 * 
 * Notes:
 *   The calling thread must hold the lock when calling this function
 *   Wakes up all waiting threads
 */
void
cv_broadcast(struct cv *cv, struct lock *lock)
{
#if OPT_SYNCH
	KASSERT(cv != NULL);
	KASSERT(lock != NULL);
	KASSERT(lock_do_i_hold(lock));

	spinlock_acquire(&cv->cv_lock);
	wchan_wakeall(cv->cv_wchan, &cv->cv_lock);
	spinlock_release(&cv->cv_lock);
#else
	(void)cv;
	(void)lock;
#endif
}
