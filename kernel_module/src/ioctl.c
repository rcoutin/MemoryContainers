//////////////////////////////////////////////////////////////////////
//                      North Carolina State University
//
//
//
//                             Copyright 2018
//
////////////////////////////////////////////////////////////////////////
//
// This program is free software; you can redistribute it and/or modify it
// under the terms and conditions of the GNU General Public License,
// version 2, as published by the Free Software Foundation.
//
// This program is distributed in the hope it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
//
////////////////////////////////////////////////////////////////////////
//
//   Author:  Hung-Wei Tseng, Yu-Chia Liu
//
//   Description:
//     Core of Kernel Module for Processor Container
//
////////////////////////////////////////////////////////////////////////

#include "memory_container.h"

#include <asm/uaccess.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/poll.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/kthread.h>

// Global container list
struct container* container_list = NULL;
struct mutex* lock = NULL;

// Structures for containers and tasks

// Tasks
struct task{
    pid_t pid;
    struct task* next;
    struct task* prev;
};

// Containers
struct container{
    __u64 container_id;
    char* cont_mem;
    struct container* next;
    struct container* prev;
    struct mutex * local_lock;
    struct task* task_head;
    unsigned long count;
    struct mutex** locks;
    unsigned long count_locks;
};

struct container* find_container(pid_t pid){
    printk("Finding container for task %d\n", pid);
    struct container* cur = container_list;
    while(cur!=NULL){

        struct task* cur_task = cur -> task_head;

        while(cur_task!=NULL){
            if(cur_task -> pid == pid){
                printk("Found container %lld for task %d\n",cur->container_id, pid);
                return cur;
            }
            else{
                cur_task = cur_task -> next;
            }
        }
        cur = cur -> next;
    }
    printk("Could not find container for task!");
    return NULL;
}


int memory_container_mmap(struct file *filp, struct vm_area_struct *vma)
{
    printk("mmap for task %d\n", current->pid);

    //void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
    printk("\n%lu\nvm_start: ",vma->vm_start);
    printk("%lu\nvm_end: ",vma->vm_end);
    //get the oid and object size here
    printk("%lu\nvm_pgoff: ",vma->vm_pgoff);
    //get the container for this task

    mutex_lock(lock);
    struct container* cont = find_container(current->pid);
    mutex_unlock(lock);
    
    unsigned long obj_size = vma->vm_end - vma->vm_start;

    printk("Container ID: %lu, Process ID: %ld", cont->container_id, current->pid);
    if(cont!=NULL){
        //check if memory has already been allocated in the container
        
        if(cont-> cont_mem == NULL){
            cont -> cont_mem = (char *) kcalloc(1,obj_size,GFP_KERNEL);
        }

        if((cont->count)-1 < vma->vm_pgoff){
            cont->cont_mem = (char*) krealloc(cont->cont_mem, sizeof(char)*(cont->count)*2, GFP_KERNEL);
            cont->count = (cont->count)*2;
            printk("Found container. Reallocing");
        }

    }else{
        printk("Could not find container at mcontainer lock");
    }
    
    phys_addr_t pfn = virt_to_phys(cont->cont_mem + (obj_size*vma->vm_pgoff)) >> PAGE_SHIFT;
    printk("finished mmap for task %d\n", current->pid);
    return remap_pfn_range(vma, vma->vm_start, pfn, obj_size, vma->vm_page_prot);
}

int memory_container_lock(struct memory_container_cmd __user *user_cmd)
{
    struct memory_container_cmd kmemory_container_cmd;
    unsigned long ret = copy_from_user(&kmemory_container_cmd, user_cmd, sizeof(struct memory_container_cmd));
    printk("started mcontainer lock for task %d and object id %llu \n", current->pid,kmemory_container_cmd.oid);
    // find out which container the process that called this function belongs to 
    if(ret==0){
        mutex_lock(lock);
        struct container* cont = find_container(current->pid);
        mutex_unlock(lock);

        //accesss the offset'th object in this containers data
        
        printk("Container ID: %lu, Process ID: %ld", cont->container_id, current->pid);
        if(cont!=NULL){
            //check if memory has already been allocated in the container
            
            if(cont-> locks == NULL){
                cont->locks = (struct mutex**) kcalloc(1, sizeof(struct mutex *),GFP_KERNEL);
                cont->count_locks = 1;
            }
            if((cont->count_locks)-1 < kmemory_container_cmd.oid){
                cont->locks = (struct mutex**) krealloc(cont->locks, sizeof(struct mutex *)*(cont->count_locks)*2,GFP_KERNEL);
                cont->count_locks *= 2;
            }

            if(cont->locks[kmemory_container_cmd.oid]==NULL){
                //kalloc the oid'th position here
                cont->locks[kmemory_container_cmd.oid]  = (struct mutex*) kcalloc(1, sizeof(struct mutex),GFP_KERNEL);
                mutex_init(cont->locks[kmemory_container_cmd.oid]);
            }
            //acquire the lock
            mutex_lock(cont->locks[kmemory_container_cmd.oid]);
            // if ( cont -> cont_mem[kmemory_container_cmd.oid].obj_lock == NULL){
            //     struct mutex *lock = (struct mutex *) kcalloc(1, sizeof(struct mutex),GFP_KERNEL);
            //     mutex_init(lock);
            //     cont -> cont_mem[kmemory_container_cmd.oid].obj_lock = lock;
            // }
            // mutex_lock(cont -> cont_mem[kmemory_container_cmd.oid].obj_lock);
            printk("acquired mcontainer lock for task %d and object id %llu \n", current->pid,kmemory_container_cmd.oid);

        }else{
            printk("Could not find container at mcontainer lock");
        }

       
    }else{
        printk("Copy from user in lock failed");
    }
    printk("finished mcontainer lock for task %d and object id %llu \n", current->pid,kmemory_container_cmd.oid);

    return 0;
}


int memory_container_unlock(struct memory_container_cmd __user *user_cmd)
{

    struct memory_container_cmd kmemory_container_cmd;
    unsigned long ret = copy_from_user(&kmemory_container_cmd, user_cmd, sizeof(struct memory_container_cmd));
    printk("started mcontainer unlock for task %d and object id %llu \n", current->pid,kmemory_container_cmd.oid);

    struct container* lookup_cont;
    // find out which container the process that called this function belongs to 
    if(ret==0){
        mutex_lock(lock);
        lookup_cont = find_container(current->pid);
        mutex_unlock(lock);
        
        if (lookup_cont!=NULL){
            mutex_unlock(lookup_cont->locks[kmemory_container_cmd.oid]);
            printk("released lock for task %d and object id %llu \n", current->pid,kmemory_container_cmd.oid);
        }

    }else{
        printk("Copy from user in lock failed");
    }
    printk("finished mcontainer unlock for task %d and object id %llu \n", current->pid,kmemory_container_cmd.oid);

    return 0;
}

// Thread Linked Lists
int add_task(struct container* container){
    struct task* current_task = (struct task*) kcalloc(1, sizeof(struct task), GFP_KERNEL);
    printk("KKK Adding a task to the container %d", current->pid);

    // allocating memory and assigning current threads task_struct
    current_task->pid = current->pid;
    current_task->prev = NULL;

    //take a lock using the containers local mutex
    mutex_lock(container->local_lock);

    //add task to the head
    current_task->next = container->task_head;
    if(container->task_head!=NULL){
        container->task_head->prev = current_task;
    }
    container->task_head = current_task;

    printk(" KKK Added task to the container %d", container->task_head->pid);
    mutex_unlock(container->local_lock);
    return 0;
}


// Lookup container by id
struct container* lookup_container(__u64 cid){
    // take a lock on the global container list
    struct container* cur;
    printk("Looking up container;before lock %d", current->pid);
    //mutex_lock(lock);
    printk("Look up container acquired lock %d", current->pid);
    cur = container_list;

    while (cur != NULL){
        printk("Container ID : %llu",cur ->container_id);
        if(cur -> container_id == cid){
            //mutex_unlock(lock);
            printk("Found container, unlocked %d", current->pid);
            return cur;
        }else{
            cur = cur -> next;
        }
    }
    
    printk("Lookup complete, didnt unlock/find container! %d", current->pid);
    return NULL;
}


void delete_container(struct container* container){
    printk("Delete container, before lock %d", current->pid);
    mutex_lock(lock);
    printk("Delete container, acquired lock %d", current->pid);
    if(container!=NULL){
        printk("Try to delete container %llu by %d",container->container_id, current->pid);
        if(container -> next !=NULL){
                container->next->prev = container->prev;
        }
        if(container->prev != NULL){
            container->prev->next = container->next;
           
        }else{
            container_list = container->next;
        }
        printk("Freed container %llu by %d",container->container_id, current->pid);

        mutex_unlock(container->local_lock);
        mutex_destroy(container->local_lock);
        kfree(container->local_lock);
        container-> local_lock = NULL;
        container->next = NULL;
        container-> prev = NULL;
    }
    mutex_unlock(lock);
    printk("Delete container, released lock %d", current->pid);
   
}

int delete_task(struct container* container){
    mutex_lock(container->local_lock);
    if(container !=NULL){
        struct task* cur = container -> task_head;
        // find the task in the container 
        while (cur != NULL){
            printk("Stored Thread %d.",cur -> pid);
            if(cur -> pid  == current -> pid){
                printk("In delete task. Task found! %d", current->pid);
                if(cur -> next !=NULL){
                    cur->next->prev = cur->prev;
                }
                if(cur->prev != NULL){
                    cur->prev->next = cur->next;
                
                }else{
                    container -> task_head = cur->next;
                }
                kfree(cur);
                cur=NULL;

                if(container->task_head == NULL){
                    delete_container(container);
                    kfree(container);
                    container=NULL;
                    //no more tasks in this container, delete it and !!!UNLOCK THE ABOVE LOCAL LOCK!!!
                }
                return 0;
            }else{
                cur = cur -> next;
            }
        }  
    } 
    if(container!=NULL){ // CAN BE NULL IF CONTAINER IS DELETED
        mutex_unlock(container->local_lock);
    }
    return -1;
}

int memory_container_delete(struct memory_container_cmd __user *user_cmd)
{

    struct memory_container_cmd kmemory_container_cmd;
    struct container* cont;
    unsigned long ret; 
    //int delete_ret;
    ret = copy_from_user(&kmemory_container_cmd, user_cmd, sizeof(struct memory_container_cmd));
    if(ret!=0){
        printk("copy_from_user failed. Couldn't delete. %d", current->pid);
        return -1;
    }
    // Lookup container
    printk("In delete lookup");
    mutex_lock(lock);
    cont = lookup_container(kmemory_container_cmd.cid);
    mutex_unlock(lock);
    if(cont!=NULL){
        delete_task(cont);
        printk("Deleted task");
    }

    return 0;
}



// Container Linked Lists
int add_container(struct container* lookup_cont, __u64 cid){
    
    //lock the global container list before adding
    printk("Adding container. Before lock %d", current->pid);
    
    printk("Adding container; acquired lock %d", current->pid);

    if(lookup_cont!= NULL){
        //container exists; add threads    
        add_task(lookup_cont);    
        printk("Added new thread %d", current->pid);
    }else{
        struct container* new_head = (struct container*) kcalloc(1, sizeof(struct container), GFP_KERNEL);   

        struct mutex* container_lock = (struct mutex*) kcalloc(1,sizeof(struct mutex),GFP_KERNEL);
        mutex_init(container_lock);

        new_head->local_lock = container_lock;
        new_head->container_id = cid;
        new_head->next = container_list;
        new_head->prev = NULL;

        // new_head->cont_mem = (struct object*) kcalloc(1, sizeof(struct object), GFP_KERNEL);
        // new_head->count = 1;
        // new_head->lock = (struct mutex *) kcalloc(1, sizeof(struct mutex),GFP_KERNEL);
        // mutex_init(new_head->lock);

        if(container_list!=NULL){
            container_list->prev = new_head;
        }
        container_list = new_head;
        printk("KKK Adding a fresh container %d", current->pid);
        add_task(container_list);
        printk("Added container, unlocked %d", current->pid);
     }

    //  mutex_unlock(lock);
     
    return 0;
}


int memory_container_create(struct memory_container_cmd __user *user_cmd)
{
    // Create a container if container with CID is not present
    struct memory_container_cmd kmemory_container_cmd;
    struct container* lookup_cont;
    unsigned long ret;

    if(lock == NULL){
        lock = (struct mutex *) kcalloc(1, sizeof(struct mutex),GFP_KERNEL);
        mutex_init(lock);
        printk("Initialized lock %d", current->pid);
    }

    mutex_lock(lock);
    ret = copy_from_user(&kmemory_container_cmd, user_cmd, sizeof(struct memory_container_cmd));
    if(ret==0){
        printk("Task ID: %d CID: %llu", current->pid, kmemory_container_cmd.cid);

        //lock here
        printk("Create: Obtaining lock");
        // lookup container
        lookup_cont = lookup_container(kmemory_container_cmd.cid);
        // add
        add_container(lookup_cont, kmemory_container_cmd.cid);
        //
    }else{
        printk("Did not work");
    }
    mutex_unlock(lock);

    return 0;
}


int memory_container_free(struct memory_container_cmd __user *user_cmd)
{
    // Write method to free
    return 0;
}


/**
 * control function that receive the command in user space and pass arguments to
 * corresponding functions.
 */
int memory_container_ioctl(struct file *filp, unsigned int cmd,
                              unsigned long arg)
{
    switch (cmd)
    {
    case MCONTAINER_IOCTL_CREATE:
        return memory_container_create((void __user *)arg);
    case MCONTAINER_IOCTL_DELETE:
        return memory_container_delete((void __user *)arg);
    case MCONTAINER_IOCTL_LOCK:
        return memory_container_lock((void __user *)arg);
    case MCONTAINER_IOCTL_UNLOCK:
        return memory_container_unlock((void __user *)arg);
    case MCONTAINER_IOCTL_FREE:
        return memory_container_free((void __user *)arg);
    default:
        return -ENOTTY;
    }
}
