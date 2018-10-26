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
    task* next;
    task* prev;
};

// Containers
struct container{
    __u64 container_id;
    char* start_data;
    struct container* next;
    struct container* prev;
    struct mutex * local_lock;
    task* tasks;
};


int memory_container_mmap(struct file *filp, struct vm_area_struct *vma)
{
    return 0;
}

int memory_container_lock(struct memory_container_cmd __user *user_cmd)
{
    // Write lock
    return 0;
}


int memory_container_unlock(struct memory_container_cmd __user *user_cmd)
{
    // Write unlock
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


int memory_container_delete(struct memory_container_cmd __user *user_cmd)
{
    // Lookup container
    // Lookup process in container and delete it
    // Delete container if empty
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
        printk("Thread ID: %d CID: %llu", task->pid, kmemory_container_cmd.cid);

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
