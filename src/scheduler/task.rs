// Copyright (c) 2017 Stefan Lankes, RWTH Aachen University
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![allow(dead_code)]

use alloc;
use alloc::alloc::{alloc, dealloc, Layout};
use alloc::rc::Rc;
use collections::{DoublyLinkedList, Node};
use consts::*;
use core::cell::RefCell;
use core::fmt;
use logging::*;

extern "C" {
    fn get_bootstack() -> *mut u8;
}

/// The status of the task - used for scheduling
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TaskStatus {
    TaskInvalid,
    TaskReady,
    TaskRunning,
    TaskBlocked,
    TaskFinished,
    TaskIdle,
}

/// Unique identifier for a task (i.e. `pid`).
#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone, Copy)]
pub struct TaskId(u32);

impl TaskId {
    pub const fn into(self) -> u32 {
        self.0
    }

    pub const fn from(x: u32) -> Self {
        TaskId(x)
    }
}

impl alloc::fmt::Display for TaskId {
    fn fmt(&self, f: &mut fmt::Formatter) -> alloc::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Copy, Clone)]
#[repr(align(64))]
#[repr(C)]
pub struct Stack {
    buffer: [u8; STACK_SIZE],
}

/// Stack definition
impl Stack {
    pub const fn new() -> Stack {
        Stack {
            buffer: [0; STACK_SIZE],
        }
    }

    /// Return pointer to stack top
    pub fn top(&self) -> usize {
        (&(self.buffer[STACK_SIZE - 16]) as *const _) as usize
    }
    /// Return pointer to stack botttom
    pub fn bottom(&self) -> usize {
        (&(self.buffer[0]) as *const _) as usize
    }
}

/// New stack
pub static mut BOOT_STACK: Stack = Stack::new();

/// Task queue definition as doubly linked list
pub struct TaskQueue {
    queue: DoublyLinkedList<Rc<RefCell<Task>>>,
}
/// The task queue implementation
impl TaskQueue {
    /// Create a new task queue
    pub fn new() -> TaskQueue {
        TaskQueue {
            queue: Default::default(),
        }
    }

    /// Add a task by its priority to the queue
    pub fn push(&mut self, task: Rc<RefCell<Task>>) {
        self.queue.push(Node::new(task));
    }

    /// Pop the task from the queue
    pub fn pop(&mut self) -> Option<Rc<RefCell<Task>>> {
        let first_task = self.queue.head();
        first_task.map(|task| {
            self.queue.remove(task.clone());

            task.borrow().value.clone()
        })
    }

    /// Remove a specific task from the priority queue.
    pub fn remove(&mut self, task: Rc<RefCell<Task>>) {
        for node in self.queue.iter() {
            if Rc::ptr_eq(&node.borrow().value, &task) {
                self.queue.remove(node.clone());

                break;
            }
        }
    }
}

/// A task control block, which identifies either a process or a thread
#[repr(align(64))]
pub struct Task {
    /// The ID of this context
    pub id: TaskId,
    /// Status of a task, e.g. if the task is ready or blocked
    pub status: TaskStatus,
    /// Last stack pointer before a context switch to another task
    pub last_stack_pointer: usize,
    /// Stack of the task
    pub stack: *mut Stack,
}

/// The task implementation
impl Task {
    /// Create a new idle task
    /// * `id` - The idle task's id
    pub fn new_idle(id: TaskId) -> Task {
        Task {
            id: id,
            status: TaskStatus::TaskIdle,
            last_stack_pointer: 0,
            stack: unsafe { &mut BOOT_STACK },
        }
    }

    /// Create a new task
    /// * `id` - `TaskId` the new task should have
    /// * `status` - `TaskStatus` status the task should have
    pub fn new(id: TaskId, status: TaskStatus) -> Task {
        let stack = unsafe { alloc(Layout::new::<Stack>()) as *mut Stack };

        debug!("Allocate stack for task {} at 0x{:x}", id, stack as usize);

        Task {
            id: id,
            status: status,
            last_stack_pointer: 0,
            stack: stack,
        }
    }
}

/// Task frame trait
pub trait TaskFrame {
    /// Create the initial stack frame for a new task
    fn create_stack_frame(&mut self, func: extern "C" fn());
}

/// Drop implementation for Task
impl Drop for Task {
    /// Drops the task and deallocates the stack
    /// * `self`: The task to drop
    fn drop(&mut self) {
        if unsafe { self.stack != &mut BOOT_STACK } {
            debug!(
                "Deallocate stack of task {} (stack at 0x{:x})",
                self.id, self.stack as usize
            );

            // deallocate stack
            unsafe {
                dealloc(self.stack as *mut u8, Layout::new::<Stack>());
            }
        }
    }
}
