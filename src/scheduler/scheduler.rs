// Copyright (c) 2017-2018 Stefan Lankes, RWTH Aachen University
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::rc::Rc;
use core::cell::RefCell;
use core::sync::atomic::{AtomicU32, Ordering};
use scheduler::task::*;
// use arch::switch;
use arch::aarch64::irq;
use logging::*;

static NO_TASKS: AtomicU32 = AtomicU32::new(0);
static TID_COUNTER: AtomicU32 = AtomicU32::new(0);

/// Scheduler struct
pub struct Scheduler {
    /// task id which is currently running
    current_task: Rc<RefCell<Task>>,
    /// task id of the idle task
    idle_task: Rc<RefCell<Task>>,
    /// queue of tasks, which are ready
    ready_queue: TaskQueue,
    /// queue of tasks, which are finished and can be released
    finished_tasks: VecDeque<TaskId>,
    /// map between task id and task control block
    tasks: BTreeMap<TaskId, Rc<RefCell<Task>>>,
}

/// Function implementation for scheduler
impl Scheduler {
    /// Create a new scheduler
    pub fn new() -> Scheduler {
        let tid = TaskId::from(TID_COUNTER.fetch_add(1, Ordering::SeqCst));
        let idle_task = Rc::new(RefCell::new(Task::new_idle(tid)));
        let mut tasks = BTreeMap::new();
        tasks.insert(tid, idle_task.clone());
        Scheduler {
            current_task: idle_task.clone(),
            idle_task: idle_task.clone(),
            ready_queue: TaskQueue::new(),
            finished_tasks: VecDeque::<TaskId>::new(),
            tasks: tasks,
        }
    }

    fn get_tid(&self) -> TaskId {
        loop {
            let id = TaskId::from(TID_COUNTER.fetch_add(1, Ordering::SeqCst));

            if self.tasks.contains_key(&id) == false {
                return id;
            }
        }
    }

    /// Spawn a new task and add it to the ready queue
    pub fn spawn(&mut self, func: extern "C" fn()) -> TaskId {
        // Create the new task.
        let tid = self.get_tid();
        let task = Rc::new(RefCell::new(Task::new(tid, TaskStatus::TaskReady)));

        task.borrow_mut().create_stack_frame(func);

        // Add it to the task lists.
        self.ready_queue.push(task.clone());
        self.tasks.insert(tid, task);
        NO_TASKS.fetch_add(1, Ordering::SeqCst);

        info!("Creating task {}", tid);

        tid
    }

    /// Change task status to TaskFinished
    pub fn exit(&mut self) {
        if self.current_task.borrow().status != TaskStatus::TaskIdle {
            println!("finish task with id {}", self.current_task.borrow().id);
            self.current_task.borrow_mut().status = TaskStatus::TaskFinished;
        } else {
            panic!("unable to terminate idle task");
        }

        irq::trigger_schedule();
    }

    /// Return the current task's id
    pub fn get_current_taskid(&self) -> TaskId {
        self.current_task.borrow().id
    }

    /// Return the current task's stack pointer
    pub fn get_current_stack(&self) -> usize {
        self.current_task.borrow().last_stack_pointer
    }

    /// The scheduler's core functionality:
    /// - drop task from finish queue
    /// - determine the new task
    /// - update task queues
    /// - switch to new task, if there is none switch to idle task
    /// - return the old stack pointer
    pub fn schedule(&mut self) -> usize {
        // do we have finished tasks? => drop tasks => deallocate implicitly the stack
        match self.finished_tasks.pop_front() {
            Some(id) => {
                println!("poped task from finish queue");
                if self.tasks.remove(&id).is_none() == true {
                    println!("Unable to drop task {}", id);
                }
            }
            _ => {}
        }

        // Get information about the current task.
        let (old_id, old_stack_pointer, current_status) = {
            let mut borrowed = self.current_task.borrow_mut();
            (
                borrowed.id,
                &mut borrowed.last_stack_pointer as *mut usize,
                borrowed.status,
            )
        };

        // do we have a task, which is ready?
        let mut next_task = self.ready_queue.pop();
        if next_task.is_none() == true {
            if current_status != TaskStatus::TaskRunning && current_status != TaskStatus::TaskIdle {
                println!("Switch to idle task");
                // current task isn't able to run and no other task available
                // => switch to the idle task
                next_task = Some(self.idle_task.clone());
            }
        }

        match next_task {
            Some(new_task) => {
                let (new_id, new_stack_pointer) = {
                    let mut borrowed = new_task.borrow_mut();
                    borrowed.status = TaskStatus::TaskRunning;
                    (borrowed.id, borrowed.last_stack_pointer)
                };

                if current_status == TaskStatus::TaskRunning {
                    println!("Add task {} to ready queue", old_id);
                    self.current_task.borrow_mut().status = TaskStatus::TaskReady;
                    self.ready_queue.push(self.current_task.clone());
                } else if current_status == TaskStatus::TaskFinished {
                    println!("Task {} finished", old_id);
                    self.current_task.borrow_mut().status = TaskStatus::TaskInvalid;
                    // release the task later, because the stack is required
                    // to call the function "switch"
                    // => push id to a queue and release the task later
                    self.finished_tasks.push_back(old_id);
                }

                println!(
                    "Switching task from {} to {} (stack {:#X} => {:#X})",
                    old_id,
                    new_id,
                    unsafe { *old_stack_pointer },
                    new_stack_pointer
                );

                self.current_task = new_task;
                return old_stack_pointer as usize;
            }
            _ => 0,
        }
    }

    /// Public interface to initiate a reschedule
    pub fn reschedule(&mut self) -> usize {
        self.schedule()
    }
}
