package utils

import (
	"fmt"
	"sync"
)

type WorkerPool struct {
	workers int
	tasks   chan func()
	wg      sync.WaitGroup
	done    bool
}

func NewWorkPool(workers int) *WorkerPool {
	pool := &WorkerPool{
		workers: workers,
		tasks:   make(chan func()),
		done:    false,
	}
	return pool
}

func (pool *WorkerPool) Run() {
	for i := 0; i < pool.workers; i++ {
		pool.wg.Add(1)
		go func() {
			defer pool.wg.Done()
			for {
				select {
				case task, ok := <-pool.tasks:
					if pool.done {
						return
					}
					if !ok {
						continue
					}
					task()
				default:
					continue
				}
			}
		}()
	}
}

func (pool *WorkerPool) Stop() {
	pool.done = true
}

func (pool *WorkerPool) Add(task func()) error {
	if pool.done {
		return fmt.Errorf("can not add task on a close workerpool\n")
	}
	pool.tasks <- task
	return nil
}

func (pool *WorkerPool) Wait() {
	close(pool.tasks)
	pool.wg.Wait()
}
