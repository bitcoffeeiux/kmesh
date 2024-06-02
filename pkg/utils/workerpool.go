/*
 * Copyright 2024 The Kmesh Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
