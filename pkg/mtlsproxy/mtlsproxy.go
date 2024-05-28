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

package mtlsproxy

import (
	"kmesh.net/kmesh/pkg/logger"
	"kmesh.net/kmesh/pkg/utils"
)

var log = logger.NewLoggerField("mtls proxy")

type mtlsproxy struct {
	worker *utils.WorkerPool
	done   chan bool
}

func NewProxy() *mtlsproxy {
	return &mtlsproxy{
		worker: utils.NewWorkPool(10),
		done:   make(chan bool, 1),
	}
}

func (proxy *mtlsproxy) Start() error {
	log.Debug("mtls proxy start...")
	netlink_sock := NewNetlinkSock()

	proxy.worker.Run()
	go func() {
		for {
			select {
			case <-proxy.done:
				break
			default:
				migration_sock, role := netlink_sock.GetNext()
				task := NewMtlsTask(migration_sock, role)
				proxy.worker.Add(func() {
					if err := task.Handle(); err != nil {
						log.Error(err)
					}
				})
			}
		}
	}()
	return nil
}

func (proxy *mtlsproxy) Stop() {
	proxy.done <- true
	proxy.worker.Stop()
	proxy.worker.Wait()
}
