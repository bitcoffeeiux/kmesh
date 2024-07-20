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
	"golang.org/x/sys/unix"
	"kmesh.net/kmesh/pkg/logger"
)

var log = logger.NewLoggerField("mtls proxy")

type mtlsproxy struct {
	done chan bool
}

func NewProxy() *mtlsproxy {
	return &mtlsproxy{
		done: make(chan bool, 1),
	}
}

func (proxy *mtlsproxy) Start() error {
	log.Debug("mtls proxy start...")
	sockpair := NewSockPair()

	err := sockpair.Run()
	if err != nil {
		return err
	}

	go func() {
		for {
			select {
			case <-proxy.done:
				break
			default:
				migration_sock, role := sockpair.GetNext()
				if err == unix.EAGAIN {
					continue
				} else if err != nil {
					log.Errorf("Failed to operator sockpair, err is %v\n", err)
					break
				}
				task := NewMtlsTask(migration_sock, role)
				go func() {
					if err := task.Handle(); err != nil {
						log.Error(err)
					}
				}()
			}
		}
	}()
}

func (proxy *mtlsproxy) Stop() {
	proxy.done <- true
}
