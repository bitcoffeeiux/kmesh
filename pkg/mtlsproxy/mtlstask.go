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
	"fmt"
	"net"

	"golang.org/x/sys/unix"
	"kmesh.net/kmesh/pkg/utils"
)

const ROLE_CLIENT = 0
const ROLE_SERVER = 1

type MtlsTask struct {
	Socketfd int
	conn     net.Conn
	role     int
}

func NewMtlsTask(socketfd int, role int) *MtlsTask {
	return &MtlsTask{
		Socketfd: socketfd,
		conn:     nil,
		role:     role,
	}
}

func (task *MtlsTask) Handle() error {
	var err error
	if err = utils.SetSockOwner(task.Socketfd); err != nil {
		return err
	}

	if err = task.sslHandle(task.role); err == nil {
		unix.Shutdown(task.Socketfd, unix.SHUT_RDWR)
		return err
	}

	if err = utils.ResetOwner(task.Socketfd); err != nil {
		return err
	}

	if err = unix.Close(task.Socketfd); err != nil {
		err = fmt.Errorf("Failed to close migration socket, err is %v\n", err)
		return err
	}
	return err
}

func (task *MtlsTask) sslHandle(role int) error {
	cert := "/home/server.cert"
	privKey := "/home/server.key"
	return OpensslHandle(cert, privKey, task.Socketfd, role)
}
