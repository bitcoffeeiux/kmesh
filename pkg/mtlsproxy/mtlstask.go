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
	"context"
	"net"
	"os"
	"time"
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
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*1)
	defer cancel()

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		var err error
		if err = task.restoreSocket(); err != nil {
			return err
		}

		if task.role == ROLE_SERVER {
			err = task.sslAccept()
		} else {
			err = task.sslConnect()
		}
		if err == nil {
			netlink_sock.ResetOwner(task.Socketfd)
		}
		return err
	}
}

func (task *MtlsTask) restoreSocket() error {
	var err error
	if task.conn != nil {
		return nil
	}

	task.conn, err = net.FileConn(os.NewFile(uintptr(task.Socketfd), "socket"))
	if err != nil {
		task.conn = nil
	}
	return err
}

func (task *MtlsTask) sslAccept() error {
	cert := "server.cert"
	privKey := "server.key"
	return OpensslAccept(cert, privKey, task.Socketfd)
}

func (task *MtlsTask) sslConnect() error {
	cert := "server.cert"
	privKey := "server.key"
	return OpensslConnect(cert, privKey, task.Socketfd)
}
