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
	"os"
	"strconv"

	"github.com/mdlayher/netlink"
)

const (
	userDefine netlink.HeaderType = 5
	setOwner   netlink.HeaderType = 6
	resetOwner netlink.HeaderType = 7
	netlinkNum                    = 30
)

var conn *netlink.Conn = nil

func createNetlink() error {
	if conn == nil {
		conn, err := netlink.Dial(netlinkNum, nil)
		if err != nil {
			err = fmt.Errorf("Failed to netlink dial, err is %v\n", err)
			return err
		}
	}
	return nil
}

func SendSockPair(socket int) error {
	var err error
	if err = createNetlink(); err != nil {
		return err
	}
	data := make([]byte, 4)
	copy(data[:], strconv.Itoa(socket))
	nlmsg := netlink.Message{
		Header: netlink.Header{
			Type: userDefine,
		},
		Data: data,
	}
	_, err = conn.Send(nlmsg)
	if err != nil {
		err = fmt.Errorf("Failed to netlink send, err is %v\n", err)
		return err
	}
	return nil
}

func SetSockOwner(socket int) error {
	var err error
	if err = createNetlink(); err != nil {
		return err
	}

	data := make([]byte, 4)
	copy(data[:], strconv.Itoa(socket))
	nlmsg := netlink.Message{
		Header: netlink.Header{
			Type: setOwner,
			PID:  uint32(os.Getpid()),
		},
		Data: data,
	}
	_, err = conn.Send(nlmsg)
	if err != nil {
		err = fmt.Errorf("Failed to netlink send, err is %v\n", err)
		return err
	}
	return nil
}

func ResetSockOwner(socket int) error {
	var err error
	if err = createNetlink(); err != nil {
		return err
	}
	data := make([]byte, 4)
	copy(data[:], strconv.Itoa(socket))
	nlmsg := netlink.Message{
		Header: netlink.Header{
			Type: resetOwner,
			PID:  uint32(os.Getpid()),
		},
		Data: data,
	}
	_, err = conn.Send(nlmsg)
	if err != nil {
		err = fmt.Errorf("Failed to netlink send, err is %v\n", err)
		return err
	}
	return nil
}
