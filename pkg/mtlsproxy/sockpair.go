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
	"bytes"
	"encoding/binary"

	"golang.org/x/sys/unix"
	"kmesh.net/kmesh/pkg/utils"
)

type Sockpair struct {
	sock int
}

func NewSockPair() *Sockpair {
	return &Sockpair{
		sock: 0,
	}
}

func (s *Sockpair) Run() error {
	pair, err := unix.SocketPair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		log.Errorf("Failed to create socket pair, err is %v\n", err)
		return err
	}

	if err = utils.SendSockPair(pair[1]); err != nil {
		log.Errorf("Failed to dial netlink, err is %v\n", err)
		return err
	}
	s.sock = pair[0]
	return nil
}

func (s *sockpair) GetNext() (int, int, error) {
	buf := make([]byte, 1)
	oob := make([]byte, 32)
	for {
		_, oobn, _, _, err := unix.Recvmsg(s.sock, buf, oob, 0)
		if err != nil {
			if err != unix.EAGAIN {
				log.Errorf("Failed to read msg unix, err is %v\n", err)
			}
			return 0, 0, err
		}

		scms, err := unix.ParseSocketControlMessage(oob[:oobn])
		if err != nil {
			log.Errorf("Failed to parse unix rights, err is %v\n", err)
			return 0, 0, err
		}

		if len(scms) == 0 {
			log.Warnf("get a valid message, scms len is 0\n")
			continue
		}

		info, err := unix.ParseUnixRights(&(scms[0]))
		if err != nil {
			log.Errorf("Failed to parse unix rights, err is %v\n", err)
			return 0, 0, err
		}


		var role int8
		err = binary.Read(bytes.NewBuffer(buf), binary.LittleEndian, &role)
		if err != nil {
			log.Errorf("Failed to parse role, err is %v\n", err)
			return 0, 0, err
		}
		role -= '0'

		return info[0], int(role), nil
	}
}
