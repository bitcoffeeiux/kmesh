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

import "net"

type Sockpair struct {
	conn net.Conn
}

func NewSockPair() *Sockpair {
	return & Sockpair{
		conn: nil
	}
}

func (s *sockpair) Run() error {
	pair, err := syscall.SocketPair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		log.Errorf("Failed to create socket pair, err is %v\n", err)
		return err
	}

	err := utils.SendSockPair(s.pair[1])
	if err != nil {
		log.Errorf("Failed to dial netlink, err is %v\n", err)
		return err
	}
	file := os.NewFile(uintptr(pair[0], ""))
	defer file.Close()
	s.conn, err := net.FileConn(file)
	if err != nil {
		log.Errorf("Failed to create file conn, err is %v\n", err)
		return err
	}
	return nil
}

func (s *sockpair) GetNext() (int, int, error) {
	if s.conn == nil {
		err := fmt.Errorf("sockpair not init\n")
		log.Errorf(err)
		return 0, 0, err
	}
	buf := make([]byte, 32)
	oob := make([]byte, 32)
	for {
		_, oobn, _, _, err := s.conn.(*net.UnixConn).ReadMsgUnix(buf, oob)
		if err != nil {
			log.Errorf("Failed to read msg unix, err is %v\n", err)
			return 0, 0, err
		}

		scms, err := syscall.ParseSocketControlMessage(oob[:oobn])
		if err != nil {
			log.Errorf("Failed to parse unix rights, err is %v\n", err)
			return 0, 0, err
		}

		if len(scms) == 0 {
			log.Warnf("scms len is 0\n")
			continue
		}
		
		info, err := syscall.ParseUnixRights(&(scms[0]))
		if err != nil {
			log.Errorf("Failed to parse unix rights, err is %v\n", err)
			return 0, 0, err
		}

		return info[0], info[1], nil
	}
}
