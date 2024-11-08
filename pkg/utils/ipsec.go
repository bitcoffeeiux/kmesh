/*
 * Copyright The Kmesh Authors.
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
	"net"
	"os"
	"strconv"

	"github.com/vishvananda/netlink"
)

func InsertXfrmRule(rawSrc, rawDst string,
	rawDstCIDR string, nodeID string,
	spi int8, keyName string, key []byte, keyLength int, out bool) error {
	src := net.ParseIP(rawSrc)
	if src == nil {
		return fmt.Errorf("failed to parser ip in inserting xfrm out rule, input: %v", rawSrc)
	}
	dst := net.ParseIP(rawDst)
	if dst == nil {
		return fmt.Errorf("failed to parser ip in inserting xfrm out rule, input: %v", rawDst)
	}

	err := createStateRule(src, dst, spi, keyName, key, keyLength)
	if err != nil {
		return err
	}

	err = createPolicyRule(rawDstCIDR, src, dst, out, nodeID, spi)
	if err != nil {
		return err
	}

	return nil
}

func createPolicyRule(rawDstCIDR string, src net.IP, dst net.IP, out bool, nodeID string, spi int8) error {
	_, srcCIDR, err := net.ParseCIDR("0.0.0.0/0")
	if err != nil {
		return fmt.Errorf("failed to parser CIDR in inserting xfrm out rule, %v", err)
	}

	_, dstCIRD, err := net.ParseCIDR(rawDstCIDR)
	if err != nil {
		return fmt.Errorf("failed to parser CIDR in inserting xfrm out rule, %v", err)
	}

	policy := &netlink.XfrmPolicy{
		Src: srcCIDR,
		Dst: dstCIRD,
		Tmpls: []netlink.XfrmPolicyTmpl{
			{
				Src:   src,
				Dst:   dst,
				Proto: netlink.XFRM_PROTO_ESP,
				Reqid: 1,
				Mode:  netlink.XFRM_MODE_TUNNEL,
			},
		},
		Mark: &netlink.XfrmMark{},
	}

	if out {
		mark, err := strconv.ParseInt(nodeID+strconv.Itoa(int(spi))+"e00", 16, 64)
		if err != nil {
			return fmt.Errorf("failed to convert mark in inserting xfrm out rule, %v", err)
		}

		policy.Mark.Value = uint32(mark)
		policy.Tmpls[0].Spi = int(spi)
		policy.Dir = netlink.XFRM_DIR_OUT

		err = netlink.XfrmPolicyAdd(policy)
		if err != nil && os.IsExist(err) {
			err = netlink.XfrmPolicyUpdate(policy)
		}
		if err != nil {
			return fmt.Errorf("failed to add xfrm policy to host in inserting xfrm out rule, %v", err)
		}
	} else {
		mark, err := strconv.ParseInt(nodeID+"d00", 16, 64)
		if err != nil {
			return fmt.Errorf("failed to convert mark in inserting xfrm in rule, %v", err)
		}

		policy.Mark.Value = uint32(mark)
		policy.Dir = netlink.XFRM_DIR_IN

		err = netlink.XfrmPolicyAdd(policy)
		if err != nil && os.IsExist(err) {
			err = netlink.XfrmPolicyUpdate(policy)
		}
		if err != nil {
			return fmt.Errorf("failed to add xfrm policy to host in inserting xfrm in rule, %v", err)
		}

		policy.Dir = netlink.XFRM_DIR_FWD
		err = netlink.XfrmPolicyAdd(policy)
		if err != nil && os.IsExist(err) {
			err = netlink.XfrmPolicyUpdate(policy)
		}
		if err != nil {
			return fmt.Errorf("failed to add xfrm policy to host in inserting xfrm fwd rule, %v", err)
		}
	}
	return nil
}

func createStateRule(src net.IP, dst net.IP, spi int8, keyName string, key []byte, keyLength int) error {
	state := &netlink.XfrmState{
		Src:   src,
		Dst:   dst,
		Proto: netlink.XFRM_PROTO_ESP,
		Mode:  netlink.XFRM_MODE_TUNNEL,
		Spi:   int(spi),
		Reqid: 1,
		Aead: &netlink.XfrmStateAlgo{
			Name:   keyName,
			Key:    key,
			ICVLen: keyLength,
		},
	}
	err := netlink.XfrmStateAdd(state)
	if err != nil && os.IsExist(err) {
		err = netlink.XfrmStateUpdate(state)
	}
	if err != nil {
		return fmt.Errorf("failed to add xfrm state to host in inserting xfrm out rule, %v", err)
	}
	return nil
}

func CreateNewStateFromOldByLocalNidIP(spi, oldSpi int8, nicIP []string) error {
	oldStateList, err := netlink.XfrmStateList(netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("failed to list all xfrm state, %v", err)
	}
	for _, ipString := range nicIP {
		ip := net.ParseIP(ipString)
		for _, state := range oldStateList {
			if !state.Dst.Equal(ip) {
				continue
			}
			state.Spi = int(spi)
			if err = netlink.XfrmStateAdd(&state); err != nil {
				return fmt.Errorf("failed to add xfrm state to host in create new state from old")
			}
		}
	}
	return nil
}

