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

package controller

import (
	"context"
	"fmt"

	"kmesh.net/kmesh/daemon/options"
	bpfads "kmesh.net/kmesh/pkg/bpf/ads"
	bpfwl "kmesh.net/kmesh/pkg/bpf/workload"
	"kmesh.net/kmesh/pkg/constants"
	"kmesh.net/kmesh/pkg/controller/bypass"
	"kmesh.net/kmesh/pkg/controller/encryption/ipsec"
	manage "kmesh.net/kmesh/pkg/controller/manage"
	"kmesh.net/kmesh/pkg/controller/security"
	"kmesh.net/kmesh/pkg/dns"
	"kmesh.net/kmesh/pkg/logger"
	"kmesh.net/kmesh/pkg/utils"
)

var (
	ctx, cancel = context.WithCancel(context.Background())
	log         = logger.NewLoggerScope("controller")
)

type Controller struct {
	mode                string
	bpfAdsObj           *bpfads.BpfAds
	bpfWorkloadObj      *bpfwl.BpfWorkload
	client              *XdsClient
	enableByPass        bool
	enableSecretManager bool
	bpfFsPath           string
	enableBpfLog        bool
	enableAccesslog     bool
	enablePerfMonitor   bool
	enableIpsec         bool
}

func NewController(opts *options.BootstrapConfigs, bpfAdsObj *bpfads.BpfAds, bpfWorkloadObj *bpfwl.BpfWorkload, bpfFsPath string, enableBpfLog, enableAccesslog, enableIpsec bool) *Controller {
	return &Controller{
		mode:                opts.BpfConfig.Mode,
		enableByPass:        opts.ByPassConfig.EnableByPass,
		bpfAdsObj:           bpfAdsObj,
		bpfWorkloadObj:      bpfWorkloadObj,
		enableSecretManager: opts.SecretManagerConfig.Enable,
		bpfFsPath:           bpfFsPath,
		enableBpfLog:        enableBpfLog,
		enableAccesslog:     enableAccesslog,
		enablePerfMonitor:   opts.PerfConfig.EnablePerfMonitor,
		enableIpsec:         enableIpsec,
	}
}

func (c *Controller) Start(stopCh <-chan struct{}) error {
	var secertManager *security.SecretManager
	var err error
	var kmeshManageController *manage.KmeshManageController

	if c.mode == constants.DualEngineMode && c.enableSecretManager {
		secertManager, err = security.NewSecretManager()
		if err != nil {
			return fmt.Errorf("secretManager create failed: %v", err)
		}
		go secertManager.Run(stopCh)
	}

	clientset, err := utils.GetK8sclient()
	if err != nil {
		return err
	}

	if c.mode == constants.DualEngineMode {
		kmeshManageController, err = manage.NewKmeshManageController(clientset, secertManager, c.bpfWorkloadObj.XdpAuth.XdpShutdown.FD(), c.mode)
	} else {
		kmeshManageController, err = manage.NewKmeshManageController(clientset, secertManager, -1, c.mode)
	}
	if err != nil {
		return fmt.Errorf("failed to start kmesh manage controller: %v", err)
	}
	go kmeshManageController.Run(stopCh)
	log.Info("start kmesh manage controller successfully")

	if c.enableByPass {
		c := bypass.NewByPassController(clientset)
		go c.Run(stopCh)
		log.Info("start bypass controller successfully")
	}

	if c.mode != constants.DualEngineMode && c.mode != constants.KernelNativeMode {
		return nil
	}

	if c.enableIpsec {
		c, err := ipsec.NewIPsecController(clientset)
		if err != nil {
			return fmt.Errorf("failed to new IPSec controller, %v", err)
		}
		go c.Run(stopCh)
		log.Info("start ipsec controller successfully")
	}

	if c.enableBpfLog {
		if err := logger.StartRingBufReader(ctx, c.mode, c.bpfFsPath); err != nil {
			return fmt.Errorf("fail to start ringbuf reader: %v", err)
		}
	}
	c.client = NewXdsClient(c.mode, c.bpfAdsObj, c.bpfWorkloadObj, c.enableAccesslog)

	if c.client.WorkloadController != nil {
		c.client.WorkloadController.Run(ctx, c.enablePerfMonitor)
	}

	if c.client.AdsController != nil {
		dnsResolver, err := dns.NewDNSResolver(c.client.AdsController.Processor.Cache)
		if err != nil {
			return fmt.Errorf("dns resolver create failed: %v", err)
		}
		dnsResolver.StartDNSResolver(stopCh)
		c.client.AdsController.Processor.DnsResolverChan = dnsResolver.DnsResolverChan
	}

	return c.client.Run(stopCh)
}

func (c *Controller) Stop() {
	if c == nil {
		return
	}
	cancel()
	if c.client != nil {
		c.client.Close()
	}
}

func (c *Controller) GetXdsClient() *XdsClient {
	return c.client
}
