package main

/*
#include <stdlib.h>
*/
import "C"
import (
	"context"
	"fmt"
	"sync"
	"time"
	"unsafe"

	"github.com/fatedier/frp/client"
	"github.com/fatedier/frp/pkg/config"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/config/source"
	"github.com/fatedier/frp/pkg/policy/security"
	"github.com/fatedier/frp/pkg/util/log"
)

type frpInstance struct {
	svr    *client.Service
	cancel context.CancelFunc
}

var (
	instances = make(map[int]*frpInstance)
	nextID    = 1
	mu        sync.Mutex
	lastErr   string
)

//export StartFrpClient
func StartFrpClient(tomlContent *C.char) C.int {
	content := C.GoString(tomlContent)

	var allCfg v1.ClientConfig
	if err := config.LoadConfigure([]byte(content), &allCfg, true, "toml"); err != nil {
		setLastErr(fmt.Sprintf("parse toml: %v", err))
		return -1
	}

	common := &allCfg.ClientCommonConfig
	if err := common.Complete(); err != nil {
		setLastErr(fmt.Sprintf("complete config: %v", err))
		return -1
	}

	log.InitLogger(common.Log.To, common.Log.Level, int(common.Log.MaxDays), common.Log.DisablePrintColor)

	proxies := make([]v1.ProxyConfigurer, 0)
	for _, p := range allCfg.Proxies {
		proxies = append(proxies, p.ProxyConfigurer)
	}
	visitors := make([]v1.VisitorConfigurer, 0)
	for _, v := range allCfg.Visitors {
		visitors = append(visitors, v.VisitorConfigurer)
	}

	unsafeFeatures := security.NewUnsafeFeatures([]string{})
	configSource := source.NewConfigSource()
	if err := configSource.ReplaceAll(proxies, visitors); err != nil {
		setLastErr(fmt.Sprintf("config source: %v", err))
		return -1
	}

	return startService(common, configSource, unsafeFeatures, "")
}

//export StartFrpClientFromFile
func StartFrpClientFromFile(cfgPath *C.char) C.int {
	configPath := C.GoString(cfgPath)

	result, err := config.LoadClientConfigResult(configPath, true)
	if err != nil {
		setLastErr(fmt.Sprintf("load config: %v", err))
		return -1
	}

	log.InitLogger(result.Common.Log.To, result.Common.Log.Level, int(result.Common.Log.MaxDays), result.Common.Log.DisablePrintColor)

	unsafeFeatures := security.NewUnsafeFeatures([]string{})
	configSource := source.NewConfigSource()
	if err := configSource.ReplaceAll(result.Proxies, result.Visitors); err != nil {
		setLastErr(fmt.Sprintf("config source: %v", err))
		return -1
	}

	return startService(result.Common, configSource, unsafeFeatures, configPath)
}

func startService(common *v1.ClientCommonConfig, configSource *source.ConfigSource, unsafeFeatures *security.UnsafeFeatures, configPath string) C.int {
	aggregator := source.NewAggregator(configSource)

	svr, err := client.NewService(client.ServiceOptions{
		Common:                 common,
		ConfigSourceAggregator: aggregator,
		UnsafeFeatures:         unsafeFeatures,
		ConfigFilePath:         configPath,
	})
	if err != nil {
		setLastErr(fmt.Sprintf("new service: %v", err))
		return -1
	}

	ctx, cancel := context.WithCancel(context.Background())

	mu.Lock()
	id := nextID
	nextID++
	instances[id] = &frpInstance{svr: svr, cancel: cancel}
	mu.Unlock()

	go func() {
		svr.Run(ctx)
		mu.Lock()
		delete(instances, id)
		mu.Unlock()
	}()

	return C.int(id)
}

//export StopFrpClient
func StopFrpClient(id C.int) C.int {
	mu.Lock()
	inst, ok := instances[int(id)]
	mu.Unlock()

	if !ok {
		setLastErr("invalid instance id")
		return -1
	}

	inst.svr.GracefulClose(5 * time.Second)
	inst.cancel()
	return 0
}

//export GetFrpClientStatus
func GetFrpClientStatus(id C.int) C.int {
	mu.Lock()
	defer mu.Unlock()
	if _, ok := instances[int(id)]; ok {
		return 1
	}
	return 0
}

//export GetLastErrorMessage
func GetLastErrorMessage() *C.char {
	mu.Lock()
	defer mu.Unlock()
	return C.CString(lastErr)
}

//export FreeString
func FreeString(s *C.char) {
	C.free(unsafe.Pointer(s))
}

func setLastErr(msg string) {
	mu.Lock()
	lastErr = msg
	mu.Unlock()
}

func main() {}
