package main

import (
	"C"

	"go.etcd.io/etcd/embed"
)
import (
	"errors"

	"go.etcd.io/etcd/pkg/types"
)

// Server represents a Etcd instance
type Server struct {
	Server *embed.Etcd
}

var server Server

// Run runs an embedded etcd server
//export Run
func Run(data string, name string, initialCluster string,
	logLevel string,
	advertiseClient string, listenClient string,
	advertisePeer string, listenPeer string,
) string {
	var err error
	var etcd *embed.Etcd
	cfg := embed.NewConfig()
	if server.Server != nil {
		err = errors.New("Server is already running")
		goto end
	}

	cfg.Dir = data
	cfg.LogLevel = "warn"
	cfg.Name = name
	cfg.InitialCluster = initialCluster
	cfg.LogLevel = logLevel

	if cfg.ACUrls, err = types.NewURLs([]string{advertiseClient}); err != nil {
		goto end
	}
	if cfg.LCUrls, err = types.NewURLs([]string{listenClient}); err != nil {
		goto end
	}
	if cfg.APUrls, err = types.NewURLs([]string{advertisePeer}); err != nil {
		goto end
	}
	if cfg.LPUrls, err = types.NewURLs([]string{listenPeer}); err != nil {
		goto end
	}

	etcd, err = embed.StartEtcd(cfg)
	server.Server = etcd

end:
	if err == nil {
		return ""
	} else {
		return err.Error()
	}
}

// Stop stops etcd server
//export Stop
func Stop() {
	server.Server.Server.Stop()
	server.Server.Close()
	server.Server = nil
}

func main() {}
