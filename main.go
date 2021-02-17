package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"time"

	"github.com/pelletier/go-toml"
	"github.com/urfave/cli/v2"
	ldap "github.com/vjeantet/ldapserver"
	"go.etcd.io/etcd/clientv3"
	"go.etcd.io/etcd/embed"
	"go.etcd.io/etcd/pkg/types"
	etcdVersion "go.etcd.io/etcd/version"
)

// Host struct represents a host
type Host struct {
	HostName        string
	ListenClient    string
	AdvertiseClient string
	ListenPeer      string
	AdvertisePeer   string
	Ldap            string
	TLSCert         string
	TLSKey          string
}

// Config struct for config file
type Config struct {
	RootPassword string
	EtcdPassword string
	Host         []Host
}

var etcd *embed.Etcd
var client *clientv3.Client
var kvc clientv3.KV
var config Config
var host Host

func action(c *cli.Context) error {
	if c.Bool("install") {
		log.Printf("Installing daccountd.service to /etc/systemd/system")
		err := ioutil.WriteFile("/etc/systemd/system/daccountd.service", systemdService, 0644)
		if err != nil {
			log.Printf("Installing daccountd.service failed with %s", err)
		}

		log.Printf("Installing daccountd to /usr/sbin/daccountd")
		err = exec.Command("install", "-m", "755", os.Args[0], "/usr/sbin/daccountd").Run()
		if err != nil {
			log.Printf("Installing daccountd failed with %s", err)
		}
		return nil
	}

	sigChannel := make(chan os.Signal, 1)
	signal.Notify(sigChannel, os.Interrupt)

	configFile := c.String("config")
	stat, err := os.Stat(configFile)
	if err != nil {
		log.Fatal("Failed to stat config file: ", err)
		return err
	} else if stat.Mode()&0600 != stat.Mode() {
		log.Fatalf("Config file mode(%o) should be a subset of 600", stat.Mode())
		return err
	}

	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		log.Fatal("Failed to read config file: ", err)
		return err
	}

	config = Config{}
	err = toml.Unmarshal(data, &config)
	if err != nil {
		log.Fatal("Failed to parse config file: ", err)
		return err
	}

	// override
	envEtcdPasswd := os.Getenv("DACCOUNTD_ETCD_PASSWORD")
	if envEtcdPasswd != "" {
		config.EtcdPassword = envEtcdPasswd
	}

	hostname := c.String("host")

	host = Host{}
	initialCluster := ""
	for h := range config.Host {
		initialCluster += fmt.Sprintf(",%s=%s", config.Host[h].HostName, config.Host[h].AdvertisePeer)
		if config.Host[h].HostName == hostname {
			log.Printf("Found config for host %s", hostname)
			host = config.Host[h]
		}
	}
	// strip leading comma
	initialCluster = initialCluster[1:]

	if host.HostName == "" {
		log.Fatalf("Config not found for hostname %s", hostname)
		return err
	}

	if host.TLSKey != "" {
		stat, err := os.Stat(host.TLSKey)
		if err != nil {
			log.Fatal("Failed to stat tls key file: ", err)
			return err
		} else if stat.Mode()&0600 != stat.Mode() {
			log.Fatalf("TLS file mode(%o) should be a subset of 600", stat.Mode())
			return err
		}
	}

	cfg := embed.NewConfig()
	cfg.Dir = c.String("data-dir")
	cfg.LogLevel = "warn"
	cfg.Name = hostname
	cfg.InitialCluster = initialCluster
	cfg.LogOutputs = []string{fmt.Sprintf("etcd-%s.log", hostname)}
	cfg.ClientAutoTLS = true
	cfg.PeerAutoTLS = true
	cfg.Logger = "zap"
	if c.Bool("existing") {
		cfg.ClusterState = "existing"
	}

	if host.AdvertiseClient != "" {
		if cfg.ACUrls, err = types.NewURLs([]string{host.AdvertiseClient}); err != nil {
			log.Fatalf("Bad url(%s): %s", host.AdvertiseClient, err)
			return err
		}
	}
	if host.ListenClient != "" {
		if cfg.LCUrls, err = types.NewURLs([]string{host.ListenClient}); err != nil {
			log.Fatalf("Bad url(%s): %s", host.ListenClient, err)
			return err
		}
	}
	if host.AdvertisePeer != "" {
		if cfg.APUrls, err = types.NewURLs([]string{host.AdvertisePeer}); err != nil {
			log.Fatalf("Bad url(%s): %s", host.AdvertisePeer, err)
			return err
		}
	}
	if host.ListenPeer != "" {
		if cfg.LPUrls, err = types.NewURLs([]string{host.ListenPeer}); err != nil {
			log.Fatalf("Bad url(%s): %s", host.ListenPeer, err)
			return err
		}
	}

	log.Printf("Using etcd version %s", etcdVersion.Version)
	log.Printf("Using advertise client url: %s", cfg.ACUrls[0].String())
	log.Printf("Using listen client url: %s", cfg.LCUrls[0].String())
	log.Printf("Using advertise peer url: %s", cfg.APUrls[0].String())
	log.Printf("Using listen peer url: %s", cfg.LPUrls[0].String())
	log.Printf("Using initial cluster: %s", cfg.InitialCluster)

	etcd, err = embed.StartEtcd(cfg)
	if err != nil {
		log.Fatal("Failed to start embedded etcd: ", err)
		return err
	}
	log.Printf("Server started")
	defer etcd.Close()

	// too verbose
	ldap.Logger = ldap.DiscardingLogger
	ldapServer := ldap.NewServer()

	routes := ldap.NewRouteMux()
	routes.Bind(handleBind)
	routes.Search(handleSearchDSE).
		BaseDn("").
		Scope(ldap.SearchRequestScopeBaseObject).
		Filter("(objectclass=*)")
	routes.Search(handleSearch)
	routes.Add(handleAdd)
	routes.Delete(handleDelete)
	routes.Abandon(handleAbandon)
	routes.Modify(handleModify)
	routes.Extended(handleStartTLS).
		RequestName(ldap.NoticeOfStartTLS)
	routes.Extended(handlePasswordModify).
		RequestName(ldap.NoticeOfPasswordModify)
	ldapServer.Handle(routes)

	go ldapServer.ListenAndServe(host.Ldap)

	etcdUsername := ""
	etcdPassword := ""
	if config.EtcdPassword != "" {
		log.Printf("Using root user to access etcd")
		etcdUsername = "root"
		etcdPassword = config.EtcdPassword
	} else {
		log.Printf("Etcd is unprotected, please beware!")
	}

	client, err = clientv3.New(clientv3.Config{
		Endpoints:   []string{host.ListenClient},
		DialTimeout: 5 * time.Second,
		Username:    etcdUsername,
		Password:    etcdPassword,
	})
	if err != nil {
		log.Fatal("Failed to start etcd client: ", err)
		return err
	}

	auth := clientv3.NewAuth(client)

	// check authentication is good
	_, err = auth.UserList(context.Background())
	if err != nil {
		log.Fatal("Authentication failed, please check root password setting")
		return err
	}

	// if EtcdPassword is set, test root user and enable auth
	if config.EtcdPassword != "" {
		auth := clientv3.NewAuth(client)

		_, err = auth.UserGet(context.Background(), "root")
		if err != nil {
			log.Printf("Root user does not exist, creating etcd root user")
			_, err := auth.UserAdd(context.Background(), "root", config.EtcdPassword)
			if err != nil {
				log.Fatal("Failed to create etcd root user: ", err)
				return err
			}
		}

		log.Printf("Granting root role to etcd root user")
		_, err = auth.UserGrantRole(context.Background(), "root", "root")
		if err != nil {
			log.Fatal("Failed to grant root role: ", err)
			return err
		}

		log.Printf("Enabling etcd auth")
		_, err = auth.AuthEnable(context.Background())
		if err != nil {
			log.Fatal("Failed to enable auth on etcd: ", err)
			return err
		}

		log.Printf("Etcd is protected")
	}

	// check authentication is good again
	_, err = auth.UserList(context.Background())
	if err != nil {
		log.Fatal("Authentication failed, please check root password setting")
		return err
	}

	kvc = clientv3.NewKV(client)
	defer client.Close()

	exit := false
	for !exit {
		select {
		case sig := <-sigChannel:
			log.Printf("Received signal %s, stopping", sig)
			etcd.Server.Stop()
			ldapServer.Stop()
			exit = true
		}
	}

	return nil
}

func main() {
	hostname, err := os.Hostname()
	if err != nil {
		log.Printf("Failed to get hostname: %s", err)
	}

	app := &cli.App{
		Name:  "daccountd",
		Usage: "A distributed account system",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "data-dir",
				Value: "data",
				Usage: "The path to data directory",
			},
			&cli.StringFlag{
				Name:  "config",
				Value: "config.toml",
				Usage: "The path to config file",
			},
			&cli.StringFlag{
				Name:  "host",
				Value: hostname,
				Usage: "Override host name",
			},
			&cli.BoolFlag{
				Name:  "existing",
				Usage: "Join existing cluster",
			},
			&cli.BoolFlag{
				Name:  "install",
				Usage: "Install systemd service to /etc/systemd/system",
			},
		},
		Action: action,
	}

	err = app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}

}
