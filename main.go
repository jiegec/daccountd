package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/pelletier/go-toml"
	"github.com/urfave/cli/v2"
	"go.etcd.io/etcd/embed"
	"go.etcd.io/etcd/pkg/types"
)

// Host struct represents a host
type Host struct {
	HostName        string
	ListenClient    string
	AdvertiseClient string
	ListenPeer      string
	AdvertisePeer   string
}

// Config struct for config file
type Config struct {
	Host []Host
}

func dumpPacket(packet *ber.Packet, indent int) {
	log.Printf("%s Id=%+v Val=%+v", strings.Repeat(" ", indent), packet.Identifier, packet.Value)
	for i := range packet.Children {
		dumpPacket(packet.Children[i], indent+2)
	}
}

func handleLdapConnection(c net.Conn) {
	log.Printf("Handle LDAP connection from %s", c.RemoteAddr().String())
	defer c.Close()
	for {
		packet, err := ber.ReadPacket(c)
		if err != nil {
			log.Print("Failed to read packet: ", err)
			return
		}
		dumpPacket(packet, 0)
	}
}

func ldapServer() {
	l, err := net.Listen("tcp", ":1389")
	if err != nil {
		log.Fatal("Failed to listen", err)
		return
	}
	log.Printf("Listening LDAP on :1389")

	defer l.Close()

	for {
		c, err := l.Accept()
		if err != nil {
			log.Fatal("Failed to accept", err)
			return
		}
		go handleLdapConnection(c)
	}
}

func action(c *cli.Context) error {
	sigChannel := make(chan os.Signal, 1)
	signal.Notify(sigChannel, os.Interrupt)

	configFile := c.String("config")
	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		log.Fatal("Failed to read config file: ", err)
		return err
	}

	config := Config{}
	err = toml.Unmarshal(data, &config)
	if err != nil {
		log.Fatal("Failed to parse config file: ", err)
		return err
	}

	hostname := c.String("host")

	host := Host{}
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

	cfg := embed.NewConfig()
	cfg.Dir = c.String("data-dir")
	cfg.LogLevel = "warn"
	cfg.Name = hostname
	cfg.InitialCluster = initialCluster

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

	log.Printf("Using advertise client url: %s", cfg.ACUrls[0].String())
	log.Printf("Using listen client url: %s", cfg.LCUrls[0].String())
	log.Printf("Using advertise peer url: %s", cfg.APUrls[0].String())
	log.Printf("Using listen peer url: %s", cfg.LPUrls[0].String())
	log.Printf("Using initial cluster: %s", cfg.InitialCluster)

	server, err := embed.StartEtcd(cfg)
	if err != nil {
		log.Fatal("Failed to start embedded etcd", err)
		return err
	}
	log.Printf("Server started")
	defer server.Close()

	go ldapServer()

	exit := false
	for !exit {
		select {
		case sig := <-sigChannel:
			log.Printf("Received signal %s, stopping", sig)
			server.Server.Stop()
			exit = true
		}
	}
	log.Printf("Stopped, exiting")
	os.Exit(0)

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
		},
		Action: action,
	}

	err = app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}

}
