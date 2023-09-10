package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/exp/slog"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	wrg "github.com/seankhliao/go-wg"
)


var (
	ListDeviceName string
	WgDeviceName   string 
	SnapLen        int
	WireguardPort  int
	RotateS        int
)

func init() {
	// Setting up the cmdline
	flag.StringVar(&ListDeviceName, "l", "enp0s5", "device where Wireguard's is listening connections")
	flag.StringVar(&WgDeviceName, "d", "wg0", "device created by Wireguard's")

	flag.IntVar(&SnapLen, "s", 262144, "snapshot size")
	flag.IntVar(&WireguardPort, "p", 51923, "wireguard's port")
	flag.IntVar(&RotateS, "r", 86400, "rotation time in seconds")

	flag.Parse()

}

type MacRef struct {
	IntSubnets []string `json:"internal_subnets"`
	ExtIP net.IP		`json:"external_ip"`
}

type SRCStats struct {
	FirstConnected time.Time	`json:"first_connected,omitempty"`
	LastPacket     time.Time	`json:"last_packet,omitempty"`
	PacketN        int 			`json:"packets_count,omitempty"`
}

type LogMessage struct {
	Event string     `json:"event"`

	ConPacket struct {
		SrcIPv4 net.IP `json:"src_ipv4,omitempty"`
		SrcMac  string `json:"src_mac,omitempty"`

		DstIPv4 net.IP `json:"dst_ipv4,omitempty"`

		SrcIPv6 net.IP `json:"src_ipv6,omitempty"`
		DstIPv6 net.IP `json:"dst_ipv6,omitempty"`

		SrcPort int  `json:"src_port,omitempty"`
		DstPort int  `json:"dst_port,omitempty"`

		Stats SRCStats `json:"src_detailed,omitempty"`
	} `json:"pct,omitempty"`
	
	Ref MacRef `json:"ref"`

	WgPacket struct {
		// for inner requests
	} `json:"wg_pct,omitempty"`

}

func (m *LogMessage) SetCon(udp *layers.UDP, ipv4 *layers.IPv4, ipv6 *layers.IPv6) {
	m.ConPacket.DstPort = int(udp.DstPort)
	m.ConPacket.SrcPort = int(udp.SrcPort)

	if ipv4 != nil {
		m.ConPacket.SrcIPv4 = ipv4.SrcIP
		m.ConPacket.DstIPv4 = ipv4.DstIP
	} else {
		m.ConPacket.SrcIPv6 = ipv6.SrcIP
		m.ConPacket.DstIPv6 = ipv6.DstIP
	}
}

func (m *LogMessage) SetRef(details *MacRef) {
	m.Ref = *details
}

func (m *LogMessage) SetSRCDetails(details *SRCStats) {
	m.ConPacket.Stats = *details
}

func (m *LogMessage) SetEtherDetails(details *layers.Ethernet) {
	m.ConPacket.SrcMac = details.SrcMAC.String()
}

func (m *LogMessage) RaiseDetails() {
	slog.Info(
		"New event on main loop", "details", m,
	)
}

func (m *LogMessage) Raise() {
	slog.Info(
		"New event on main loop", slog.String("details", m.Event),
	)
}

func NewMessage(event string) *LogMessage {
	return &LogMessage{
		Event: event,
	}
}

func setupLogger(fd *os.File) {
	logger := slog.New(slog.NewJSONHandler(fd, nil))
	slog.SetDefault(logger)
}


func conLogs(fd *os.File, refs map[string]*MacRef) {
	srcMap := make(map[string]*SRCStats)
	
	rule := fmt.Sprintf("port %d", WireguardPort)
	ticker := time.Tick(time.Millisecond * time.Duration(RotateS))

	NewMessage(fmt.Sprintf("Wireguard-logger started with rule: %s", rule)).Raise()

	for {
		mon, err := pcap.OpenLive(ListDeviceName, int32(SnapLen), true, pcap.BlockForever)
		if err != nil {
			panic(err)
		}

		if err := mon.SetBPFFilter(rule); err != nil {
			panic(err)
		}

		stream := gopacket.NewPacketSource(mon, mon.LinkType()).Packets()
		
		for packet := range stream {
			msg := NewMessage("udp packet")

			if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
				udpd, _ := udpLayer.(*layers.UDP)
				
				if ip4l, ip6l := packet.Layer(layers.LayerTypeIPv4), packet.Layer(layers.LayerTypeIPv4); ip4l != nil || ip6l != nil {
					ip4d, _ := ip4l.(*layers.IPv4)
					ip6d, _ := ip6l.(*layers.IPv6)
					
					// Load base info
					msg.SetCon(udpd, ip4d, ip6d)
					
					// Load src_stats
					var kIP net.IP
					if ip4d != nil {
						kIP = ip4d.SrcIP
						
					} else {
						kIP = ip6d.SrcIP
					}
					
					if stats, found := srcMap[string(kIP)]; !found {
						srcMap[string(kIP)] = &SRCStats{
							FirstConnected: time.Now(),
							LastPacket: time.Now(),
							PacketN: 1,
						}
						
						// first time connected event
						NewMessage(fmt.Sprintf("%s connected first time at %v", kIP, time.Now())).Raise()
					} else {
						stats.LastPacket = time.Now()
						stats.PacketN += 1
					}
					msg.SetSRCDetails(srcMap[string(kIP)])
						
					// Because wireguard is connectionless I think that collecting the MAC address of src is a good idea
					if ethl := packet.Layer(layers.LayerTypeEthernet); ethl != nil {
						ethd, _ := ethl.(*layers.Ethernet)
						msg.SetEtherDetails(ethd)
						
						// Save external and internal ip to mac-ref table
						srcMac := ethd.SrcMAC.String()
						
						if _, ok := refs[srcMac]; !ok {
							refs[srcMac] = new(MacRef)
							refs[srcMac].ExtIP = kIP
							

							// Get internal subnets from wg
							if wrgStatus, err := wrg.Show(WgDeviceName); err == nil {
								
								for _, peer := range wrgStatus.Peers {
									
									// Found our client in peers?
									if strings.Contains(peer.Endpoint, kIP.String()) {
										refs[srcMac].IntSubnets = peer.AllowedIPs
										break
									}
								}
							}	
						}
						msg.SetRef(refs[srcMac])
					}
					
				}
			}
			msg.RaiseDetails()
		}

		mon.Close()
		fd.Sync()

		<- ticker
	}

}

func wgLogs(fd *os.File, refs map[string]*MacRef) {
	// Here we'll be listening to internal events

	ticker := time.Tick(time.Millisecond * time.Duration(RotateS))
	for {
		mon, err := pcap.OpenLive(WgDeviceName, int32(SnapLen), true, pcap.BlockForever)
		if err != nil {
			panic(err)
		}

		stream := gopacket.NewPacketSource(mon, mon.LinkType()).Packets()

		for packet := range stream {			
			// TODO: monitor the internal network
			_ = packet
		}

		<- ticker
	}

}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	fd, err := os.OpenFile("wgl.log",  os.O_CREATE|os.O_RDWR, 0777)
	if err != nil {
		panic(err)
	}
	setupLogger(fd)

	macRefTable := make(map[string]*MacRef)

	go conLogs(fd, macRefTable)
	go wgLogs(fd, macRefTable)

	<- ctx.Done()

	NewMessage("Wireguard-logger shutdown").Raise()
	fd.Close()
}