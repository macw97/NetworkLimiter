package main

import (
	"fmt"
	"os"
	"os/signal"
	"time"
	"syscall"
	"flag"
	"net"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

func getMetrics(counter *nftables.CounterObj, conn *nftables.Conn) {
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		os.Exit(1)
	}()
	
	for {
		c, err := conn.GetObj(counter)
		if err != nil {
			fmt.Printf("Getting object failed: ",err)
			os.Exit(1)
		}
		co, ok := c[0].(*nftables.CounterObj)
		if !ok {
			fmt.Printf("Getting counter failed: ", err)
		}
		time.Sleep(10 * time.Second)
		fmt.Println("Current packets = ", co.Packets, "bytes = ", co.Bytes)
	}
}

func createFilter(ip string, bandwidth int, packetsPerS int) {
	connections := &nftables.Conn{}

	table := &nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name: "ip_filter",
	}

	table = connections.AddTable(table)
	myChain := connections.AddChain(&nftables.Chain{
		Name: "filter",
		Table: table,
		Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
	})
	
	counter := connections.AddObj(&nftables.CounterObj{
		Table: table,
		Name:  "packet_counter",
		
	}).(*nftables.CounterObj)
	
	// set := &nftables.Set{
	// 	Name: "whitelist",
	// 	Table: table,
	// 	KeyType: nftables.TypeIPAddr,
	// }

	// if err:= connections.AddSet(set, []nftables.SetElement{
	// 	{Key: net.ParseIP(ip)},
	// }); err != nil {
	// 	fmt.Println("Add set failed for ip: ", ip, " err: ", err)
	// 	os.Exit(1)
	// }

	connections.AddRule(&nftables.Rule{
		Table: table,
		Chain: myChain,
		Exprs: []expr.Any{
			&expr.Payload{
				DestRegister: 1,
				Base: expr.PayloadBaseNetworkHeader,
				Offset: 16,
				Len: 4,
			},
			&expr.Cmp{
				Op: expr.CmpOpEq,
				Register: 1,
				Data: net.ParseIP(ip).To4(),
			},

			&expr.Objref{
				Type: 1,
				Name: counter.Name,
			},
		},
	})
	
	if err := connections.Flush(); err != nil {
		fmt.Println("Add rule failed: ",err)
	}

	getMetrics(counter, connections)
}


func main() {
	var help bool
	var ip string
	var bandwidth int
	var packetsPerS int
	flag.BoolVar(&help, "h", false, "Command line arguments help")
	flag.StringVar(&ip, "ip","127.0.0.1", "Ip address with which limit traffic")
	flag.IntVar(&bandwidth, "b", 10000, "Bandwidth limit in kpbs")
	flag.IntVar(&packetsPerS, "pkt", 1000, "Packets per second")
	flag.Parse()
	if help {
		flag.PrintDefaults()
	} else {
		fmt.Println("ip:", ip,"\nbandwidth (kbps):", bandwidth,"\nPackets per second:", packetsPerS)
	}

	// Make parameters valid check

	createFilter(ip, bandwidth, packetsPerS)
}