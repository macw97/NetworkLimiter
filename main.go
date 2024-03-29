package main

import (
	"flag"
	"fmt"
	"net"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

func createFilter(ip string, bandwidth int, packetsPerS int) {
	connections := &nftables.Conn{}

	if kernel_tabs, err := connections.ListTables(); err == nil {
		for _, tab := range kernel_tabs {
			if tab.Name == "test" {
				connections.DelTable(tab)
			}
		}
	} else {
		fmt.Println("List tables error - ", err)
	}

	table := &nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "test",
	}

	table = connections.AddTable(table)

	myChain := connections.AddChain(&nftables.Chain{
		Name:     "input",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
	})

	if packetsPerS != 0 {
		connections.AddRule(&nftables.Rule{
			Table: table,
			Chain: myChain,
			Exprs: []expr.Any{
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       12,
					Len:          4,
				},

				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     net.ParseIP(ip).To4(),
				},

				&expr.Limit{
					Type:  expr.LimitTypePkts,
					Rate:  uint64(packetsPerS),
					Over:  true,
					Unit:  expr.LimitTimeSecond,
					Burst: 1,
				},

				&expr.Verdict{
					Kind: expr.VerdictDrop,
				},
			},
		})
	} else if bandwidth != 0 {

		connections.AddRule(&nftables.Rule{
			Table: table,
			Chain: myChain,
			Exprs: []expr.Any{
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       12,
					Len:          4,
				},

				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     net.ParseIP(ip).To4(),
				},

				&expr.Limit{
					Type:  expr.LimitTypePktBytes,
					Rate:  uint64(bandwidth),
					Over:  true,
					Unit:  expr.LimitTimeSecond,
					Burst: 1,
				},

				&expr.Verdict{
					Kind: expr.VerdictDrop,
				},
			},
		})
	}

	if err := connections.Flush(); err != nil {
		fmt.Println("Add rule failed: ", err)
	}

	if connects, err := connections.ListChains(); err != nil {
		fmt.Println("table error - ", err)
	} else {
		for _, s := range connects {
			fmt.Println(s)
		}
		fmt.Println(myChain)
	}

}

func main() {
	var help bool
	var ip string
	var bandwidth int
	var packetsPerS int

	flag.BoolVar(&help, "h", false, "Command line arguments help")
	flag.StringVar(&ip, "ip", "127.0.0.1", "Ip address with which limit traffic")
	flag.IntVar(&bandwidth, "b", 0, "Bandwidth limit in kpbs")
	flag.IntVar(&packetsPerS, "pkt", 0, "Packets per second")
	flag.Parse()
	if help {
		flag.PrintDefaults()
	} else {
		fmt.Println("ip:", ip, "\nbandwidth (kbps):", bandwidth, "\nPackets per second:", packetsPerS)
	}

	// Make parameters valid check

	createFilter(ip, bandwidth, packetsPerS)
}
