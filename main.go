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
			// &expr.Lookup{
			// 	SourceRegister: 1,
			// 	SetName:        set.Name,
			// 	SetID:          set.ID,
			// },
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     net.ParseIP(ip).To4(),
			},

			// &expr.Limit{
			// 	Type:  expr.LimitTypePkts,
			// 	Rate:  uint64(packetsPerS),
			// 	Over:  false,
			// 	Unit:  expr.LimitTimeMinute,
			// 	Burst: 0,
			// },
			// &expr.Verdict{
			// 	Kind: expr.VerdictAccept,
			// },

			&expr.Limit{
				Type:  expr.LimitTypePkts,
				Rate:  uint64(packetsPerS),
				Over:  true,
				Unit:  expr.LimitTimeSecond,
				Burst: 0,
			},

			&expr.Verdict{
				Kind: expr.VerdictDrop,
			},
		},
	})

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
	flag.IntVar(&bandwidth, "b", 100, "Bandwidth limit in kpbs")
	flag.IntVar(&packetsPerS, "pkt", 3, "Packets per second")
	flag.Parse()
	if help {
		flag.PrintDefaults()
	} else {
		fmt.Println("ip:", ip, "\nbandwidth (kbps):", bandwidth, "\nPackets per second:", packetsPerS)
	}

	// Make parameters valid check

	createFilter(ip, bandwidth, packetsPerS)
}
