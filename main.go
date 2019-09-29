package main

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"net"
	"os"
)

type host struct {
	IPv4      string
	IPv6      string
	Hostname  string
	IPv4Ports []int
	IPV6Ports []int
	next      *host
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Missing parameter. Provide Shodan csv export file.")
		return
	}

	al := genHostList(os.Args[1])

	for p := al; p.next != nil; p = p.next {
		fmt.Printf("IPv4: %v, IPv6: %v, Hostname: %v\n", p.IPv4, p.IPv6, p.Hostname)
	}
}

func enrich(i *host) bool {
	if addr := net.ParseIP(i.IPv6); addr == nil {
		return false
	}

	if i.Hostname == "" {
		record, err := net.LookupAddr(i.IPv6)
		if err != nil || len(record) == 0 {
			return false
		}
		i.Hostname = record[0]
	}

	//Get IPv4 from hostname
	IP, err := net.LookupHost(i.Hostname)

	if err != nil {
		return false
	}

	for _, a := range IP {
		netA := net.ParseIP(a)

		if netA.To4() != nil {
			i.IPv4 = netA.String()
			return true
		}
	}
	return false
}

func genHostList(fileName string) *host {
	var hostList host
	csvFile, err := os.Open(fileName)

	if err != nil {
		fmt.Println("Error, could not open input file: ", err)
	}

	r := csv.NewReader(bufio.NewReader(csvFile))
	for {
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatal(err)
		}
		temp := host{
			IPv6:     record[0],
			Hostname: record[4],
		}

		if OK := enrich(&temp); OK {
			addNode(&temp, &hostList)
		}
	}

	if hostList.IPv4 == "" {
		hostList = *hostList.next
	}

	return &hostList
}

func addNode(newHost, hostList *host) *host {
	if hostList == nil {
		return newHost
	}

	for p := hostList; p != nil; p = p.next {
		if p.next == nil {
			p.next = newHost
			return hostList
		}
	}
	return hostList
}
