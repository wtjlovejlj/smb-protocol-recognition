package main

import (
	"flag"
	"fmt"
	"scan_smb/smb/dcerpc"

	"scan_smb/smb"
)

func main() {

	//hostname := "172.16.20.45"
	hostname := ""
	port := 0
	IsShare := true
	flag.StringVar(&hostname, "hostname", "47.98.212.252", "IP:")
	flag.IntVar(&port, "port", 445, "端口号:")
	flag.Parse()
	options := smb.Options{
		Host: hostname,
		Port: port,
		Initiator: &smb.NTLMInitiator{
			User:     "share",
			Password: "123456",
		},
	}
	session, err := smb.NewConnection(options)
	if err != nil {
		fmt.Println(err)
		IsShare = false
		//return
	}
	defer session.Close()

	fmt.Println("SMB Status:")
	if session.IsAuthenticated {
		fmt.Printf("Authentication : disabled\n")
		IsShare = true
	} else {
		fmt.Printf("Authentication : enable\n")
		IsShare = false
	}

	fmt.Printf("SMB Vsersion :%s", session.Version)

	if IsShare {
		share := "IPC$"
		err = session.TreeConnect(share)
		if err != nil {
			fmt.Println(err)
			return
		}
		defer session.TreeDisconnect(share)
		f, err := session.OpenFile(share, "srvsvc")
		if err != nil {
			fmt.Println(err)
			return
		}
		defer f.CloseFile()

		bind, err := dcerpc.Bind(f, dcerpc.MSRPCUuidSrvSvc, 3, 0, dcerpc.MSRPCUuidNdr)
		if err != nil {
			fmt.Println(err)
			return
		}

		shares, err := bind.NetShareEnumAll(hostname)
		if err != nil {
			fmt.Println(err)
			return
		}

		fmt.Printf("\nShares:\n")
		for _, share := range shares {
			fmt.Printf("Name: %s\nType: %s\nComment: %s\n", share.Name, share.Type, share.Comment)
		}
	}
	fmt.Println("\n结束")
}
