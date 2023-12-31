package main

import (
	"encoding/json"
	"fmt"

	"github.com/jodydadescott/unifi-go-sdk"
)

func main() {

	hostname := "https://10.0.1.1"
	user := "homeauto"
	pass := "******"

	unifiClient := unifi.New(&unifi.Config{
		Hostname: hostname,
		Username: user,
		Password: pass,
	})

	// devices, err := unifiClient.GetDevices()

	devices, err := unifiClient.GetClients()

	// devices, err := unifiClient.GetEnrichedConfiguration()

	if err != nil {
		panic(err)
	}

	b, _ := json.Marshal(devices)

	fmt.Println(string(b))

	// for _, networkDevice := range devices.NetworkDevices {
	// 	//networkDevice.Name

	// 	fmt.Println(networkDevice.Name + " " + networkDevice.IP)

	// 	// for _, port := range networkDevice.PortTable {
	// 	// 	fmt.Println(networkDevice.Name + " " + port.IP)
	// 	// }

	// }

	// }

	// enrichedConfigs, err := unifiClient.GetEnrichedConfiguration()

	// if err != nil {
	// 	panic(err)
	// }

	// for _, enrichedConfig := range enrichedConfigs {
	// 	fmt.Println(enrichedConfig.Configuration.Name + " " + enrichedConfig.Configuration.IPSubnet)
	// }

}
