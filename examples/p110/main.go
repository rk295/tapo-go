package main

import (
	"encoding/json"
	"fmt"

	"github.com/rk295/tapo-go"
)

func main() {

	device, err := tapo.NewFromEnv()
	if err != nil {
		panic(err)
	}

	if err := device.Login(); err != nil {
		panic(err)
	}

	deviceInfo, err := device.GetDeviceInfo()
	if err != nil {
		panic(err)
	}

	j, _ := json.MarshalIndent(deviceInfo, "", "  ")
	fmt.Println("device_info", string(j))

	if deviceInfo.EmeterSupported() {
		energyInfo, err := device.GetEnergyUsage()
		if err != nil {
			panic(err)
		}

		j, _ = json.MarshalIndent(energyInfo, "", "  ")
		fmt.Println("energy_usage", string(j))

		deviceUsage, err := device.GetDeviceUsage()
		if err != nil {
			panic(err)
		}
		j, _ = json.MarshalIndent(deviceUsage, "", "  ")
		fmt.Println("device_usage", string(j))
	}
}
