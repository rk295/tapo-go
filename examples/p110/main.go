package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/rk295/tapo-go"
)

func main() {

	ip := os.Getenv("TAPO_IP")
	email := os.Getenv("TAPO_EMAIL")
	password := os.Getenv("TAPO_PASSWORD")

	device := tapo.New(ip, email, password)

	if err := device.Handshake(); err != nil {
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
