package tapo

import (
	"net/http"
	"strings"
	"time"
)

type apiResponse struct {
	ErrorCode int          `json:"error_code"`
	Result    *interface{} `json:"result"`
}

type Status struct {
	Avatar             string `json:"avatar"`
	DeviceID           string `json:"device_id"`
	DeviceON           bool   `json:"device_on"`
	FWID               string `json:"fw_id"`
	FWVersion          string `json:"fw_ver"`
	HasSetLocationInfo bool   `json:"has_set_location_info"`
	HWID               string `json:"hw_id"`
	HWVersion          string `json:"hw_ver"`
	IP                 string `json:"ip"`
	Lang               string `json:"lang"`
	Latitude           int    `json:"latitude"`
	Location           string `json:"location"`
	Longitude          int    `json:"longitude"`
	MAC                string `json:"mac"`
	Model              string `json:"model"`
	Nickname           string `json:"nickname"`
	OEMID              string `json:"oem_id"`
	OnTime             int    `json:"on_time"` // The time in seconds this device has been ON since the last state change (ON/OFF
	OverHeated         bool   `json:"overheated"`
	Region             string `json:"Europe/Kiev"`
	RSSI               int    `json:"rssi"`
	SignalLevel        int    `json:"signal_level"`
	Specs              string `json:"specs"`
	SSID               string `json:"ssid"`
	TimeDiff           int    `json:"time_diff"`
	Type               string `json:"type"`
}

type EnergyInfo struct {
	CurrentPower      int      `json:"current_power"`      // Current power in milliwatts (mW)
	ElectricityCharge []int    `json:"electricity_charge"` // Unknown!
	LocalTime         TapoTime `json:"local_time"`         // Local time, with the UTC offset assumed from the machine this call is made on
	MonthEnergy       int      `json:"month_energy"`       // Past 30 days energy usage in watts (W)
	MonthRuntime      int      `json:"month_runtime"`      // Past 30 days runtime in minutes
	TodayEnergy       int      `json:"today_energy"`       // Today energy usage in watts (W)
	TodayRuntime      int      `json:"today_runtime"`      // Today runtime in minutes
}

type DeviceUsage struct {
	PowerUsage Usage `json:"power_usage"`
	SavedPower Usage `json:"saved_power"`
	TimeUsage  Usage `json:"time_usage"`
}

type Usage struct {
	Past30 int `json:"past30"`
	Past7  int `json:"past7"`
	Today  int `json:"today"`
}

type Device struct {
	cipher          *Cipher
	client          *http.Client
	encodedEmail    string
	encodedPassword string
	ip              string
	sessionID       string
	token           *string
}

type jsonReq struct {
	Method string                 `json:"method"`
	Params map[string]interface{} `json:"params"`
}

type jsonResp struct {
	ErrorCode int `json:"error_code"`
	Result    struct {
		Key      string `json:"key,omitempty"`
		Response string `json:"response,omitempty"`
		Token    string `json:"token,omitempty"`
	} `json:"result"`
}

type TapoTime time.Time

func (t *TapoTime) UnmarshalJSON(data []byte) error {
	// Remove JSON quotes from the string
	s := strings.Replace(string(data), "\"", "", -1)

	// Some values are null or empty, so we can't parse them
	if s == "null" || s == "" {
		*t = TapoTime(time.Time{})
		return nil
	}

	// Its always UTC
	tParsed, err := time.ParseInLocation(tapoTimeFormat, s, time.UTC)
	if err != nil {
		*t = TapoTime(time.Time{})
		return err
	}
	*t = TapoTime(tParsed)
	return nil
}
