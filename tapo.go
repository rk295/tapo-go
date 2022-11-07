package tapo

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	timeout = time.Second * 2

	tapoTimeFormat     = "2006-01-02 03:04:05"
	defaultContentType = "application/json"

	defaultAPIPath  = "app"
	defaultScheme   = "http"
	defaultTokenKey = "token"

	methodSecurePassThrough = "securePassthrough"
	methodHandshake         = "handshake"
	methodDeviceLogin       = "login_device"
	methodSetDeviceInfo     = "set_device_info"
	methodGetDeviceInfo     = "get_device_info"
	methodGetEnergyUsage    = "get_energy_usage"
	methodGetDeviceUsage    = "get_device_usage"
)

var (
	errorNoLogin     = errors.New("login was not performed")
	errorNoHandshake = errors.New("handshake was not performed")
)

func New(ip, email, password string) *Device {
	h := sha1.New()
	h.Write([]byte(email))
	digest := hex.EncodeToString(h.Sum(nil))
	encodedEmail := base64.StdEncoding.EncodeToString([]byte(digest))
	encodedPassword := base64.StdEncoding.EncodeToString([]byte(password))

	return &Device{
		ip:              ip,
		encodedEmail:    encodedEmail,
		encodedPassword: encodedPassword,
		client:          &http.Client{Timeout: timeout},
	}
}

func (d *Device) GetURL() string {
	u := &url.URL{
		Scheme: defaultScheme,
		Host:   d.ip,
		Path:   defaultAPIPath,
	}

	if d.token != nil {
		q := u.Query()
		q.Set(defaultTokenKey, *d.token)
		u.RawQuery = q.Encode()
	}
	return u.String()
}

func (d *Device) DoRequest(payload []byte) ([]byte, error) {
	encryptedPayload := base64.StdEncoding.EncodeToString(d.cipher.Encrypt(payload))

	securedPayloadReq := &jsonReq{
		Method: methodSecurePassThrough,
		Params: securePassThroughRequest{
			Request: encryptedPayload,
		},
	}

	securedPayload, err := json.Marshal(securedPayloadReq)
	if err != nil {
		return []byte{}, err
	}

	req, err := http.NewRequest("POST", d.GetURL(), bytes.NewBuffer(securedPayload))
	if err != nil {
		return []byte{}, err
	}

	req.Header.Set("Cookie", d.sessionID)
	req.Close = true

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	jsonResp := &jsonResp{}
	json.NewDecoder(resp.Body).Decode(&jsonResp)

	switch jsonResp.ErrorCode {
	case 9999:
		if err = d.Handshake(); err != nil {
			return nil, err
		}
		if err = d.Login(); err != nil {
			return nil, err
		}

		return d.DoRequest(payload)
	default:
		if err = d.CheckErrorCode(jsonResp.ErrorCode); err != nil {
			return nil, err
		}
	}

	encryptedResponse, err := base64.StdEncoding.DecodeString(jsonResp.Result.Response)
	if err != nil {
		return nil, err
	}

	return d.cipher.Decrypt(encryptedResponse), nil
}

func (d *Device) CheckErrorCode(errorCode int) error {
	if errorCode != 0 {
		return fmt.Errorf("error code %d", errorCode)
	}

	return nil
}

func (d *Device) Handshake() (err error) {
	privKey, pubKey := GenerateRSAKeys()

	pubPEM := DumpRSAPEM(pubKey)

	req := &jsonReq{
		Method: methodHandshake,
		Params: handshakeRequest{
			Key:             string(pubPEM),
			RequestTimeMils: 0,
		},
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return
	}

	resp, err := http.Post(d.GetURL(), defaultContentType, bytes.NewBuffer(payload))
	if err != nil {
		return
	}

	defer resp.Body.Close()

	jsonResp := &jsonResp{}
	json.NewDecoder(resp.Body).Decode(&jsonResp)
	if err = d.CheckErrorCode(jsonResp.ErrorCode); err != nil {
		return
	}

	encryptedEncryptionKey, err := base64.StdEncoding.DecodeString(jsonResp.Result.Key)
	if err != nil {
		return err
	}

	encryptionKey, err := rsa.DecryptPKCS1v15(rand.Reader, privKey, encryptedEncryptionKey)
	if err != nil {
		return err
	}
	d.cipher = &Cipher{
		key: encryptionKey[:16],
		iv:  encryptionKey[16:],
	}

	d.sessionID = strings.Split(resp.Header.Get("Set-Cookie"), ";")[0]

	return
}

func (d *Device) Login() (err error) {
	if d.cipher == nil {
		return errorNoHandshake
	}

	req := &jsonReq{
		Method: methodDeviceLogin,
		Params: loginRequest{
			Username: d.encodedEmail,
			Password: d.encodedPassword,
		},
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return err
	}

	payload, err = d.DoRequest(payload)
	if err != nil {
		return
	}

	jsonResp := &jsonResp{}
	json.NewDecoder(bytes.NewBuffer(payload)).Decode(&jsonResp)
	if err = d.CheckErrorCode(jsonResp.ErrorCode); err != nil {
		return err
	}

	d.token = &jsonResp.Result.Token
	return nil
}

func (d *Device) SetDeviceInfo(params map[string]interface{}) (err error) {
	if d.token == nil {
		return errorNoLogin
	}

	req := &jsonReq{
		Method: methodSetDeviceInfo,
		Params: params,
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return err
	}

	payload, err = d.DoRequest(payload)
	if err != nil {
		return err
	}

	jsonResp := &jsonResp{}
	json.NewDecoder(bytes.NewBuffer(payload)).Decode(&jsonResp)
	if err = d.CheckErrorCode(jsonResp.ErrorCode); err != nil {
		return
	}

	if jsonResp.ErrorCode != 0 {
		return fmt.Errorf("error code %d", jsonResp.ErrorCode)
	}

	return
}

func (d *Device) Switch(status bool) (err error) {
	return d.SetDeviceInfo(map[string]interface{}{
		"device_on": status,
	})
}

func (d *Device) GetDeviceInfo() (*Status, error) {
	status := &Status{}
	if err := d.req(methodGetDeviceInfo, &status); err != nil {
		return status, err
	}
	// Base64 decode the Nickname and SSID of the device to be helpful to users
	// of this module
	nicknameEncoded, err := base64.StdEncoding.DecodeString(status.Nickname)
	if err != nil {
		return status, err
	}
	status.Nickname = string(nicknameEncoded)

	SSIDEncoded, err := base64.StdEncoding.DecodeString(status.SSID)
	if err != nil {
		return status, err
	}
	status.SSID = string(SSIDEncoded)

	return status, nil
}

func (d *Device) GetEnergyUsage() (*EnergyInfo, error) {
	energyInfo := EnergyInfo{}
	if err := d.req(methodGetEnergyUsage, &energyInfo); err != nil {
		return &energyInfo, err
	}
	return &energyInfo, nil
}

func (d *Device) GetDeviceUsage() (*DeviceUsage, error) {
	deviceUsage := DeviceUsage{}
	if err := d.req(methodGetDeviceUsage, &deviceUsage); err != nil {
		return &deviceUsage, err
	}
	return &deviceUsage, nil

}

func (d *Device) req(method string, target interface{}) error {
	if d.token == nil {
		return errorNoLogin
	}

	payload, err := json.Marshal(&jsonReq{Method: method})
	if err != nil {
		return err
	}

	apiResponse := &apiResponse{
		Result: &target,
	}

	reply, err := d.DoRequest(payload)
	if err != nil {
		return err
	}

	if err := json.NewDecoder(bytes.NewBuffer(reply)).Decode(apiResponse); err != nil {
		return err
	}

	if err = d.CheckErrorCode(apiResponse.ErrorCode); err != nil {
		return err
	}

	return nil
}
