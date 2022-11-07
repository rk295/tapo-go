# Tapo Golang

[![Go Reference](https://pkg.go.dev/badge/github.com/rk295/tapo-go)](https://pkg.go.dev/github.com/rk295/tapo-go) [![Go Report Card](https://goreportcard.com/badge/github.com/rk295/tapo-go)](https://goreportcard.com/report/github.com/rk295/tapo-go)

Library for communicating with Tapo devices

## Example usage:

```go
plug := tapo.New("192.168.1.11", "user@example.com", "your password")

if err := device.Handshake(); err != nil {
  log.Panic(err)
}

if err := device.Login(); err != nil {
  log.Panic(err)
}

device.Switch(false)

deviceInfo, err := device.GetDeviceInfo()
```
