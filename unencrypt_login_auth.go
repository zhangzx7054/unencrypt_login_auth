package unencrypt_login_auth

import (
	"errors"
	"net/smtp"
)

type unencryptplainAuth struct {
	identity, username, password string
	host                         string
}

func UnEncryptedPlainAuth(identity, username, password, host string) smtp.Auth {
	return &unencryptplainAuth{identity, username, password, host}
}

func (a *unencryptplainAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	if server.Name != a.host {
		return "", nil, errors.New("wrong host name")
	}
	resp := []byte(a.identity + "\x00" + a.username + "\x00" + a.password)
	return "PLAIN", resp, nil
}

func (a *unencryptplainAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	return nil, nil
}

type loginAuth struct {
	username, password string
}

func LoginAuth(username, password string) smtp.Auth {
	return &loginAuth{username, password}
}

func (a *loginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	return "LOGIN", []byte{}, nil
}

func (a *loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if more {
		switch string(fromServer) {
		case "Username:":
			return []byte(a.username), nil
		case "Password:":
			return []byte(a.password), nil
		}
	}
	return nil, nil
}
