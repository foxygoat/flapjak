package main

import "github.com/jimlambrt/gldap"

type LDAPError uint16

func (e LDAPError) Error() string {
	if s, ok := gldap.ResultCodeMap[uint16(e)]; ok {
		return s
	}
	return "unknown error"
}

func (e LDAPError) ResultCode() int {
	return int(e)
}
