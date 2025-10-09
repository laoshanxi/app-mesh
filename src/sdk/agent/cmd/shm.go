package main

import "errors"

const (
	ENV_PSK_SHM        = "PSK_SHM_NAME"
	PSK_MSG_LENGTH     = 32
	PSK_FLAG_OFFSET    = 64
	PSK_SHM_TOTAL_SIZE = 128
)

var (
	errNoSHMName      = errors.New("no PSK_SHM_NAME env found")
	errPSKAlreadyRead = errors.New("PSK has already been read")
)
