package api

import (
	"net/http"

	"github.com/raidiam/mock-tpp/internal/tpp"
)

type Key string

const (
	InteractionIDKey Key = "interaction-id"
)

type sessionHandlerFunc func(http.ResponseWriter, *http.Request, *tpp.Session)

type flowHandlerFunc func(http.ResponseWriter, *http.Request, *tpp.Flow)

type errorPage struct {
	Error         string
	InteractionID string
	FlowID        string
	Nonce         string
}
