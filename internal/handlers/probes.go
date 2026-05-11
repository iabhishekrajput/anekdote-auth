package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/julienschmidt/httprouter"
)

const probeTimeout = 2 * time.Second

type ProbeHandler struct {
	db          *sql.DB
	redisClient *redis.Client
}

type probeResponse struct {
	Status string            `json:"status"`
	Checks map[string]string `json:"checks,omitempty"`
}

func NewProbeHandler(db *sql.DB, redisClient *redis.Client) *ProbeHandler {
	return &ProbeHandler{
		db:          db,
		redisClient: redisClient,
	}
}

func (h *ProbeHandler) Health(w http.ResponseWriter, _ *http.Request, _ httprouter.Params) {
	writeProbeResponse(w, http.StatusOK, probeResponse{Status: "ok"})
}

func (h *ProbeHandler) Ready(w http.ResponseWriter, _ *http.Request, _ httprouter.Params) {
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()

	checks := map[string]string{
		"postgres": "ok",
		"redis":    "ok",
	}

	statusCode := http.StatusOK
	status := "ready"

	if h.db == nil || h.db.PingContext(ctx) != nil {
		checks["postgres"] = "down"
		statusCode = http.StatusServiceUnavailable
		status = "not_ready"
	}

	if h.redisClient == nil || h.redisClient.Ping(ctx).Err() != nil {
		checks["redis"] = "down"
		statusCode = http.StatusServiceUnavailable
		status = "not_ready"
	}

	writeProbeResponse(w, statusCode, probeResponse{
		Status: status,
		Checks: checks,
	})
}

func writeProbeResponse(w http.ResponseWriter, statusCode int, payload probeResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(payload)
}
