package tpp

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
)

func (t *TPP) Info(ctx context.Context, flowID, msg string, args ...slog.Attr) {
	t.log(ctx, slog.LevelInfo, flowID, msg, args...)
}

func (t *TPP) Error(ctx context.Context, flowID, msg string, args ...slog.Attr) {
	t.log(ctx, slog.LevelError, flowID, msg, args...)
}

func (t *TPP) log(ctx context.Context, level slog.Level, flowID, msg string, args ...slog.Attr) {
	slog.LogAttrs(ctx, level, msg, args...)

	log := &Log{
		ID:        uuid.NewString(),
		FlowID:    flowID,
		Message:   msg,
		Args:      make(map[string]any),
		CreatedAt: timestampNow(),
	}
	for _, arg := range args {
		log.Args[arg.Key] = arg.Value.Any()
	}

	if err := t.storage.save(ctx, log); err != nil {
		slog.ErrorContext(ctx, "failed to save log", "flow_id", flowID, "error", err.Error())
	}
}

func (t *TPP) Logs(ctx context.Context, flowID string) ([]*Log, error) {
	logs := Logs{}
	if err := t.storage.fetchAll(ctx, "flow_id", flowID, &logs); err != nil {
		return nil, fmt.Errorf("could not get logs: %w", err)
	}
	return logs, nil
}
