package tpp

import (
	"context"
	"fmt"
)

func (t *TPP) Flow(ctx context.Context, id string) (*Flow, error) {
	var flow Flow
	if err := t.storage.fetch(ctx, id, &flow); err != nil {
		return nil, fmt.Errorf("could not get flow: %w", err)
	}
	return &flow, nil
}

func (t *TPP) saveFlow(ctx context.Context, flow *Flow) error {
	if err := t.storage.save(ctx, flow); err != nil {
		return fmt.Errorf("could not save flow: %w", err)
	}
	return nil
}
