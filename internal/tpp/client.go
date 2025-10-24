package tpp

import (
	"context"
	"fmt"
)

func (t *TPP) client(ctx context.Context, authServerID string) (*Client, error) {
	var client Client
	if err := t.storage.fetch(ctx, authServerID, &client); err != nil {
		return nil, fmt.Errorf("could not get client: %w", err)
	}
	return &client, nil
}

func (t *TPP) saveClient(ctx context.Context, client *Client) error {
	if err := t.storage.save(ctx, client); err != nil {
		return fmt.Errorf("could not save client: %w", err)
	}
	return nil
}
