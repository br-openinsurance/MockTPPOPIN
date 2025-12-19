package tpp

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type Item interface {
	TableName() string
}

type Items interface {
	TableName() string
}

type Storage interface {
	save(ctx context.Context, item Item) error
	fetch(ctx context.Context, id string, item Item) error
	fetchAll(ctx context.Context, key, value string, items Items) error
	delete(ctx context.Context, id string, item Item) error
}

type storage struct {
	db *dynamodb.Client
}

func (s storage) save(ctx context.Context, item Item) error {
	itemAttrs, err := attributevalue.MarshalMapWithOptions(item, func(o *attributevalue.EncoderOptions) {
		o.TagKey = "json"
	})
	if err != nil {
		return fmt.Errorf("could not marshal item: %w", err)
	}

	_, err = s.db.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(item.TableName()),
		Item:      itemAttrs,
	})
	if err != nil {
		return fmt.Errorf("could not marshal item: %w", err)
	}

	return nil
}

func (s storage) fetch(ctx context.Context, id string, item Item) error {
	itemOutput, err := s.db.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(item.TableName()),
		Key: map[string]types.AttributeValue{
			"id": &types.AttributeValueMemberS{Value: id},
		},
	})
	if err != nil {
		return fmt.Errorf("could not get item: %w", err)
	}
	if itemOutput.Item == nil {
		return ErrNotFound
	}

	if err := attributevalue.UnmarshalMapWithOptions(itemOutput.Item, &item, func(o *attributevalue.DecoderOptions) {
		o.TagKey = "json"
	}); err != nil {
		return fmt.Errorf("could not unmarshal item: %w", err)
	}

	return nil
}

func (s storage) fetchAll(ctx context.Context, index, value string, items Items) error {
	in := &dynamodb.QueryInput{
		TableName:                 aws.String(items.TableName()),
		IndexName:                 aws.String(index + "-index"),
		KeyConditionExpression:    aws.String("#pk = :v"),
		ExpressionAttributeNames:  map[string]string{"#pk": index},
		ExpressionAttributeValues: map[string]types.AttributeValue{":v": &types.AttributeValueMemberS{Value: value}},
		Limit:                     aws.Int32(30),
		ScanIndexForward:          aws.Bool(false), // descending order.
	}

	res, err := s.db.Query(ctx, in)
	if err != nil {
		return fmt.Errorf("query %s/%s: %w", items.TableName(), index+"-index", err)
	}

	if err := attributevalue.UnmarshalListOfMapsWithOptions(res.Items, items, func(o *attributevalue.DecoderOptions) {
		o.TagKey = "json"
	}); err != nil {
		return fmt.Errorf("could not unmarshal items: %w", err)
	}

	return nil
}

func (s storage) delete(ctx context.Context, id string, item Item) error {
	_, err := s.db.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(item.TableName()),
		Key: map[string]types.AttributeValue{
			"id": &types.AttributeValueMemberS{Value: id},
		},
	})
	if err != nil {
		return fmt.Errorf("could not marshal item: %w", err)
	}

	return nil
}
