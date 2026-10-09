package kafka

import (
	"context"
	"encoding/json"
	"time"

	kafkago "github.com/segmentio/kafka-go"
	"github.com/sirupsen/logrus"

	"github.com/bintalk/bintalk-clone/internal/config"
)

// Event is the envelope published for every domain event.
type Event struct {
	Type      string      `json:"type"`
	Data      interface{} `json:"data"`
	Timestamp time.Time   `json:"timestamp"`
}

// Producer publishes domain events to Kafka asynchronously, so a slow or
// unavailable broker never blocks API requests.
type Producer struct {
	writer *kafkago.Writer
}

// NewProducer creates a Kafka producer for the configured topic.
func NewProducer(cfg config.KafkaConfig) *Producer {
	writer := &kafkago.Writer{
		Addr:                   kafkago.TCP(cfg.Brokers...),
		Topic:                  cfg.Topic,
		Balancer:               &kafkago.Hash{},
		AllowAutoTopicCreation: true,
		Async:                  true,
		BatchTimeout:           50 * time.Millisecond,
		Completion: func(messages []kafkago.Message, err error) {
			if err != nil {
				logrus.Warnf("Failed to publish %d Kafka message(s): %v", len(messages), err)
			}
		},
	}
	return &Producer{writer: writer}
}

// Publish sends an event keyed by key (events with the same key keep their order).
func (p *Producer) Publish(ctx context.Context, eventType, key string, data interface{}) {
	payload, err := json.Marshal(Event{Type: eventType, Data: data, Timestamp: time.Now().UTC()})
	if err != nil {
		logrus.Warnf("Failed to encode Kafka event %s: %v", eventType, err)
		return
	}
	if err := p.writer.WriteMessages(ctx, kafkago.Message{Key: []byte(key), Value: payload}); err != nil {
		logrus.Warnf("Failed to queue Kafka event %s: %v", eventType, err)
	}
}

// Close flushes pending messages and closes the producer.
func (p *Producer) Close() error {
	return p.writer.Close()
}
