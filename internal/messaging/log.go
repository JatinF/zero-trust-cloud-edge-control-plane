// Package messaging is an in-process at-least-once log.
// It stands in for NATS JetStream. A broker was not started.
// Acknowledging a message does not make the application step exactly once.
package messaging

import (
	"sync"

	"github.com/JatinF/zero-trust-cloud-edge-control-plane/internal/apperr"
)

type Message struct {
	Seq        uint64
	EventID    string
	Type       string
	Body       string
	Deliveries int
	Acked      bool
}

type Log struct {
	mu       sync.Mutex
	down     bool
	seq      uint64
	messages []Message
	cursor   int
}

func New() *Log {
	return &Log{}
}

func (l *Log) SetDown(down bool) {
	l.mu.Lock()
	l.down = down
	l.mu.Unlock()
}

func (l *Log) Publish(eventID, kind, body string) (Message, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.down {
		return Message{}, apperr.New("dependency_unavailable", "event log is unavailable", 503)
	}
	l.seq++
	msg := Message{Seq: l.seq, EventID: eventID, Type: kind, Body: body}
	l.messages = append(l.messages, msg)
	return msg, nil
}

// Receive returns the next unacked message and counts a delivery.
// The same message is returned again until Ack.
func (l *Log) Receive() (Message, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.down {
		return Message{}, false
	}
	for l.cursor < len(l.messages) {
		msg := &l.messages[l.cursor]
		if msg.Acked {
			l.cursor++
			continue
		}
		msg.Deliveries++
		copy := *msg
		return copy, true
	}
	return Message{}, false
}

func (l *Log) Ack(seq uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i := range l.messages {
		if l.messages[i].Seq == seq {
			l.messages[i].Acked = true
			return
		}
	}
}

// Redeliver makes every unacked message readable again.
func (l *Log) Redeliver() {
	l.mu.Lock()
	l.cursor = 0
	l.mu.Unlock()
}

func (l *Log) Deliveries(eventID string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	total := 0
	for _, msg := range l.messages {
		if msg.EventID == eventID {
			total += msg.Deliveries
		}
	}
	return total
}
