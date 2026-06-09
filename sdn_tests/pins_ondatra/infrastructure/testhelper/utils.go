package testhelper

import (
	"context"
	"fmt"
	log "github.com/golang/glog"
	"time"
)

type pollStatus bool

const (
	continuePoll pollStatus = false
	exitPoll     pollStatus = true
)

// pollFunc returns true if the condition is met.
type pollFunc func() pollStatus

// poll polls the condition until it is met or the context is done.
func poll(ctx context.Context, pollInterval time.Duration, pf pollFunc) error {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("polling for condition timed out, err: %v", ctx.Err())
		case <-ticker.C:
			if pf() == exitPoll {
				log.InfoContextf(ctx, "polling done")
				return nil
			}
		}
	}
}
