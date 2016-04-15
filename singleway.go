package main

import (
	"sync"
	"sync/atomic"
)

type callingState struct {
	mu     sync.Mutex
	cond   *sync.Cond
	sema   int32
	done   bool
	result interface{}
}

type singleWayCalling struct {
	mu    sync.Mutex
	paths map[string]*callingState
}

func newSingleWayCalling() *singleWayCalling {
	return &singleWayCalling{
		paths: make(map[string]*callingState),
	}
}

// Must catch exceptions inside the fn.
func (c *singleWayCalling) call(key string, fn func() interface{}) (interface{}, bool) {
	var state *callingState
	c.mu.Lock()
	state = c.paths[key]
	if state == nil {
		state = new(callingState)
		state.cond = sync.NewCond(&state.mu)
		c.paths[key] = state
	}
	c.mu.Unlock()
	var result interface{}
	var original bool
	// enter
	if atomic.AddInt32(&state.sema, 1) == 1 { // first
		original = true
		result = fn()
		// finished executing
		state.mu.Lock()
		state.result = result
		state.done = true
		state.cond.Broadcast()
		state.mu.Unlock()
	} else { // others
		state.mu.Lock()
		for !state.done {
			state.cond.Wait()
		}
		result = state.result
		state.mu.Unlock()
	}
	// leave
	if atomic.AddInt32(&state.sema, -1) == 0 {
		// clean resource
		c.mu.Lock()
		delete(c.paths, key)
		c.mu.Unlock()
	}
	return result, original
}
