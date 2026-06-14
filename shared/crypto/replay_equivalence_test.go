package crypto

import (
	"math/rand"
	"testing"
)

// legacyReplayState is the original shift-based anti-replay window, kept here
// verbatim as the reference oracle. The optimized circular window in
// udpdata.go must make identical accept/reject decisions for every counter.
type legacyReplayState struct {
	highest uint64
	bits    [replayWindowWords]uint64
}

func (w *legacyReplayState) accept(ctr uint64) bool {
	if ctr == 0 {
		return false
	}
	if ctr > w.highest {
		w.shift(ctr - w.highest)
		w.highest = ctr
		w.bits[0] |= 1
		return true
	}
	off := w.highest - ctr
	if off >= replayWindowBits {
		return false
	}
	word, bit := off/64, off%64
	mask := uint64(1) << bit
	if w.bits[word]&mask != 0 {
		return false
	}
	w.bits[word] |= mask
	return true
}

func (w *legacyReplayState) shift(s uint64) {
	if s >= replayWindowBits {
		for i := range w.bits {
			w.bits[i] = 0
		}
		return
	}
	wordShift := int(s / 64)
	bitShift := uint(s % 64)
	for i := replayWindowWords - 1; i >= 0; i-- {
		var v uint64
		if src := i - wordShift; src >= 0 {
			v = w.bits[src] << bitShift
			if bitShift > 0 && src-1 >= 0 {
				v |= w.bits[src-1] >> (64 - bitShift)
			}
		}
		w.bits[i] = v
	}
}

// TestReplayWindowMatchesLegacy proves the optimized window is behaviorally
// identical to the original across many randomized sequences that stress every
// branch: in-order, small/large forward gaps (including window-clearing jumps),
// in-window reorders, replays of seen counters, and too-old counters.
func TestReplayWindowMatchesLegacy(t *testing.T) {
	const seeds = 200
	const stepsPerSeed = 20000
	for seed := int64(0); seed < seeds; seed++ {
		rng := rand.New(rand.NewSource(seed))
		var got replayState
		var want legacyReplayState
		var highest uint64
		seen := make([]uint64, 0, 64)

		for step := 0; step < stepsPerSeed; step++ {
			var ctr uint64
			switch n := rng.Intn(100); {
			case n < 50: // in-order
				ctr = highest + 1
			case n < 65: // small forward gap
				ctr = highest + uint64(1+rng.Intn(100))
			case n < 75: // large forward jump (may clear the whole window)
				ctr = highest + uint64(1+rng.Intn(3000))
			case n < 90 && highest > 0: // in-window reorder / too-old boundary
				back := uint64(rng.Intn(int(replayWindowBits) + 200))
				if back <= highest {
					ctr = highest - back
				} else {
					ctr = 1
				}
			case n < 97 && len(seen) > 0: // explicit replay of a seen counter
				ctr = seen[rng.Intn(len(seen))]
			default: // edge values
				ctr = uint64(rng.Intn(2)) // 0 or 1
			}

			g := got.accept(ctr)
			w := want.accept(ctr)
			if g != w {
				t.Fatalf("seed=%d step=%d ctr=%d highest=%d: optimized=%v legacy=%v",
					seed, step, ctr, highest, g, w)
			}
			if w {
				if ctr > highest {
					highest = ctr
				}
				if len(seen) < cap(seen) {
					seen = append(seen, ctr)
				} else {
					seen[rng.Intn(len(seen))] = ctr
				}
			}
		}
	}
}

// TestReplayWindowBoundariesMatchLegacy checks the exact window edges, where
// off-by-one mistakes hide: highest, highest-(W-1) (oldest in-window), and
// highest-W (first too-old).
func TestReplayWindowBoundariesMatchLegacy(t *testing.T) {
	bases := []uint64{1, 64, 1023, 1024, 1025, 5000, 1 << 20}
	for _, base := range bases {
		var got replayState
		var want legacyReplayState
		// Seed both to the same highest.
		if got.accept(base) != want.accept(base) {
			t.Fatalf("base=%d seed mismatch", base)
		}
		for _, off := range []uint64{0, 1, 2, replayWindowBits - 1, replayWindowBits, replayWindowBits + 1} {
			if off > base {
				continue
			}
			ctr := base - off
			g := got.accept(ctr)
			w := want.accept(ctr)
			if g != w {
				t.Fatalf("base=%d off=%d ctr=%d: optimized=%v legacy=%v", base, off, ctr, g, w)
			}
		}
	}
}
