// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package mab

import (
	"math"
	"math/rand"
	"sync"

	"github.com/google/syzkaller/pkg/log"
	//"github.com/google/syzkaller/prog"
)

// Threshold to filter out bad timing measurements.
const MABExecTimeThreshold = 1000000000

type Helper struct {
	mu  sync.RWMutex
	mab *MultiArmedBandit

	count        int     // Total number of mutations observed.
	totalCov     int     // Total coverage obtained by mutation.
	totalTime    float64 // Total time cost (ns) by mutation.
	rewardTotal  float64 // Sum of all un-normalized reward.
	rewardTotal2 float64 // Sum of squares of un-normalized reward.

	// The index in this array is the same as the index in the MAB engine.
	elementIDs []int
	IDtoIndex  map[int]int

	// Reward change since last Poll.
	rewardChange map[int]float64
	timeDiff     float64
	covDiff      int
}

func NewHelper(theta float64) *Helper {
	return &Helper{
		mab:          &MultiArmedBandit{theta: theta},
		rewardChange: make(map[int]float64),
		IDtoIndex:    make(map[int]int),
	}
}

func (mh *Helper) Choose(r *rand.Rand) (int, float64) {
	mh.mu.Lock()
	defer mh.mu.Unlock()

	idx, pr := mh.mab.Choose(r)
	log.Logf(MABLogLevel, "Helper::Choose - IDX:%v; ID:%v; PR:%v, REW:%v\n", idx, mh.elementIDs[idx], pr, mh.GetRawReward(idx))
	if idx < 0 {
		// No choices available in the MAB engine.
		return idx, 0.0
	}
	return mh.elementIDs[idx], pr
}

func (mh *Helper) HasElements() bool {
	mh.mu.Lock()
	defer mh.mu.Unlock()

	return len(mh.elementIDs) != 0
}

func (mh *Helper) NewChoice(elementID int) int {
	return mh.NewChoiceWithReward(elementID, 0.0)
}

func (mh *Helper) NewChoiceWithReward(elementID int, initialReward float64) int {
	mh.mu.Lock()
	defer mh.mu.Unlock()

	idx := mh.mab.NewChoiceWithReward(initialReward)
	mh.elementIDs = append(mh.elementIDs, elementID)
	mh.IDtoIndex[elementID] = idx
	return idx
}

func (mh *Helper) NewChoiceWithWeight(elementID int, initialWeight float64) int {
	mh.mu.Lock()
	defer mh.mu.Unlock()

	idx := mh.mab.NewChoiceWithWeight(initialWeight)
	mh.elementIDs = append(mh.elementIDs, elementID)
	mh.IDtoIndex[elementID] = idx
	return idx
}

func (mh *Helper) Update(idx int, result ExecResult, pr float64) {
	mh.mu.Lock()
	defer mh.mu.Unlock()

	// For executions with bad timing measurements, assume the worst time and
	// don't update totals
	updateTotal := true
	if result.TimeExec <= 0 || result.TimeExec > MABExecTimeThreshold {
		result.TimeExec = MABExecTimeThreshold
		updateTotal = false
	}

	// Convert coverage and time into a single reward metric.
	var reward float64
	if mh.totalCov != 0 {
		conversionRate := float64(mh.totalTime) / float64(mh.totalCov)
		reward = float64(result.Cov)*conversionRate - float64(result.TimeExec)
		log.Logf(MABLogLevel, "MAB SS Reward: %v * %v / %v - %v = %v",
			result.Cov, mh.totalTime,
			mh.totalCov, result.TimeExec,
			reward)
	}
	// Normalization.
	var normReward, mean, std float64
	if mh.count > 0 {
		mean = mh.rewardTotal / float64(mh.count)
		std = (mh.rewardTotal2 / float64(mh.count)) - (mean * mean)
	}
	if std < 0.0 {
		log.Fatalf("error: Cannot compute std sqrt(%v)", std)
	} else if std > 0.0 {
		std = math.Sqrt(std)
		// Normally, Z-score should be z = (reward - meanX) / stdX.
		// However, we want to make sure positive reward is positive.
		// In later stages of fuzzing, meanX is going to be negative.
		// We don't want an "arm" with negative reward be rewarded.
		z := reward / std
		// Prevent overflowing.
		if z > MABExponentThreshold {
			z = MABExponentThreshold
		} else if z < -MABExponentThreshold {
			z = -MABExponentThreshold
		}
		normReward = (1.0 - math.Exp(-z)) / (1.0 + math.Exp(-z))
		log.Logf(1, "MAB SS Normalized Reward: %v; z=%v mean=%v std=%v", normReward, z, mean, std)
	}
	if normReward != 0.0 {
		mh.mab.Update(idx, normReward, pr)
		// Record reward change.
		if _, ok := mh.rewardChange[idx]; !ok {
			mh.rewardChange[idx] = 0.0
		}
		mh.rewardChange[idx] += normReward
	}
	// Update total time/coverage after everything.
	if updateTotal {
		mh.totalTime += result.TimeExec
		mh.totalCov += result.Cov
		mh.timeDiff += result.TimeExec
		mh.covDiff += result.Cov
		mh.count++
		mh.rewardTotal += reward
		mh.rewardTotal2 += reward * reward
	}
}

func (mh *Helper) UpdateBatch(calls []SyscallProbability, result ExecResult) {
	mh.mu.Lock()
	defer mh.mu.Unlock()

	// For executions with bad timing measurements, assume the worst time and
	// don't update totals
	updateTotal := true
	if result.TimeExec <= 0 || result.TimeExec > MABExecTimeThreshold {
		result.TimeExec = MABExecTimeThreshold
		updateTotal = false
	}

	// Convert coverage and time into a single reward metric.
	var reward float64
	if mh.totalCov != 0 {
		conversionRate := mh.totalTime / float64(mh.totalCov)
		reward = float64(result.Cov)*conversionRate - result.TimeExec
		log.Logf(MABLogLevel, "MAB SS Reward: %v * %v / %v - %v = %v",
			result.Cov, mh.totalTime,
			mh.totalCov, result.TimeExec,
			reward)
	}
	// Normalization.
	var normReward, mean, std float64
	if mh.count > 0 {
		mean = mh.rewardTotal / float64(mh.count)
		std = (mh.rewardTotal2 / float64(mh.count)) - (mean * mean)
	}
	if std < 0.0 {
		log.Fatalf("error: Cannot compute std sqrt(%v)", std)
	} else if std > 0.0 {
		std = math.Sqrt(std)
		// Normally, Z-score should be z = (reward - meanX) / stdX.
		// However, we want to make sure positive reward is positive.
		// In later stages of fuzzing, meanX is going to be negative.
		// We don't want an "arm" with negative reward be rewarded.
		z := reward / std
		// Prevent overflowing.
		if z > MABExponentThreshold {
			z = MABExponentThreshold
		} else if z < -MABExponentThreshold {
			z = -MABExponentThreshold
		}
		normReward = (1.0 - math.Exp(-z)) / (1.0 + math.Exp(-z))
		log.Logf(1, "MAB SS Normalized Reward: %v; z=%v mean=%v std=%v", normReward, z, mean, std)
	}

	//Update all choices matching the call IDs
	if normReward != 0.0 {
		for i := range calls {
			if j, ok := mh.IDtoIndex[calls[i].SyscallID]; ok {
				mh.mab.Update(j, normReward, calls[i].Probability)
				// Record reward change.
				if _, ok := mh.rewardChange[j]; !ok {
					mh.rewardChange[j] = 0.0
				}
				mh.rewardChange[j] += normReward
			}
		}
	}
	// Update total time/coverage after everything.
	if updateTotal {
		mh.totalTime += result.TimeExec
		mh.totalCov += result.Cov
		mh.timeDiff += result.TimeExec
		mh.covDiff += result.Cov
		mh.count++
		mh.rewardTotal += reward
		mh.rewardTotal2 += reward * reward
	}
}

func (mh *Helper) Poll() (map[int]float64, float64, int) {
	mh.mu.Lock()
	defer mh.mu.Unlock()

	ret := make(map[int]float64)

	syncBatchSize := 100
	synced := make([]int, 0)

	for pidx, _ := range mh.rewardChange {
		//for pidx, diff := range mh.rewardChange {
		//ret[mh.elementIDs[pidx]] = diff
		ret[mh.elementIDs[pidx]], _ = mh.mab.GetRewardAndWeight(pidx)
		synced = append(synced, pidx)
		syncBatchSize--
		if syncBatchSize < 0 {
			break
		}
	}

	// Clear reward changes.
	log.Logf(MABLogLevel, "MAB sync %v / %v", len(synced), len(mh.rewardChange))
	for _, pidx := range synced {
		delete(mh.rewardChange, pidx)
	}

	timeDiff := mh.timeDiff
	covDiff := mh.covDiff
	mh.timeDiff = 0
	mh.covDiff = 0

	return ret, timeDiff, covDiff
}

func (mh *Helper) UpdateTotal(timeTotal float64, covTotal int) {
	mh.mu.Lock()
	defer mh.mu.Unlock()

	log.Logf(MABLogLevel, "MAB total time: %v -> %v, coverage: %v -> %v",
		mh.totalTime, timeTotal, mh.totalCov, covTotal)
	mh.totalTime = timeTotal
	mh.totalCov = covTotal
}

func (mh *Helper) GetRawReward(idx int) float64 {
	return mh.mab.GetRawReward(idx)
}

func (mh *Helper) DumpElements() {
	mh.mu.Lock()
	defer mh.mu.Unlock()

	for i, id := range mh.elementIDs {
		reward, weight := mh.mab.GetRewardAndWeight(i)
		log.Logf(0, "%v. ID = %v, Reward = %v, Weight = %v", i, id, reward, weight)
	}
}

func (mh *Helper) GetChoiceAndProbability(syscallID int) (Choice, float64) {
	mh.mu.Lock()
	defer mh.mu.Unlock()

	if j, ok := mh.IDtoIndex[syscallID]; ok {
		return mh.mab.GetChoiceAndProbability(j)
	}

	return Choice{
		Reward:     -1,
		Weight:     -1,
		SumWeights: -1,
	}, -1.0
}

func (mh *Helper) UpdateSyncData(calls map[int]float64, timeTotal float64, covTotal int) {
	mh.mu.Lock()
	defer mh.mu.Unlock()

	for ID, reward := range calls {
		if j, ok := mh.IDtoIndex[ID]; ok {
			mh.mab.UpdateSync(j, reward)
		}
	}

	//log.Logf(MABLogLevel, "MAB total time: %v -> %v, coverage: %v -> %v", mh.totalTime, timeTotal, mh.totalCov, covTotal)
	mh.totalTime = timeTotal
	mh.totalCov = covTotal
}
