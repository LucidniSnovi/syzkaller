// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package mab

import (
	"math"
	"math/rand"
	"sort"
	"sync"

	"github.com/google/syzkaller/pkg/log"
)

const (
	MABLogLevel           = 4
	MABWeightThresholdMax = 1e10
	MABWeightThresholdMin = 1e-10
	MABExponentThreshold  = 23.0 // e^23 approximate to 1e10
	MABDefaultThetaValue  = 0.1
)

type Choice struct {
	Reward     float64 // Normalized Reward, adjusted to prevent overflow.
	Weight     float64 // Weight proportional to Reward. Subject to float64 overflow prevention.
	SumWeights float64 // Sum of weights up to current choice.
}

type MultiArmedBandit struct {
	mu      sync.RWMutex
	choices []Choice // choices.

	// Keep track of sumRewards (avgReward) to prevent weight overflowing.
	// If e^(avgReward) exceeds MABWeightThresholds, subtracts all rewards
	// by avgReward
	sumRewards   float64
	rewardAdjust float64

	theta float64 // Factor controlling gamma and eta.
	gamma float64 // Exploration factor.
	eta   float64 // Growth factor.
}

// Randomly chooses an "arm" in the choices array.
// Returns both the choice as well as the probability of making this choice.
func (mab *MultiArmedBandit) Choose(r *rand.Rand) (int, float64) {
	mab.mu.RLock()
	defer mab.mu.RUnlock()

	if len(mab.choices) == 0 {
		return -1, 0.0
	}
	sumWeights := mab.choices[len(mab.choices)-1].SumWeights
	randVal := r.Float64() * sumWeights
	idx := sort.Search(len(mab.choices), func(i int) bool {
		return mab.choices[i].SumWeights >= randVal
	})

	log.Logf(0, "-------------------------> Choose --- CHOICES:\n")
	for i := range mab.choices {
		log.Logf(0, "%v, ", mab.choices[i].SumWeights)
	}
	log.Logf(0, "\n")
	log.Logf(0, "-------------------------> Choose --- randVal: %v; sumWeights: %v; chosen SW: %v", randVal, sumWeights, mab.choices[idx].SumWeights)
	return idx, mab.choices[idx].Weight / sumWeights
}

func (mab *MultiArmedBandit) NewChoice() int {
	return mab.NewChoiceWithReward(0.0)
}

func (mab *MultiArmedBandit) adjustValues() {
	// Compute average reward and check whether we need to modify reward
	// for all choices.
	avgReward := mab.sumRewards / float64(len(mab.choices))
	if avgReward < -MABExponentThreshold || avgReward > MABExponentThreshold {
		log.Logf(MABLogLevel, "MAB average reward (%v) exceeds threshold (+-%v), adjusting",
			avgReward, MABExponentThreshold)

		log.Logf(MABLogLevel, "-------------------------> adjustValues\n")

		sumWeights := 0.0
		for i := 0; i < len(mab.choices); i++ {
			mab.choices[i].Reward -= avgReward
			mab.choices[i].Weight = math.Exp(mab.choices[i].Reward)
			sumWeights += mab.choices[i].Weight
			mab.choices[i].SumWeights = sumWeights
		}
		mab.sumRewards = 0.0
		mab.rewardAdjust += avgReward
	}
}

func (mab *MultiArmedBandit) updateWeight(idx int) {
	mab.adjustValues()

	// Update selection weight and prevent float64 overflow for individual
	// choice.
	weight := math.Exp(mab.choices[idx].Reward)
	if weight > MABWeightThresholdMax {
		weight = MABWeightThresholdMax
	}
	if weight < MABWeightThresholdMin {
		weight = MABWeightThresholdMin
	}
	mab.choices[idx].Weight = weight
	if idx == 0 {
		mab.choices[idx].SumWeights = mab.choices[idx].Weight
	} else {
		mab.choices[idx].SumWeights = mab.choices[idx-1].SumWeights + mab.choices[idx].Weight
	}
	// Only need to update choices with a higher index.
	for i := idx + 1; i < len(mab.choices); i++ {
		mab.choices[i].SumWeights = mab.choices[i-1].SumWeights + mab.choices[i].Weight
	}
}

func (mab *MultiArmedBandit) NewChoiceWithReward(initialReward float64) int {
	mab.mu.Lock()
	defer mab.mu.Unlock()

	newChoice := Choice{
		Reward:     initialReward - mab.rewardAdjust,
		Weight:     1.0,
		SumWeights: 1.0,
	}
	if len(mab.choices) > 0 {
		newChoice.SumWeights = mab.choices[len(mab.choices)-1].SumWeights + newChoice.Weight
	}
	mab.choices = append(mab.choices, newChoice)
	idx := len(mab.choices) - 1
	mab.sumRewards += newChoice.Reward
	mab.updateWeight(idx)

	// Need to update exploration and exploitation factors.
	K := float64(len(mab.choices))
	mab.eta = mab.theta * math.Sqrt(2.0*math.Log(K)/K)
	mab.gamma = mab.eta / 2.0
	//log.Logf(MABLogLevel, "MAB gamma = %v, eta = %v", mab.gamma, mab.eta)

	return idx
}

func (mab *MultiArmedBandit) NewChoiceWithWeight(initialWeight float64) int {
	mab.mu.Lock()
	defer mab.mu.Unlock()

	if initialWeight > MABWeightThresholdMax {
		initialWeight = MABWeightThresholdMax
	}
	if initialWeight < MABWeightThresholdMin {
		initialWeight = MABWeightThresholdMin
	}

	initialReward := math.Log(initialWeight)

	//log.Logf(0, "----------------------> NewChoiceWithWeight - %v,  %v", initialWeight, initialReward)

	newChoice := Choice{
		Reward:     initialReward,
		Weight:     initialWeight,
		SumWeights: initialWeight,
	}
	if len(mab.choices) > 0 {
		newChoice.SumWeights = mab.choices[len(mab.choices)-1].SumWeights + newChoice.Weight
	}
	mab.choices = append(mab.choices, newChoice)
	idx := len(mab.choices) - 1
	mab.sumRewards += newChoice.Reward

	mab.adjustValues()

	// Need to update exploration and exploitation factors.
	K := float64(len(mab.choices))
	mab.eta = mab.theta * math.Sqrt(2.0*math.Log(K)/K)
	mab.gamma = mab.eta / 2.0
	//log.Logf(MABLogLevel, "MAB gamma = %v, eta = %v", mab.gamma, mab.eta)

	return idx
}

func (mab *MultiArmedBandit) Update(idx int, reward, pr float64) {
	mab.mu.Lock()
	defer mab.mu.Unlock()

	if idx >= len(mab.choices) {
		log.Fatalf("MAB Update Error: Index %v out of bound %v", idx, len(mab.choices))
	}
	if pr == 0 {
		log.Fatalf("MAB Update Error: Probability is zero")
	}
	if reward > 1.0 || reward < -1.0 {
		log.Fatalf("MAB Update Error: Reward (%v) should have been normalized to [-1, 1]", reward)
	}
	// Update reward based on growth factor.
	rewardDiff := mab.eta * reward / (pr + mab.gamma)
	log.Logf(MABLogLevel, "MAB reward update: %v * %v / (%v + %v) = %v",
		mab.eta, reward, pr, mab.gamma, rewardDiff)
	mab.choices[idx].Reward += rewardDiff
	mab.sumRewards += rewardDiff
	mab.updateWeight(idx)
}

func (mab *MultiArmedBandit) UpdateSync(idx int, reward float64) {
	mab.mu.Lock()
	defer mab.mu.Unlock()

	if idx >= len(mab.choices) {
		log.Fatalf("MAB Update Error: Index %v out of bound %v", idx, len(mab.choices))
	}
	oldReward := mab.choices[idx].Reward
	mab.choices[idx].Reward = reward
	mab.sumRewards += reward - oldReward
	mab.updateWeight(idx)
}

func (mab *MultiArmedBandit) GetRawReward(idx int) float64 {
	mab.mu.Lock()
	defer mab.mu.Unlock()

	if idx < 0 || idx >= len(mab.choices) {
		return math.Inf(-1)
	}
	return mab.choices[idx].Reward + mab.rewardAdjust
}

func (mab *MultiArmedBandit) GetRewardAndWeight(idx int) (float64, float64) {
	mab.mu.Lock()
	defer mab.mu.Unlock()

	if idx < 0 || idx >= len(mab.choices) {
		return math.Inf(-1), math.Inf(-1)
	}
	return mab.choices[idx].Reward, mab.choices[idx].Weight
}

func (mab *MultiArmedBandit) GetChoiceAndProbability(idx int) (Choice, float64) {
	mab.mu.RLock()
	defer mab.mu.RUnlock()

	if len(mab.choices) == 0 {
		return Choice{
			Reward:     -1,
			Weight:     -1,
			SumWeights: -1,
		}, -1.0
	}

	sumWeights := mab.choices[len(mab.choices)-1].SumWeights
	return mab.choices[idx], mab.choices[idx].Weight / sumWeights
}
