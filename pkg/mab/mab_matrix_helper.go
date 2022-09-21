package mab

import (
	"github.com/google/syzkaller/pkg/log"
	"math/rand"
	"sync"
)

type MatrixHelper struct {
	mu         sync.RWMutex
	mabHelpers []*Helper
}

func NewMatrixHelper(runs [][]int32) *MatrixHelper {
	matrixHelper := &MatrixHelper{}
	for i := range runs {
		mabHelper := NewHelper(MABDefaultThetaValue)
		matrixHelper.mabHelpers = append(matrixHelper.mabHelpers, mabHelper)
		//If the syscall has no connection syscalls just leave helper empty
		if runs[i] != nil {
			var previousValue int32 = -1
			//We only add connected syscalls that have a weight
			//For example here we take the fourth and seventh (last one) : 0 0 0 900 900 900 1900
			//That is why we skip zeros and same values as the previous
			for j := range runs[i] {
				//log.Logf(MABLogLevel, "---------------------- [%v][%v] = %v ---------------------- \n", i, j, runs[i][j])
				if runs[i][j] != 0 {
					if runs[i][j] != previousValue {
						newValue := runs[i][j]
						//We subtract the previous value from weight, so we get 900 and 1000 in the mentioned example
						if previousValue != -1 {
							newValue -= previousValue
						}
						mabHelper.NewChoiceWithWeight(j, float64(newValue))
						previousValue = runs[i][j]
					}
				}
			}
		}
	}
	return matrixHelper
}

func (mh *MatrixHelper) DumpElements(count int) {
	mh.mu.Lock()
	defer mh.mu.Unlock()

	for i, mabHelper := range mh.mabHelpers {
		if mabHelper.HasElements() {
			log.Logf(0, "---------------------- %v. elements: ---------------------- \n", i)
			mabHelper.DumpElements()
		} else {
			log.Logf(0, "---------------------- %v. has no elements...\n", i)
		}

		if (count > 0) && (i == count) {
			break
		}
	}
}

func (mh *MatrixHelper) Choose(biasCall int, r *rand.Rand) (int, float64) {
	mh.mu.Lock()
	defer mh.mu.Unlock()

	if mh.mabHelpers[biasCall].HasElements() {
		log.Logf(MABLogLevel, "MatrixHelper::Choose --- biasCall = %v\n", biasCall)
		return mh.mabHelpers[biasCall].Choose(r)
	} else {
		return -1, 0.0
	}
}

func (mh *MatrixHelper) UpdateBatch(biasCalls []SyscallProbability, generatedCalls []SyscallProbability, result ExecResult) {
	mh.mu.Lock()
	defer mh.mu.Unlock()
	processedCalls := make(map[int]bool)

	for i := range biasCalls {
		currentBiasCall := biasCalls[i]
		if _, ok := processedCalls[currentBiasCall.SyscallID]; !ok {
			log.Logf(MABLogLevel, "MatrixHelper::UpdateBatch --- currentBiasCall = %v\n", currentBiasCall)
			processedCalls[currentBiasCall.SyscallID] = true
			var correspondingGeneratedCalls []SyscallProbability
			correspondingGeneratedCalls = append(correspondingGeneratedCalls, generatedCalls[i])
			for j := i + 1; j < len(biasCalls); j++ {
				if biasCalls[j].SyscallID == currentBiasCall.SyscallID {
					correspondingGeneratedCalls = append(correspondingGeneratedCalls, generatedCalls[j])
				}
			}
			mh.mabHelpers[currentBiasCall.SyscallID].UpdateBatch(correspondingGeneratedCalls, result)
		}
	}
}

func (mh *MatrixHelper) Poll() map[int]map[int]float64 {
	mh.mu.Lock()
	defer mh.mu.Unlock()

	ret := make(map[int]map[int]float64)

	for i, mabHelper := range mh.mabHelpers {
		tmp, _, _ := mabHelper.Poll()
		if len(tmp) > 0 {
			ret[i] = tmp
		}
	}

	return ret
}

func (mh *MatrixHelper) UpdateSyncData(matrix map[int]map[int]float64, timeTotal float64, covTotal int) {
	mh.mu.Lock()
	defer mh.mu.Unlock()

	for biasCall, generatedCalls := range matrix {
		if len(generatedCalls) > 0 {
			mh.mabHelpers[biasCall].UpdateSyncData(generatedCalls, timeTotal, covTotal)
		}
	}
}
