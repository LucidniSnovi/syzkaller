// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mab"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/prog"
)

func (status *MABStatus) readMABStatus() rpctype.RPCMABStatus {
	fuzzerStatus := rpctype.RPCMABStatus{
		Round:        status.Round,
		Exp31Round:   status.Exp31Round,
		Reward:       status.Reward,
		CorpusReward: make(map[hash.Sig]mab.CorpusReward),
	}
	const batchSize = 100
	syncedCnt := 0
	synced := make([]int, batchSize)
	for pidx := range status.CorpusUpdate {
		// Avoid sending too much
		if syncedCnt >= batchSize {
			break
		}
		if pidx >= 0 && pidx < len(status.fuzzer.corpus) {
			p := status.fuzzer.corpus[pidx]
			sig := hash.Hash(p.Serialize())
			fuzzerStatus.CorpusReward[sig] = p.CorpusReward
			log.Logf(MABLogLevel, "MAB Corpus Sync Send %v: %+v\n", sig.String(), p.CorpusReward)
			synced[syncedCnt] = pidx
			syncedCnt++
		}
	}
	for i := 0; i < syncedCnt; i++ {
		spidx := synced[i]
		delete(status.CorpusUpdate, spidx)
	}
	log.Logf(MABLogLevel, "MAB Corpus Sync Pending: %v\n", len(status.CorpusUpdate))
	return fuzzerStatus
}

func (status *MABStatus) writeMABStatus(managerStatus rpctype.RPCMABStatus) {
	if status.Round < managerStatus.Round {
		status.Round = managerStatus.Round
		status.Exp31Round = managerStatus.Exp31Round
		status.BootstrapExp31()
		status.Reward = managerStatus.Reward
	}
	for sig, v := range managerStatus.CorpusReward {
		pidx := -1
		ok := false
		if pidx, ok = status.fuzzer.corpusHashes[sig]; ok && pidx >= 0 && pidx < len(status.fuzzer.corpus) {
			status.fuzzer.corpus[pidx].CorpusReward = v
			sig := hash.Hash(status.fuzzer.corpus[pidx].Serialize())
			log.Logf(MABLogLevel, "MAB Corpus Sync Receive %v: %+v\n", sig.String(), v)
		}
	}
}

func (status *MABStatus) readMABGenSync(ct *prog.ChoiceTable) rpctype.RPCMABGenSync {
	var syncData rpctype.RPCMABGenSync
	if ct == nil {
		//log.Logf(MABLogLevel, "MABStatus::readMABGenSync --- NO Choice Table\n")
		syncData = rpctype.RPCMABGenSync{
			EnabledCalls: make(map[int]float64),
			ChoiceTable:  make(map[int]map[int]float64),
		}
	} else {
		enabledCallsRewards, count, totalCov, totalTime, rewardTotal, rewardTotal2, _ := ct.MabEnabledCalls.Poll()
		choiceTableRewards, countCT, totalCovCT, totalTimeCT, rewardTotalCT, rewardTotal2CT := ct.MabChoiceTable.Poll()

		syncData = rpctype.RPCMABGenSync{
			EnabledCalls: enabledCallsRewards,
			ChoiceTable:  choiceTableRewards,

			Count:    count,
			Coverage: totalCov,
			Time:     totalTime,
			Reward:   rewardTotal,
			Reward2:  rewardTotal2,

			CountCT:    countCT,
			CoverageCT: totalCovCT,
			TimeCT:     totalTimeCT,
			RewardCT:   rewardTotalCT,
			Reward2CT:  rewardTotal2CT,
		}
	}

	return syncData
}

func (status *MABStatus) writeMABGenSync(ct *prog.ChoiceTable, managerStatus rpctype.RPCMABGenSync) {
	if ct != nil {
		ct.MabEnabledCalls.UpdateSyncData(managerStatus.EnabledCalls, managerStatus.Count, managerStatus.Coverage, managerStatus.Time,
			managerStatus.Reward, managerStatus.Reward2)
		ct.MabChoiceTable.UpdateSyncData(managerStatus.ChoiceTable, managerStatus.CountCT, managerStatus.CoverageCT, managerStatus.TimeCT,
			managerStatus.RewardCT, managerStatus.Reward2CT)
	} else {
		if len(managerStatus.EnabledCalls) > 0 {
			status.MABGenEnabledCalls = managerStatus.EnabledCalls
		}
		if len(managerStatus.ChoiceTable) > 0 {
			status.MABGenChoiceTable = managerStatus.ChoiceTable
		}
		if managerStatus.Count > 0 {
			status.MABGenCount = managerStatus.Count
			status.MABGenCoverage = managerStatus.Coverage
			status.MABGenTime = managerStatus.Time
			status.MABGenReward = managerStatus.Reward
			status.MABGenReward2 = managerStatus.Reward2
		}
		if len(managerStatus.CountCT) > 0 {
			status.MABGenCountCT = managerStatus.CountCT
			status.MABGenCoverageCT = managerStatus.CoverageCT
			status.MABGenTimeCT = managerStatus.TimeCT
			status.MABGenRewardCT = managerStatus.RewardCT
			status.MABGenReward2CT = managerStatus.Reward2CT
		}
	}
}
