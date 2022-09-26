// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mab"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
)

type RPCServer struct {
	mgr                   RPCManagerView
	cfg                   *mgrconfig.Config
	modules               []host.KernelModule
	port                  int
	targetEnabledSyscalls map[*prog.Syscall]bool
	coverFilter           map[uint32]uint32
	stats                 *Stats
	batchSize             int

	mu            sync.Mutex
	fuzzers       map[string]*Fuzzer
	checkResult   *rpctype.CheckArgs
	maxSignal     signal.Signal
	corpusSignal  signal.Signal
	corpusCover   cover.Cover
	rotator       *prog.Rotator
	rnd           *rand.Rand
	checkFailures int

	// For now we assume a single-fuzzer model
	MABRound        int
	MABExp31Round   int
	MABReward       mab.TotalReward
	MABCorpusReward map[hash.Sig]mab.CorpusReward

	MABEnabledCalls map[int]float64
	MABChoiceTable  map[int]map[int]float64

	MABGenCount    int
	MABGenCoverage int
	MABGenTime     float64
	MABGenReward   float64
	MABGenReward2  float64

	MABGenCountCT    map[int]int
	MABGenCoverageCT map[int]int
	MABGenTimeCT     map[int]float64
	MABGenRewardCT   map[int]float64
	MABGenReward2CT  map[int]float64
}

type Fuzzer struct {
	name          string
	rotated       bool
	inputs        []rpctype.Input
	newMaxSignal  signal.Signal
	rotatedSignal signal.Signal
	machineInfo   []byte

	MABEnabledCallsRewards map[int]float64
	MABChoiceTableRewards  map[int]map[int]float64

	MABGenCount    int
	MABGenCoverage int
	MABGenTime     float64
	MABGenReward   float64
	MABGenReward2  float64

	MABGenCountCT    map[int]int
	MABGenCoverageCT map[int]int
	MABGenTimeCT     map[int]float64
	MABGenRewardCT   map[int]float64
	MABGenReward2CT  map[int]float64
}

type BugFrames struct {
	memoryLeaks []string
	dataRaces   []string
}

// RPCManagerView restricts interface between RPCServer and Manager.
type RPCManagerView interface {
	fuzzerConnect([]host.KernelModule) (
		[]rpctype.Input, BugFrames, map[uint32]uint32, []byte, error)
	machineChecked(result *rpctype.CheckArgs, enabledSyscalls map[*prog.Syscall]bool)
	newInput(inp rpctype.Input, sign signal.Signal) bool
	candidateBatch(size int) []rpctype.Candidate
	rotateCorpus() bool
}

func startRPCServer(mgr *Manager) (*RPCServer, error) {
	serv := &RPCServer{
		mgr:             mgr,
		cfg:             mgr.cfg,
		stats:           mgr.stats,
		fuzzers:         make(map[string]*Fuzzer),
		rnd:             rand.New(rand.NewSource(time.Now().UnixNano())),
		MABRound:        0,
		MABExp31Round:   0,
		MABCorpusReward: make(map[hash.Sig]mab.CorpusReward),
	}
	if mgr.cfg.MABGEN {
		serv.MABEnabledCalls = make(map[int]float64)
		serv.MABChoiceTable = make(map[int]map[int]float64)

		serv.MABGenCountCT = make(map[int]int)
		serv.MABGenCoverageCT = make(map[int]int)
		serv.MABGenTimeCT = make(map[int]float64)
		serv.MABGenRewardCT = make(map[int]float64)
		serv.MABGenReward2CT = make(map[int]float64)
	}
	serv.batchSize = 5
	if serv.batchSize < mgr.cfg.Procs {
		serv.batchSize = mgr.cfg.Procs
	}
	s, err := rpctype.NewRPCServer(mgr.cfg.RPC, "Manager", serv)
	if err != nil {
		return nil, err
	}
	log.Logf(0, "serving rpc on tcp://%v", s.Addr())
	serv.port = s.Addr().(*net.TCPAddr).Port
	go s.Serve()
	return serv, nil
}

func (serv *RPCServer) Connect(a *rpctype.ConnectArgs, r *rpctype.ConnectRes) error {
	log.Logf(1, "fuzzer %v connected", a.Name)
	serv.stats.vmRestarts.inc()

	corpus, bugFrames, coverFilter, coverBitmap, err := serv.mgr.fuzzerConnect(a.Modules)
	if err != nil {
		return err
	}
	serv.coverFilter = coverFilter
	serv.modules = a.Modules

	serv.mu.Lock()
	defer serv.mu.Unlock()

	f := &Fuzzer{
		name:        a.Name,
		machineInfo: a.MachineInfo,
	}
	serv.fuzzers[a.Name] = f
	r.MemoryLeakFrames = bugFrames.memoryLeaks
	r.DataRaceFrames = bugFrames.dataRaces
	r.CoverFilterBitmap = coverBitmap
	r.EnabledCalls = serv.cfg.Syscalls
	r.GitRevision = prog.GitRevision
	r.TargetRevision = serv.cfg.Target.Revision
	if serv.mgr.rotateCorpus() && serv.rnd.Intn(5) == 0 {
		// We do rotation every other time because there are no objective
		// proofs regarding its efficiency either way.
		// Also, rotation gives significantly skewed syscall selection
		// (run prog.TestRotationCoverage), it may or may not be OK.
		r.CheckResult = serv.rotateCorpus(f, corpus)
	} else {
		r.CheckResult = serv.checkResult
		f.inputs = corpus
		f.newMaxSignal = serv.maxSignal.Copy()
	}
	if serv.cfg.MABGEN {
		f.MABEnabledCallsRewards = make(map[int]float64)
		f.MABChoiceTableRewards = make(map[int]map[int]float64)

		f.MABGenCountCT = make(map[int]int)
		f.MABGenCoverageCT = make(map[int]int)
		f.MABGenTimeCT = make(map[int]float64)
		f.MABGenRewardCT = make(map[int]float64)
		f.MABGenReward2CT = make(map[int]float64)
	}
	return nil
}

func (serv *RPCServer) rotateCorpus(f *Fuzzer, corpus []rpctype.Input) *rpctype.CheckArgs {
	// Fuzzing tends to stuck in some local optimum and then it fails to cover
	// other state space points since code coverage is only a very approximate
	// measure of logic coverage. To overcome this we introduce some variation
	// into the process which should cause steady corpus rotation over time
	// (the same coverage is achieved in different ways).
	//
	// First, we select a subset of all syscalls for each VM run (result.EnabledCalls).
	// This serves 2 goals: (1) target fuzzer at a particular area of state space,
	// (2) disable syscalls that cause frequent crashes at least in some runs
	// to allow it to do actual fuzzing.
	//
	// Then, we remove programs that contain disabled syscalls from corpus
	// that will be sent to the VM (f.inputs). We also remove 10% of remaining
	// programs at random to allow to rediscover different variations of these programs.
	//
	// Then, we drop signal provided by the removed programs and also 10%
	// of the remaining signal at random (f.newMaxSignal). This again allows
	// rediscovery of this signal by different programs.
	//
	// Finally, we adjust criteria for accepting new programs from this VM (f.rotatedSignal).
	// This allows to accept rediscovered varied programs even if they don't
	// increase overall coverage. As the result we have multiple programs
	// providing the same duplicate coverage, these are removed during periodic
	// corpus minimization process. The minimization process is specifically
	// non-deterministic to allow the corpus rotation.
	//
	// Note: at no point we drop anything globally and permanently.
	// Everything we remove during this process is temporal and specific to a single VM.
	calls := serv.rotator.Select()

	var callIDs []int
	callNames := make(map[string]bool)
	for call := range calls {
		callNames[call.Name] = true
		callIDs = append(callIDs, call.ID)
	}

	f.inputs, f.newMaxSignal = serv.selectInputs(callNames, corpus, serv.maxSignal)
	// Remove the corresponding signal from rotatedSignal which will
	// be used to accept new inputs from this manager.
	f.rotatedSignal = serv.corpusSignal.Intersection(f.newMaxSignal)
	f.rotated = true

	result := *serv.checkResult
	result.EnabledCalls = map[string][]int{serv.cfg.Sandbox: callIDs}
	return &result
}

func (serv *RPCServer) selectInputs(enabled map[string]bool, inputs0 []rpctype.Input, signal0 signal.Signal) (
	inputs []rpctype.Input, signal signal.Signal) {
	signal = signal0.Copy()
	for _, inp := range inputs0 {
		calls, _, err := prog.CallSet(inp.Prog)
		if err != nil {
			panic(fmt.Sprintf("rotateInputs: CallSet failed: %v\n%s", err, inp.Prog))
		}
		for call := range calls {
			if !enabled[call] {
				goto drop
			}
		}
		if serv.rnd.Float64() > 0.9 {
			goto drop
		}
		inputs = append(inputs, inp)
		continue
	drop:
		for _, sig := range inp.Signal.Elems {
			delete(signal, sig)
		}
	}
	signal.Split(len(signal) / 10)
	return inputs, signal
}

func (serv *RPCServer) Check(a *rpctype.CheckArgs, r *int) error {
	serv.mu.Lock()
	defer serv.mu.Unlock()

	if serv.checkResult != nil {
		return nil // another VM has already made the check
	}
	// Note: need to print disbled syscalls before failing due to an error.
	// This helps to debug "all system calls are disabled".
	if len(serv.cfg.EnabledSyscalls) != 0 && len(a.DisabledCalls[serv.cfg.Sandbox]) != 0 {
		disabled := make(map[string]string)
		for _, dc := range a.DisabledCalls[serv.cfg.Sandbox] {
			disabled[serv.cfg.Target.Syscalls[dc.ID].Name] = dc.Reason
		}
		for _, id := range serv.cfg.Syscalls {
			name := serv.cfg.Target.Syscalls[id].Name
			if reason := disabled[name]; reason != "" {
				log.Logf(0, "disabling %v: %v", name, reason)
			}
		}
	}
	if a.Error != "" {
		log.Logf(0, "machine check failed: %v", a.Error)
		serv.checkFailures++
		if serv.checkFailures == 10 {
			log.Fatalf("machine check failing")
		}
		return fmt.Errorf("machine check failed: %v", a.Error)
	}
	serv.targetEnabledSyscalls = make(map[*prog.Syscall]bool)
	for _, call := range a.EnabledCalls[serv.cfg.Sandbox] {
		serv.targetEnabledSyscalls[serv.cfg.Target.Syscalls[call]] = true
	}
	log.Logf(0, "machine check:")
	log.Logf(0, "%-24v: %v/%v", "syscalls", len(serv.targetEnabledSyscalls), len(serv.cfg.Target.Syscalls))
	for _, feat := range a.Features.Supported() {
		log.Logf(0, "%-24v: %v", feat.Name, feat.Reason)
	}
	serv.mgr.machineChecked(a, serv.targetEnabledSyscalls)
	a.DisabledCalls = nil
	serv.checkResult = a
	serv.rotator = prog.MakeRotator(serv.cfg.Target, serv.targetEnabledSyscalls, serv.rnd)
	return nil
}

func (serv *RPCServer) NewInput(a *rpctype.NewInputArgs, r *int) error {
	inputSignal := a.Signal.Deserialize()
	log.Logf(4, "new input from %v for syscall %v (signal=%v, cover=%v)",
		a.Name, a.Call, inputSignal.Len(), len(a.Cover))
	bad, disabled := checkProgram(serv.cfg.Target, serv.targetEnabledSyscalls, a.Input.Prog)
	if bad || disabled {
		log.Logf(0, "rejecting program from fuzzer (bad=%v, disabled=%v):\n%s", bad, disabled, a.Input.Prog)
		return nil
	}
	serv.mu.Lock()
	defer serv.mu.Unlock()

	f := serv.fuzzers[a.Name]
	// Note: f may be nil if we called shutdownInstance,
	// but this request is already in-flight.
	genuine := !serv.corpusSignal.Diff(inputSignal).Empty()
	rotated := false
	if !genuine && f != nil && f.rotated {
		rotated = !f.rotatedSignal.Diff(inputSignal).Empty()
	}
	if !genuine && !rotated {
		return nil
	}
	if !serv.mgr.newInput(a.Input, inputSignal) {
		return nil
	}

	// Update reward
	sig := hash.Hash(a.Input.Prog)
	serv.MABCorpusReward[sig] = a.Input.Reward

	if f != nil && f.rotated {
		f.rotatedSignal.Merge(inputSignal)
	}
	diff := serv.corpusCover.MergeDiff(a.Cover)
	serv.stats.corpusCover.set(len(serv.corpusCover))
	if len(diff) != 0 && serv.coverFilter != nil {
		// Note: ReportGenerator is already initialized if coverFilter is enabled.
		rg, err := getReportGenerator(serv.cfg, serv.modules)
		if err != nil {
			return err
		}
		filtered := 0
		for _, pc := range diff {
			if serv.coverFilter[uint32(rg.RestorePC(pc))] != 0 {
				filtered++
			}
		}
		serv.stats.corpusCoverFiltered.add(filtered)
	}
	serv.stats.newInputs.inc()
	if rotated {
		serv.stats.rotatedInputs.inc()
	}

	if genuine {
		serv.corpusSignal.Merge(inputSignal)
		serv.stats.corpusSignal.set(serv.corpusSignal.Len())

		a.Input.Cover = nil // Don't send coverage back to all fuzzers.
		a.Input.RawCover = nil
		for _, other := range serv.fuzzers {
			if other == f || other.rotated {
				continue
			}
			other.inputs = append(other.inputs, a.Input)
		}
	}
	return nil
}

func (serv *RPCServer) Poll(a *rpctype.PollArgs, r *rpctype.PollRes) error {
	serv.stats.mergeNamed(a.Stats)

	serv.mu.Lock()
	defer serv.mu.Unlock()

	f := serv.fuzzers[a.Name]
	if f == nil {
		// This is possible if we called shutdownInstance,
		// but already have a pending request from this instance in-flight.
		log.Logf(1, "poll: fuzzer %v is not connected", a.Name)
		return nil
	}
	newMaxSignal := serv.maxSignal.Diff(a.MaxSignal.Deserialize())
	if !newMaxSignal.Empty() {
		serv.maxSignal.Merge(newMaxSignal)
		serv.stats.maxSignal.set(len(serv.maxSignal))
		for _, f1 := range serv.fuzzers {
			if f1 == f || f1.rotated {
				continue
			}
			f1.newMaxSignal.Merge(newMaxSignal)
		}
	}
	if f.rotated {
		// Let rotated VMs run in isolation, don't send them anything.
		return nil
	}
	r.MaxSignal = f.newMaxSignal.Split(2000).Serialize()
	if a.NeedCandidates {
		r.Candidates = serv.mgr.candidateBatch(serv.batchSize)
	}
	if len(r.Candidates) == 0 {
		batchSize := serv.batchSize
		// When the fuzzer starts, it pumps the whole corpus.
		// If we do it using the final batchSize, it can be very slow
		// (batch of size 6 can take more than 10 mins for 50K corpus and slow kernel).
		// So use a larger batch initially (we use no stats as approximation of initial pump).
		const initialBatch = 50
		if len(a.Stats) == 0 && batchSize < initialBatch {
			batchSize = initialBatch
		}
		for i := 0; i < batchSize && len(f.inputs) > 0; i++ {
			last := len(f.inputs) - 1
			r.NewInputs = append(r.NewInputs, f.inputs[last])

			// Send MAB status as well
			sig := hash.Hash(f.inputs[last].Prog)
			if r.CorpusReward == nil {
				r.CorpusReward = make(map[hash.Sig]mab.CorpusReward)
			}
			if v, ok := serv.MABCorpusReward[sig]; ok {
				r.CorpusReward[sig] = v
				r.NewInputs[len(r.NewInputs)-1].Reward = v
			}

			f.inputs[last] = rpctype.Input{}
			f.inputs = f.inputs[:last]
		}
		if len(f.inputs) == 0 {
			f.inputs = nil
		}
	}
	// Sync MAB status
	serv.SyncMABStatus(&a.RPCMABStatus, &r.RPCMABStatus)
	log.Logf(4, "poll from %v: candidates=%v inputs=%v maxsignal=%v",
		a.Name, len(r.Candidates), len(r.NewInputs), len(r.MaxSignal.Elems))

	if serv.cfg.MABGEN {
		serv.SyncMABGenStatus(f, &a.RPCMABGenSync, &r.RPCMABGenSync)
	}

	return nil
}

func (serv *RPCServer) shutdownInstance(name string) []byte {
	serv.mu.Lock()
	defer serv.mu.Unlock()

	fuzzer := serv.fuzzers[name]
	if fuzzer == nil {
		return nil
	}
	delete(serv.fuzzers, name)
	return fuzzer.machineInfo
}

func (serv *RPCServer) SyncMABStatus(a *rpctype.RPCMABStatus, r *rpctype.RPCMABStatus) error {
	if a.Round > serv.MABRound {
		serv.MABRound = a.Round
		serv.MABExp31Round = a.Exp31Round
		serv.MABReward = a.Reward
		for sig, v := range a.CorpusReward {
			serv.MABCorpusReward[sig] = v
			log.Logf(4, "MAB Corpus Sync %v: %+v\n", sig.String(), v)
		}
	} else if a.Round < serv.MABRound {
		r.Round = serv.MABRound
		r.Exp31Round = serv.MABExp31Round
		r.Reward = serv.MABReward
		r.CorpusReward = make(map[hash.Sig]mab.CorpusReward)
		for sig, v := range serv.MABCorpusReward {
			r.CorpusReward[sig] = v
		}
	}
	return nil
}

func (serv *RPCServer) SyncMABGenStatus(fuzzer *Fuzzer, a *rpctype.RPCMABGenSync, r *rpctype.RPCMABGenSync) error {
	log.Logf(4, "RPCServer::SyncMABGenStatus --- a.EnabledCalls = %v\n", a.EnabledCalls)
	log.Logf(4, "RPCServer::SyncMABGenStatus --- a.ChoiceTable = %v\n", a.ChoiceTable)
	log.Logf(4, "RPCServer::SyncMABGenStatus --- a.Count : %v; a.Coverage : %v; a.Time : %v; a.Reward : %v; a.Reward2 : %v\n", a.Count, a.Coverage, a.Time, a.Reward, a.Reward2)
	log.Logf(4, "RPCServer::SyncMABGenStatus --- a.TimeCT = %v\n", a.TimeCT)
	log.Logf(4, "RPCServer::SyncMABGenStatus --- a.CoverageCT = %v\n", a.CoverageCT)

	//Process Enabled calls by setting the Fuzzer field and updating the Server field
	for ID, reward := range a.EnabledCalls {
		fuzzer.MABEnabledCallsRewards[ID] = reward

		var newReward float64
		var rewardsCount int
		for _, currentFuzzer := range serv.fuzzers {
			if _, ok := currentFuzzer.MABEnabledCallsRewards[ID]; ok {
				newReward += currentFuzzer.MABEnabledCallsRewards[ID]
				rewardsCount++
			}
		}
		newReward = newReward / float64(rewardsCount)
		serv.MABEnabledCalls[ID] = newReward
	}

	//Send all changed rewards for Enabled calls and save them for fuzzer
	for ID, serverReward := range serv.MABEnabledCalls {
		/*		if fuzzerReward, ok := fuzzer.MABEnabledCallsRewards[ID]; ok {
				log.Logf(4, "RPCServer::SyncMABGenStatus --- Fuzz reward = %v, Server reward = %v\n", fuzzerReward, serverReward)
			}*/

		if fuzzerReward, ok := fuzzer.MABEnabledCallsRewards[ID]; !ok || fuzzerReward != serverReward {
			if r.EnabledCalls == nil {
				r.EnabledCalls = make(map[int]float64)
			}
			r.EnabledCalls[ID] = serverReward
			fuzzer.MABEnabledCallsRewards[ID] = serverReward
		}
	}
	log.Logf(4, "RPCServer::SyncMABGenStatus --- r.EnabledCalls : %v\n", r.EnabledCalls)

	//Process Enabled calls coverage and time by setting the Fuzzer field and updating the Server field
	if len(a.EnabledCalls) > 0 {
		fuzzer.MABGenCount = a.Count
		fuzzer.MABGenCoverage = a.Coverage
		fuzzer.MABGenTime = a.Time
		fuzzer.MABGenReward = a.Reward
		fuzzer.MABGenReward2 = a.Reward2

		var newCount int
		var newCov int
		var newTime float64
		var newRew float64
		var newRew2 float64
		var fuzzerCount int
		for _, currentFuzzer := range serv.fuzzers {
			newCount += currentFuzzer.MABGenCount
			newCov += currentFuzzer.MABGenCoverage
			newTime += currentFuzzer.MABGenTime
			newRew += currentFuzzer.MABGenReward
			newRew2 += currentFuzzer.MABGenReward2
			fuzzerCount++
		}
		newCount = newCount / fuzzerCount
		newCov = newCov / fuzzerCount
		newTime = newTime / float64(fuzzerCount)
		newRew = newRew / float64(fuzzerCount)
		newRew2 = newRew2 / float64(fuzzerCount)

		serv.MABGenCount = newCount
		serv.MABGenCoverage = newCov
		serv.MABGenTime = newTime
		serv.MABGenReward = newRew
		serv.MABGenReward2 = newRew2
	}
	log.Logf(4, "RPCServer::SyncMABGenStatus --- serv.MABGenCoverage : %v; serv.MABGenTime : %v\n", serv.MABGenCoverage, serv.MABGenTime)

	//Send changed coverage and time for Enabled calls and save them for fuzzer
	r.Count = serv.MABGenCount
	r.Coverage = serv.MABGenCoverage
	r.Time = serv.MABGenTime
	r.Reward = serv.MABGenReward
	r.Reward2 = serv.MABGenReward2

	fuzzer.MABGenCount = serv.MABGenCount
	fuzzer.MABGenCoverage = serv.MABGenCoverage
	fuzzer.MABGenTime = serv.MABGenTime
	fuzzer.MABGenReward = serv.MABGenReward
	fuzzer.MABGenReward2 = serv.MABGenReward2
	log.Logf(4, "RPCServer::SyncMABGenStatus --- r.Count : %v; r.Coverage : %v; r.Time : %v; r.Reward : %v; r.Reward2 : %v\n", r.Count, r.Coverage, r.Time, r.Reward, r.Reward2)

	//Process Choice Table, coverage and time by setting the Fuzzer field and updating the Server field
	for biasCall, generatedCalls := range a.ChoiceTable {
		for ID, reward := range generatedCalls {
			if fuzzer.MABChoiceTableRewards[biasCall] == nil {
				fuzzer.MABChoiceTableRewards[biasCall] = make(map[int]float64)
			}
			fuzzer.MABChoiceTableRewards[biasCall][ID] = reward

			var newReward float64
			var rewardsCount int
			for _, currentFuzzer := range serv.fuzzers {
				if _, ok := currentFuzzer.MABChoiceTableRewards[biasCall][ID]; ok {
					newReward += currentFuzzer.MABChoiceTableRewards[biasCall][ID]
					rewardsCount++
				}
			}
			newReward = newReward / float64(rewardsCount)
			if serv.MABChoiceTable[biasCall] == nil {
				serv.MABChoiceTable[biasCall] = make(map[int]float64)
			}
			serv.MABChoiceTable[biasCall][ID] = newReward
		}

		//Coverage and time
		fuzzer.MABGenCountCT[biasCall] = a.CountCT[biasCall]
		fuzzer.MABGenCoverageCT[biasCall] = a.CoverageCT[biasCall]
		fuzzer.MABGenTimeCT[biasCall] = a.TimeCT[biasCall]
		fuzzer.MABGenRewardCT[biasCall] = a.RewardCT[biasCall]
		fuzzer.MABGenReward2CT[biasCall] = a.Reward2CT[biasCall]

		var newCount int
		var newCov int
		var newTime float64
		var newRew float64
		var newRew2 float64
		var fuzzerCount int
		for _, currentFuzzer := range serv.fuzzers {
			if _, ok := currentFuzzer.MABGenCountCT[biasCall]; ok {
				newCount += currentFuzzer.MABGenCountCT[biasCall]
				newCov += currentFuzzer.MABGenCoverageCT[biasCall]
				newTime += currentFuzzer.MABGenTimeCT[biasCall]
				newRew += currentFuzzer.MABGenRewardCT[biasCall]
				newRew2 += currentFuzzer.MABGenReward2CT[biasCall]
				fuzzerCount++
			}
		}
		newCount = newCount / fuzzerCount
		newCov = newCov / fuzzerCount
		newTime = newTime / float64(fuzzerCount)
		newRew = newRew / float64(fuzzerCount)
		newRew2 = newRew2 / float64(fuzzerCount)

		serv.MABGenCountCT[biasCall] = newCount
		serv.MABGenCoverageCT[biasCall] = newCov
		serv.MABGenTimeCT[biasCall] = newTime
		serv.MABGenRewardCT[biasCall] = newRew
		serv.MABGenReward2CT[biasCall] = newRew2
	}

	//Send all saved rewards, coverage and time for Choice Table and save them for Fuzzer
	for biasCall, generatedCalls := range serv.MABChoiceTable {
		if fuzzer.MABChoiceTableRewards[biasCall] == nil {
			fuzzer.MABChoiceTableRewards[biasCall] = make(map[int]float64)
		}
		for ID, serverReward := range generatedCalls {
			/*			if fuzzerReward, ok := fuzzer.MABChoiceTableRewards[biasCall][ID]; ok {
						log.Logf(4, "RPCServer::SyncMABGenStatus --- Fuzz reward = %v, Server reward = %v\n", fuzzerReward, serverReward)
					}*/

			if fuzzerReward, ok := fuzzer.MABChoiceTableRewards[biasCall][ID]; !ok || fuzzerReward != serverReward {
				if r.ChoiceTable == nil {
					r.ChoiceTable = make(map[int]map[int]float64)
				}
				if r.ChoiceTable[biasCall] == nil {
					r.ChoiceTable[biasCall] = make(map[int]float64)
				}
				r.ChoiceTable[biasCall][ID] = serverReward
				fuzzer.MABChoiceTableRewards[biasCall][ID] = serverReward
			}
		}
		if fuzzer.MABGenCoverageCT[biasCall] != serv.MABGenCoverageCT[biasCall] {
			if r.CountCT == nil {
				r.CountCT = make(map[int]int)
			}
			if r.CoverageCT == nil {
				r.CoverageCT = make(map[int]int)
			}
			if r.TimeCT == nil {
				r.TimeCT = make(map[int]float64)
			}
			if r.RewardCT == nil {
				r.RewardCT = make(map[int]float64)
			}
			if r.Reward2CT == nil {
				r.Reward2CT = make(map[int]float64)
			}
			r.CountCT[biasCall] = serv.MABGenCountCT[biasCall]
			r.CoverageCT[biasCall] = serv.MABGenCoverageCT[biasCall]
			r.TimeCT[biasCall] = serv.MABGenTimeCT[biasCall]
			r.RewardCT[biasCall] = serv.MABGenRewardCT[biasCall]
			r.Reward2CT[biasCall] = serv.MABGenReward2CT[biasCall]

			fuzzer.MABGenCountCT[biasCall] = serv.MABGenCountCT[biasCall]
			fuzzer.MABGenCoverageCT[biasCall] = serv.MABGenCoverageCT[biasCall]
			fuzzer.MABGenTimeCT[biasCall] = serv.MABGenTimeCT[biasCall]
			fuzzer.MABGenRewardCT[biasCall] = serv.MABGenRewardCT[biasCall]
			fuzzer.MABGenReward2CT[biasCall] = serv.MABGenReward2CT[biasCall]
		}
	}
	log.Logf(4, "RPCServer::SyncMABGenStatus --- r.ChoiceTable : %v\n", r.ChoiceTable)
	log.Logf(4, "RPCServer::SyncMABGenStatus --- r.CoverageCT : %v\n", r.CoverageCT)
	log.Logf(4, "RPCServer::SyncMABGenStatus --- r.TimeCT : %v\n", r.TimeCT)

	return nil
}
