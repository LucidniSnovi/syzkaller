// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"math"
	"math/rand"
	"os"
	"runtime"
	"runtime/debug"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/ipc/ipcconfig"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mab"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/sys/targets"
)

type Fuzzer struct {
	name              string
	outputType        OutputType
	config            *ipc.Config
	execOpts          *ipc.ExecOpts
	procs             []*Proc
	gate              *ipc.Gate
	workQueue         *WorkQueue
	needPoll          chan struct{}
	choiceTable       *prog.ChoiceTable
	stats             [StatCount]uint64
	manager           *rpctype.RPCClient
	target            *prog.Target
	triagedCandidates uint32
	timeouts          targets.Timeouts

	faultInjectionEnabled    bool
	comparisonTracingEnabled bool
	fetchRawCover            bool

	corpusMu     sync.RWMutex
	corpus       []*prog.Prog
	corpusHashes map[hash.Sig]int
	corpusPrios  []float64 // Individual priority
	sumPrios     []float64 // Accumulated priority, i.e. sum(corpusPrios[0:i])

	signalMu     sync.RWMutex
	corpusSignal signal.Signal // signal of inputs in corpus
	maxSignal    signal.Signal // max signal ever observed including flakes
	newSignal    signal.Signal // diff of maxSignal since last sync with master

	checkResult *rpctype.CheckArgs
	logMu       sync.Mutex

	// MAB-related status
	MABStatus MABStatus
}

type FuzzerSnapshot struct {
	corpus      []*prog.Prog
	corpusPrios []float64
	sumPrios    []float64
	workQueue   *WorkQueue
}

type Stat int

const (
	StatGenerate Stat = iota
	StatFuzz
	StatCandidate
	StatTriage
	StatMinimize
	StatSmash
	StatHint
	StatSeed
	StatCollide
	StatCount
)

var statNames = [StatCount]string{
	StatGenerate:  "exec gen",
	StatFuzz:      "exec fuzz",
	StatCandidate: "exec candidate",
	StatTriage:    "exec triage",
	StatMinimize:  "exec minimize",
	StatSmash:     "exec smash",
	StatHint:      "exec hints",
	StatSeed:      "exec seeds",
	StatCollide:   "exec collide",
}

type OutputType int

const (
	OutputNone OutputType = iota
	OutputStdout
	OutputDmesg
	OutputFile
)

func createIPCConfig(features *host.Features, config *ipc.Config) {
	if features[host.FeatureExtraCoverage].Enabled {
		config.Flags |= ipc.FlagExtraCover
	}
	if features[host.FeatureDelayKcovMmap].Enabled {
		config.Flags |= ipc.FlagDelayKcovMmap
	}
	if features[host.FeatureNetInjection].Enabled {
		config.Flags |= ipc.FlagEnableTun
	}
	if features[host.FeatureNetDevices].Enabled {
		config.Flags |= ipc.FlagEnableNetDev
	}
	config.Flags |= ipc.FlagEnableNetReset
	config.Flags |= ipc.FlagEnableCgroups
	config.Flags |= ipc.FlagEnableCloseFds
	if features[host.FeatureDevlinkPCI].Enabled {
		config.Flags |= ipc.FlagEnableDevlinkPCI
	}
	if features[host.FeatureVhciInjection].Enabled {
		config.Flags |= ipc.FlagEnableVhciInjection
	}
	if features[host.FeatureWifiEmulation].Enabled {
		config.Flags |= ipc.FlagEnableWifi
	}
}

// nolint: funlen
func main() {
	debug.SetGCPercent(50)

	var (
		flagName     = flag.String("name", "test", "unique name for manager")
		flagOS       = flag.String("os", runtime.GOOS, "target OS")
		flagArch     = flag.String("arch", runtime.GOARCH, "target arch")
		flagManager  = flag.String("manager", "", "manager rpc address")
		flagProcs    = flag.Int("procs", 1, "number of parallel test processes")
		flagOutput   = flag.String("output", "stdout", "write programs to none/stdout/dmesg/file")
		flagTest     = flag.Bool("test", false, "enable image testing mode")      // used by syz-ci
		flagRunTest  = flag.Bool("runtest", false, "enable program testing mode") // used by pkg/runtest
		flagRawCover = flag.Bool("raw_cover", false, "fetch raw coverage")
		flagMABTS    = flag.Bool("mabts", false, "enable mab task selection")
		flagMABSS    = flag.Bool("mabss", false, "enable mab seed selection")
		flagMABGEN   = flag.Bool("mabgen", false, "enable mab generation")
	)
	defer tool.Init()()
	outputType := parseOutputType(*flagOutput)
	log.Logf(0, "fuzzer started")

	target, err := prog.GetTarget(*flagOS, *flagArch)
	if err != nil {
		log.Fatalf("%v", err)
	}

	config, execOpts, err := ipcconfig.Default(target)
	if err != nil {
		log.Fatalf("failed to create default ipc config: %v", err)
	}
	if *flagRawCover {
		execOpts.Flags &^= ipc.FlagDedupCover
	}
	timeouts := config.Timeouts
	sandbox := ipc.FlagsToSandbox(config.Flags)
	shutdown := make(chan struct{})
	osutil.HandleInterrupts(shutdown)
	go func() {
		// Handles graceful preemption on GCE.
		<-shutdown
		log.Logf(0, "SYZ-FUZZER: PREEMPTED")
		os.Exit(1)
	}()

	checkArgs := &checkArgs{
		target:         target,
		sandbox:        sandbox,
		ipcConfig:      config,
		ipcExecOpts:    execOpts,
		gitRevision:    prog.GitRevision,
		targetRevision: target.Revision,
	}
	if *flagTest {
		testImage(*flagManager, checkArgs)
		return
	}

	machineInfo, modules := collectMachineInfos(target)

	log.Logf(0, "dialing manager at %v", *flagManager)
	manager, err := rpctype.NewRPCClient(*flagManager, timeouts.Scale)
	if err != nil {
		log.Fatalf("failed to connect to manager: %v ", err)
	}

	log.Logf(1, "connecting to manager...")
	a := &rpctype.ConnectArgs{
		Name:        *flagName,
		MachineInfo: machineInfo,
		Modules:     modules,
	}
	r := &rpctype.ConnectRes{}
	if err := manager.Call("Manager.Connect", a, r); err != nil {
		log.Fatalf("failed to connect to manager: %v ", err)
	}
	featureFlags, err := csource.ParseFeaturesFlags("none", "none", true)
	if err != nil {
		log.Fatal(err)
	}
	if r.CoverFilterBitmap != nil {
		if err := osutil.WriteFile("syz-cover-bitmap", r.CoverFilterBitmap); err != nil {
			log.Fatalf("failed to write syz-cover-bitmap: %v", err)
		}
	}
	if r.CheckResult == nil {
		checkArgs.gitRevision = r.GitRevision
		checkArgs.targetRevision = r.TargetRevision
		checkArgs.enabledCalls = r.EnabledCalls
		checkArgs.allSandboxes = r.AllSandboxes
		checkArgs.featureFlags = featureFlags
		r.CheckResult, err = checkMachine(checkArgs)
		if err != nil {
			if r.CheckResult == nil {
				r.CheckResult = new(rpctype.CheckArgs)
			}
			r.CheckResult.Error = err.Error()
		}
		r.CheckResult.Name = *flagName
		if err := manager.Call("Manager.Check", r.CheckResult, nil); err != nil {
			log.Fatalf("Manager.Check call failed: %v", err)
		}
		if r.CheckResult.Error != "" {
			log.Fatalf("%v", r.CheckResult.Error)
		}
	} else {
		target.UpdateGlobs(r.CheckResult.GlobFiles)
		if err = host.Setup(target, r.CheckResult.Features, featureFlags, config.Executor); err != nil {
			log.Fatal(err)
		}
	}
	log.Logf(0, "syscalls: %v", len(r.CheckResult.EnabledCalls[sandbox]))
	for _, feat := range r.CheckResult.Features.Supported() {
		log.Logf(0, "%v: %v", feat.Name, feat.Reason)
	}
	createIPCConfig(r.CheckResult.Features, config)

	if *flagRunTest {
		runTest(target, manager, *flagName, config.Executor)
		return
	}

	needPoll := make(chan struct{}, 1)
	needPoll <- struct{}{}
	fuzzer := &Fuzzer{
		name:                     *flagName,
		outputType:               outputType,
		config:                   config,
		execOpts:                 execOpts,
		workQueue:                newWorkQueue(*flagProcs, needPoll),
		needPoll:                 needPoll,
		manager:                  manager,
		target:                   target,
		timeouts:                 timeouts,
		faultInjectionEnabled:    r.CheckResult.Features[host.FeatureFault].Enabled,
		comparisonTracingEnabled: r.CheckResult.Features[host.FeatureComparisons].Enabled,
		checkResult:              r.CheckResult,
		fetchRawCover:            *flagRawCover,
		corpusHashes:             make(map[hash.Sig]int),
		MABStatus: MABStatus{
			TSEnabled:      *flagMABTS,
			SSEnabled:      *flagMABSS,
			GenEnabled:     *flagMABGEN,
			CorpusUpdate:   make(map[int]int),
			TSGamma:        0.05,
			TSEta:          0.1,
			SSGamma:        0.05,
			SSEta:          0.1,
			Round:          0,
			Exp31Round:     1,
			Exp31Threshold: 1.0,
			Reward:         mab.TotalReward{},
		},
	}
	fuzzer.MABStatus.fuzzer = fuzzer
	log.Logf(0, "MAB Current Reward: %+v", fuzzer.MABStatus.Reward)
	gateCallback := fuzzer.useBugFrames(r, *flagProcs)
	fuzzer.gate = ipc.NewGate(2**flagProcs, gateCallback)

	for needCandidates, more := true, true; more; needCandidates = false {
		more = fuzzer.poll(needCandidates, nil)
		// This loop lead to "no output" in qemu emulation, tell manager we are not dead.
		log.Logf(0, "fetching corpus: %v, signal %v/%v (executing program)",
			len(fuzzer.corpus), len(fuzzer.corpusSignal), len(fuzzer.maxSignal))
	}
	calls := make(map[*prog.Syscall]bool)
	for _, id := range r.CheckResult.EnabledCalls[sandbox] {
		calls[target.Syscalls[id]] = true
	}
	fuzzer.choiceTable = target.BuildChoiceTable(fuzzer.corpus, calls)

	if fuzzer.MABStatus.GenEnabled {
		log.Logf(0, "Creating MAB Enabled calls and MAB Choice table.\n")
		fuzzer.choiceTable.MabGenEnabled = true
		fuzzer.choiceTable.CreateMABEnabledCalls()
		fuzzer.choiceTable.CreateMABChoiceTable()
		log.Logf(0, "Creating MAB Enabled calls and MAB Choice table...DONE\n")
		log.Logf(0, "Updating with MAB Gen sync data.\n")
		fuzzer.choiceTable.MabEnabledCalls.UpdateSyncData(fuzzer.MABStatus.MABGenEnabledCalls, fuzzer.MABStatus.MABGenCount, fuzzer.MABStatus.MABGenCoverage,
			fuzzer.MABStatus.MABGenTime, fuzzer.MABStatus.MABGenReward, fuzzer.MABStatus.MABGenReward2)
		fuzzer.choiceTable.MabChoiceTable.UpdateSyncData(fuzzer.MABStatus.MABGenChoiceTable, fuzzer.MABStatus.MABGenCountCT, fuzzer.MABStatus.MABGenCoverageCT,
			fuzzer.MABStatus.MABGenTimeCT, fuzzer.MABStatus.MABGenRewardCT, fuzzer.MABStatus.MABGenReward2CT)
		log.Logf(0, "Updating with MAB Gen sync data...DONE\n")
	}

	if r.CoverFilterBitmap != nil {
		fuzzer.execOpts.Flags |= ipc.FlagEnableCoverageFilter
	}

	log.Logf(0, "starting %v fuzzer processes", *flagProcs)
	for pid := 0; pid < *flagProcs; pid++ {
		proc, err := newProc(fuzzer, pid)
		if err != nil {
			log.Fatalf("failed to create proc: %v", err)
		}
		fuzzer.procs = append(fuzzer.procs, proc)
		go proc.loop()
	}

	fuzzer.pollLoop()
}

func collectMachineInfos(target *prog.Target) ([]byte, []host.KernelModule) {
	machineInfo, err := host.CollectMachineInfo()
	if err != nil {
		log.Fatalf("failed to collect machine information: %v", err)
	}
	modules, err := host.CollectModulesInfo()
	if err != nil {
		log.Fatalf("failed to collect modules info: %v", err)
	}
	return machineInfo, modules
}

// Returns gateCallback for leak checking if enabled.
func (fuzzer *Fuzzer) useBugFrames(r *rpctype.ConnectRes, flagProcs int) func() {
	var gateCallback func()

	if r.CheckResult.Features[host.FeatureLeak].Enabled {
		gateCallback = func() { fuzzer.gateCallback(r.MemoryLeakFrames) }
	}

	if r.CheckResult.Features[host.FeatureKCSAN].Enabled && len(r.DataRaceFrames) != 0 {
		fuzzer.filterDataRaceFrames(r.DataRaceFrames)
	}

	return gateCallback
}

func (fuzzer *Fuzzer) gateCallback(leakFrames []string) {
	// Leak checking is very slow so we don't do it while triaging the corpus
	// (otherwise it takes infinity). When we have presumably triaged the corpus
	// (triagedCandidates == 1), we run leak checking bug ignore the result
	// to flush any previous leaks. After that (triagedCandidates == 2)
	// we do actual leak checking and report leaks.
	triagedCandidates := atomic.LoadUint32(&fuzzer.triagedCandidates)
	if triagedCandidates == 0 {
		return
	}
	args := append([]string{"leak"}, leakFrames...)
	timeout := fuzzer.timeouts.NoOutput * 9 / 10
	output, err := osutil.RunCmd(timeout, "", fuzzer.config.Executor, args...)
	if err != nil && triagedCandidates == 2 {
		// If we exit right away, dying executors will dump lots of garbage to console.
		os.Stdout.Write(output)
		fmt.Printf("BUG: leak checking failed\n")
		time.Sleep(time.Hour)
		os.Exit(1)
	}
	if triagedCandidates == 1 {
		atomic.StoreUint32(&fuzzer.triagedCandidates, 2)
	}
}

func (fuzzer *Fuzzer) filterDataRaceFrames(frames []string) {
	args := append([]string{"setup_kcsan_filterlist"}, frames...)
	timeout := time.Minute * fuzzer.timeouts.Scale
	output, err := osutil.RunCmd(timeout, "", fuzzer.config.Executor, args...)
	if err != nil {
		log.Fatalf("failed to set KCSAN filterlist: %v", err)
	}
	log.Logf(0, "%s", output)
}

func (fuzzer *Fuzzer) pollLoop() {
	var execTotal uint64
	var lastPoll time.Time
	var lastPrint time.Time
	ticker := time.NewTicker(3 * time.Second * fuzzer.timeouts.Scale).C
	for {
		poll := false
		select {
		case <-ticker:
		case <-fuzzer.needPoll:
			poll = true
		}
		if fuzzer.outputType != OutputStdout && time.Since(lastPrint) > 10*time.Second*fuzzer.timeouts.Scale {
			// Keep-alive for manager.
			log.Logf(0, "alive, executed %v", execTotal)
			lastPrint = time.Now()
		}
		if poll || time.Since(lastPoll) > 10*time.Second*fuzzer.timeouts.Scale {
			needCandidates := fuzzer.workQueue.wantCandidates()
			if poll && !needCandidates {
				continue
			}
			stats := make(map[string]uint64)
			for _, proc := range fuzzer.procs {
				stats["exec total"] += atomic.SwapUint64(&proc.env.StatExecs, 0)
				stats["executor restarts"] += atomic.SwapUint64(&proc.env.StatRestarts, 0)
			}
			for stat := Stat(0); stat < StatCount; stat++ {
				v := atomic.SwapUint64(&fuzzer.stats[stat], 0)
				stats[statNames[stat]] = v
				execTotal += v
			}
			if !fuzzer.poll(needCandidates, stats) {
				lastPoll = time.Now()
			}
		}
	}
}

func (fuzzer *Fuzzer) poll(needCandidates bool, stats map[string]uint64) bool {
	a := &rpctype.PollArgs{
		Name:           fuzzer.name,
		NeedCandidates: needCandidates,
		MaxSignal:      fuzzer.grabNewSignal().Serialize(),
		Stats:          stats,
	}
	if fuzzer.MABStatus.TSEnabled || fuzzer.MABStatus.SSEnabled {
		fuzzer.MABStatus.MABMu.Lock()
		a.RPCMABStatus = fuzzer.MABStatus.readMABStatus()
		if fuzzer.MABStatus.GenEnabled {
			a.RPCMABGenSync = fuzzer.MABStatus.readMABGenSync(fuzzer.choiceTable)
		}
	} else if fuzzer.MABStatus.GenEnabled {
		fuzzer.MABStatus.MABMu.Lock()
		a.RPCMABGenSync = fuzzer.MABStatus.readMABGenSync(fuzzer.choiceTable)
	}
	r := &rpctype.PollRes{}
	if err := fuzzer.manager.Call("Manager.Poll", a, r); err != nil {
		log.Fatalf("Manager.Poll call failed: %v", err)
	}
	maxSignal := r.MaxSignal.Deserialize()
	log.Logf(1, "poll: candidates=%v inputs=%v signal=%v",
		len(r.Candidates), len(r.NewInputs), maxSignal.Len())
	fuzzer.addMaxSignal(maxSignal)
	for _, inp := range r.NewInputs {
		fuzzer.addInputFromAnotherFuzzer(inp)
	}
	for _, candidate := range r.Candidates {
		fuzzer.addCandidateInput(candidate)
	}
	if needCandidates && len(r.Candidates) == 0 && atomic.LoadUint32(&fuzzer.triagedCandidates) == 0 {
		atomic.StoreUint32(&fuzzer.triagedCandidates, 1)
	}
	if fuzzer.MABStatus.TSEnabled || fuzzer.MABStatus.SSEnabled {
		fuzzer.MABStatus.writeMABStatus(r.RPCMABStatus)
		if fuzzer.MABStatus.GenEnabled {
			fuzzer.MABStatus.writeMABGenSync(fuzzer.choiceTable, r.RPCMABGenSync)
		}
		fuzzer.MABStatus.MABMu.Unlock()
	} else if fuzzer.MABStatus.GenEnabled {
		fuzzer.MABStatus.writeMABGenSync(fuzzer.choiceTable, r.RPCMABGenSync)
		fuzzer.MABStatus.MABMu.Unlock()
	}
	return len(r.NewInputs) != 0 || len(r.Candidates) != 0 || maxSignal.Len() != 0
}

func (fuzzer *Fuzzer) sendInputToManager(inp rpctype.Input) {
	a := &rpctype.NewInputArgs{
		Name:  fuzzer.name,
		Input: inp,
	}

	if err := fuzzer.manager.Call("Manager.NewInput", a, nil); err != nil {
		log.Fatalf("Manager.NewInput call failed: %v", err)
	}
}

func (fuzzer *Fuzzer) addInputFromAnotherFuzzer(inp rpctype.Input) {
	p := fuzzer.deserializeInput(inp.Prog)
	if p == nil {
		return
	}
	p.CorpusReward = inp.Reward
	sig := hash.Hash(inp.Prog)
	sign := inp.Signal.Deserialize()
	fuzzer.addInputToCorpus(p, sign, sig)
}

func (fuzzer *FuzzerSnapshot) chooseProgram(r *rand.Rand) (int, *prog.Prog) {
	randVal := r.Float64() * fuzzer.sumPrios[len(fuzzer.sumPrios)-1]
	idx := sort.Search(len(fuzzer.sumPrios), func(i int) bool {
		return fuzzer.sumPrios[i] >= randVal
	})
	return idx, fuzzer.corpus[idx]
}

func (fuzzer *Fuzzer) addCandidateInput(candidate rpctype.Candidate) {
	p := fuzzer.deserializeInput(candidate.Prog)
	if p == nil {
		return
	}
	flags := ProgCandidate
	if candidate.Minimized {
		flags |= ProgMinimized
	}
	if candidate.Smashed {
		flags |= ProgSmashed
	}
	fuzzer.workQueue.enqueue(&WorkCandidate{
		p:     p,
		flags: flags,
	})
}

func (fuzzer *Fuzzer) deserializeInput(inp []byte) *prog.Prog {
	p, err := fuzzer.target.Deserialize(inp, prog.NonStrict)
	if err != nil {
		log.Fatalf("failed to deserialize prog: %v\n%s", err, inp)
	}
	// We build choice table only after we received the initial corpus,
	// so we don't check the initial corpus here, we check it later in BuildChoiceTable.
	if fuzzer.choiceTable != nil {
		fuzzer.checkDisabledCalls(p)
	}
	if len(p.Calls) > prog.MaxCalls {
		return nil
	}
	return p
}

func (fuzzer *Fuzzer) checkDisabledCalls(p *prog.Prog) {
	for _, call := range p.Calls {
		if !fuzzer.choiceTable.Enabled(call.Meta.ID) {
			fmt.Printf("executing disabled syscall %v [%v]\n", call.Meta.Name, call.Meta.ID)
			sandbox := ipc.FlagsToSandbox(fuzzer.config.Flags)
			fmt.Printf("check result for sandbox=%v:\n", sandbox)
			for _, id := range fuzzer.checkResult.EnabledCalls[sandbox] {
				meta := fuzzer.target.Syscalls[id]
				fmt.Printf("  %v [%v]\n", meta.Name, meta.ID)
			}
			fmt.Printf("choice table:\n")
			for i, meta := range fuzzer.target.Syscalls {
				fmt.Printf("  #%v: %v [%v]: enabled=%v\n", i, meta.Name, meta.ID, fuzzer.choiceTable.Enabled(meta.ID))
			}
			panic("disabled syscall")
		}
	}
}

func (fuzzer *Fuzzer) addInputToCorpus(p *prog.Prog, sign signal.Signal, sig hash.Sig) int {
	pidx := -1 // If duplicate seed, do not set pidx
	fuzzer.corpusMu.Lock()
	if _, ok := fuzzer.corpusHashes[sig]; !ok {
		prio := float64(len(sign))
		if sign.Empty() {
			prio = 1.0
		} else if fuzzer.MABStatus.SSEnabled {
			prio = math.Exp(p.CorpusReward.MutateRewardOrig)
		}
		fuzzer.corpus = append(fuzzer.corpus, p)
		pidx = len(fuzzer.corpus) - 1
		fuzzer.corpusHashes[sig] = pidx
		fuzzer.corpusPrios = append(fuzzer.corpusPrios, prio)
		newPrio := prio
		if len(fuzzer.sumPrios) > 0 {
			newPrio = fuzzer.sumPrios[len(fuzzer.sumPrios)-1] + prio
		}
		fuzzer.sumPrios = append(fuzzer.sumPrios, newPrio)
		// MAB-SS parameters need to change
		if fuzzer.MABStatus.SSEnabled {
			K := float64(len(fuzzer.corpus))
			fuzzer.MABStatus.SSEta = 0.1 * math.Sqrt(2.0*math.Log(K)/K)
			fuzzer.MABStatus.SSGamma = fuzzer.MABStatus.SSEta / 2.0
			log.Logf(MABLogLevel, "MAB SS Gamma = %v, Eta = %v", fuzzer.MABStatus.SSGamma, fuzzer.MABStatus.SSEta)
		}
	}
	fuzzer.corpusMu.Unlock()

	if !sign.Empty() {
		fuzzer.signalMu.Lock()
		fuzzer.corpusSignal.Merge(sign)
		fuzzer.maxSignal.Merge(sign)
		fuzzer.signalMu.Unlock()
	}
	return pidx
}

func (fuzzer *Fuzzer) snapshot() FuzzerSnapshot {
	fuzzer.corpusMu.RLock()
	defer fuzzer.corpusMu.RUnlock()
	return FuzzerSnapshot{fuzzer.corpus, fuzzer.corpusPrios, fuzzer.sumPrios, fuzzer.workQueue}
}

func (fuzzer *Fuzzer) addMaxSignal(sign signal.Signal) {
	if sign.Len() == 0 {
		return
	}
	fuzzer.signalMu.Lock()
	defer fuzzer.signalMu.Unlock()
	fuzzer.maxSignal.Merge(sign)
}

func (fuzzer *Fuzzer) grabNewSignal() signal.Signal {
	fuzzer.signalMu.Lock()
	defer fuzzer.signalMu.Unlock()
	sign := fuzzer.newSignal
	if sign.Empty() {
		return nil
	}
	fuzzer.newSignal = nil
	return sign
}

func (fuzzer *Fuzzer) corpusSignalDiff(sign signal.Signal) signal.Signal {
	fuzzer.signalMu.RLock()
	defer fuzzer.signalMu.RUnlock()
	return fuzzer.corpusSignal.Diff(sign)
}

func (fuzzer *Fuzzer) checkNewSignal(p *prog.Prog, info *ipc.ProgInfo) (calls []int, extra bool, cov int) {
	fuzzer.signalMu.RLock()
	defer fuzzer.signalMu.RUnlock()
	cov = 0
	thisCov := 0
	for i, inf := range info.Calls {
		thisCov = fuzzer.checkNewCallSignal(p, &inf, i)
		if thisCov > 0 {
			calls = append(calls, i)
			cov += thisCov
		}
	}
	extra = false
	thisCov = fuzzer.checkNewCallSignal(p, &info.Extra, -1)
	if thisCov > 0 {
		extra = true
		cov += thisCov
	}
	return
}

func (fuzzer *Fuzzer) checkNewCallSignal(p *prog.Prog, info *ipc.CallInfo, call int) int {
	diff := fuzzer.maxSignal.DiffRaw(info.Signal, signalPrio(p, info, call))
	if diff.Empty() {
		return 0
	}
	fuzzer.signalMu.RUnlock()
	fuzzer.signalMu.Lock()
	fuzzer.maxSignal.Merge(diff)
	fuzzer.newSignal.Merge(diff)
	fuzzer.signalMu.Unlock()
	fuzzer.signalMu.RLock()
	return len(diff)
}

func signalPrio(p *prog.Prog, info *ipc.CallInfo, call int) (prio uint8) {
	if call == -1 {
		return 0
	}
	if info.Errno == 0 {
		prio |= 1 << 1
	}
	if !p.Target.CallContainsAny(p.Calls[call]) {
		prio |= 1 << 0
	}
	return
}

func parseOutputType(str string) OutputType {
	switch str {
	case "none":
		return OutputNone
	case "stdout":
		return OutputStdout
	case "dmesg":
		return OutputDmesg
	case "file":
		return OutputFile
	default:
		log.Fatalf("-output flag must be one of none/stdout/dmesg/file")
		return OutputNone
	}
}
