// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package vm

import (
	"fmt"
	"math/big"
	"os"
	"unicode"

	"github.com/ethereum/go-ethereum/common"
)

type Storage map[common.Hash]common.Hash

func (self Storage) Copy() Storage {
	cpy := make(Storage)
	for key, value := range self {
		cpy[key] = value
	}

	return cpy
}

// StructuredLogCollector is the basic interface to capture emited logs by the EVM logger.
type StructuredLogCollector interface {
	// Adds the structured log to the collector.
	AddStructuredLog(StructLog)
}

// LogCfg are the configuration options for structured logger the EVM
type LogCfg struct {
	DisableMemory  bool                   // disable memory capture
	DisableStack   bool                   // disable stack capture
	DisableStorage bool                   // disable storage capture
	FullStorage    bool                   // show full storage (slow)
	Collector      StructuredLogCollector // the log collector
}

// VmLogger is a logger interface used by the EVM to emit structured logs.
type VmLogger interface {
	// Log logs the given input.
	CaptureState(pc uint64, op OpCode, gas, cost *big.Int, memory *Memory, stack *stack, contract *Contract, err error)
}

// StructLog is emitted to the Environment each cycle and lists information about the current internal state
// prior to the execution of the statement.
type StructLog struct {
	Pc      uint64
	Op      OpCode
	Gas     *big.Int
	GasCost *big.Int
	Memory  []byte
	Stack   []*big.Int
	Storage map[common.Hash]common.Hash
	Err     error
}

// logger implements VmLogger
type Logger struct {
	cfg LogCfg

	env           Environment
	changedValues map[common.Address]Storage
}

// newLogger returns a new logger
func newLogger(cfg LogCfg, env Environment) *Logger {
	return &Logger{
		cfg:           cfg,
		env:           env,
		changedValues: make(map[common.Address]Storage),
	}
}

// CaptureState logs a new structured log message and pushes it out to the environment
//
// CaptureState also tracks SSTORE ops to track dirty values.
func (l *Logger) CaptureState(pc uint64, op OpCode, gas, cost *big.Int, memory *Memory, stack *stack, contract *Contract, err error) {
	// short circuit if no log collector is present
	if l.cfg.Collector == nil {
		return
	}

	switch op {
	case SSTORE:
		var (
			value   = common.BigToHash(stack.data[stack.len()-2])
			address = common.BigToHash(stack.data[stack.len()-1])
		)
		l.changedValues[contract.Address()][address] = value
	}

	var mem []byte
	if !l.cfg.DisableMemory {
		mem = make([]byte, len(memory.Data()))
		copy(mem, memory.Data())
	}

	var stck []*big.Int
	if !l.cfg.DisableStack {
		stck = make([]*big.Int, len(stack.Data()))
		for i, item := range stack.Data() {
			stck[i] = new(big.Int).Set(item)
		}
	}

	var storage Storage
	if !l.cfg.DisableStorage {
		if l.cfg.FullStorage {
			storage = make(Storage)

			l.env.Db().GetAccount(contract.Address()).ForEachStorage(func(key, value common.Hash) bool {
				storage[key] = value
				return true
			})
		} else {
			storage = l.changedValues[contract.Address()].Copy()
		}
	}

	log := StructLog{pc, op, new(big.Int).Set(gas), cost, mem, stck, storage, err}
	// Add the log to the collector
	l.cfg.Collector.AddStructuredLog(log)
}

// noopLoggor implement VmLogger and implements an empty
// logging method.
type noopLogger struct{}

// CaptureState comforms to VmLogger but is an noop, logging nothing
func (noopLogger) CaptureState(pc uint64, op OpCode, gas, cost *big.Int, memory *Memory, stack *stack, contract *Contract, err error) {
}

// StdErrFormat formats a slice of StructLogs to human readable format
func StdErrFormat(logs []StructLog) {
	fmt.Fprintf(os.Stderr, "VM STAT %d OPs\n", len(logs))
	for _, log := range logs {
		fmt.Fprintf(os.Stderr, "PC %08d: %s GAS: %v COST: %v", log.Pc, log.Op, log.Gas, log.GasCost)
		if log.Err != nil {
			fmt.Fprintf(os.Stderr, " ERROR: %v", log.Err)
		}
		fmt.Fprintf(os.Stderr, "\n")

		fmt.Fprintln(os.Stderr, "STACK =", len(log.Stack))

		for i := len(log.Stack) - 1; i >= 0; i-- {
			fmt.Fprintf(os.Stderr, "%04d: %x\n", len(log.Stack)-i-1, common.LeftPadBytes(log.Stack[i].Bytes(), 32))
		}

		const maxMem = 10
		addr := 0
		fmt.Fprintln(os.Stderr, "MEM =", len(log.Memory))
		for i := 0; i+16 <= len(log.Memory) && addr < maxMem; i += 16 {
			data := log.Memory[i : i+16]
			str := fmt.Sprintf("%04d: % x  ", addr*16, data)
			for _, r := range data {
				if r == 0 {
					str += "."
				} else if unicode.IsPrint(rune(r)) {
					str += fmt.Sprintf("%s", string(r))
				} else {
					str += "?"
				}
			}
			addr++
			fmt.Fprintln(os.Stderr, str)
		}

		fmt.Fprintln(os.Stderr, "STORAGE =", len(log.Storage))
		for h, item := range log.Storage {
			fmt.Fprintf(os.Stderr, "%x: %x\n", h, item, 32)
		}
		fmt.Fprintln(os.Stderr)
	}
}
