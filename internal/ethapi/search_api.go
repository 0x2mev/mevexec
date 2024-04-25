package ethapi

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus/misc/eip1559"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth/tracers/logger"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/holiman/uint256"
	"golang.org/x/crypto/sha3"
	"math"
	"math/big"
	"math/rand"
	"time"
)

// MEVEXEC ADDITIONS
// the following are additional rpc methods added into the execution client for mev searchers

// SearcherAPI provides an API to access Ethereum blockchain data.
type SearcherAPI struct {
	b     Backend
	chain *core.BlockChain
}

func NewSearcherAPI(b Backend, chain *core.BlockChain) *SearcherAPI {
	return &SearcherAPI{b, chain}
}

// CallBundleArgs represents the arguments for a call.
type CallBundleArgs struct {
	Txs                    []hexutil.Bytes       `json:"txs"`
	BlockNumber            rpc.BlockNumber       `json:"blockNumber"`
	StateBlockNumberOrHash rpc.BlockNumberOrHash `json:"stateBlockNumber"`
	Coinbase               *string               `json:"coinbase"`
	Timestamp              *uint64               `json:"timestamp"`
	Timeout                *int64                `json:"timeout"`
	GasLimit               *uint64               `json:"gasLimit"`
	Difficulty             *hexutil.Big          `json:"difficulty"`
	BaseFee                *hexutil.Big          `json:"baseFee"`
	SimulationLogs         bool                  `json:"simulationLogs"`
	CreateAccessList       bool                  `json:"createAccessList"`
	StateOverrides         *StateOverride        `json:"stateOverrides"`
	MixDigest              *common.Hash          `json:"mixDigest"`
}

// CallBundle will simulate a bundle of transactions at the top of a given block
// number with the state of another (or the same) block. This can be used to
// simulate future blocks with the current state, or it can be used to simulate
// a past block.
// The sender is responsible for signing the transactions and using the correct
// nonce and ensuring validity
func (s *SearcherAPI) CallBundle(ctx context.Context, args CallBundleArgs) (map[string]interface{}, error) {
	if len(args.Txs) == 0 {
		return nil, errors.New("bundle missing txs")
	}
	if args.BlockNumber == 0 {
		return nil, errors.New("bundle missing blockNumber")
	}

	var txs types.Transactions

	for _, encodedTx := range args.Txs {
		tx := new(types.Transaction)
		if err := tx.UnmarshalBinary(encodedTx); err != nil {
			return nil, err
		}
		txs = append(txs, tx)
	}
	defer func(start time.Time) { log.Debug("Executing EVM call finished", "runtime", time.Since(start)) }(time.Now())

	timeoutMilliSeconds := int64(5000)
	if args.Timeout != nil {
		timeoutMilliSeconds = *args.Timeout
	}
	timeout := time.Millisecond * time.Duration(timeoutMilliSeconds)
	state, parent, err := s.b.StateAndHeaderByNumberOrHash(ctx, args.StateBlockNumberOrHash)
	if state == nil || err != nil {
		return nil, err
	}
	if err := args.StateOverrides.Apply(state); err != nil {
		return nil, err
	}
	blockNumber := big.NewInt(int64(args.BlockNumber))

	timestamp := parent.Time + 12
	if args.Timestamp != nil {
		timestamp = *args.Timestamp
	}
	coinbase := parent.Coinbase
	if args.Coinbase != nil {
		coinbase = common.HexToAddress(*args.Coinbase)
	}
	difficulty := parent.Difficulty
	if args.Difficulty != nil {
		difficulty = args.Difficulty.ToInt()
	}
	gasLimit := parent.GasLimit
	if args.GasLimit != nil {
		gasLimit = *args.GasLimit
	}
	var baseFee *big.Int
	if args.BaseFee != nil {
		baseFee = args.BaseFee.ToInt()
	} else if s.b.ChainConfig().IsLondon(big.NewInt(args.BlockNumber.Int64())) {
		baseFee = eip1559.CalcBaseFee(s.b.ChainConfig(), parent)
	}
	mixDigest := parent.MixDigest
	if args.MixDigest != nil {
		mixDigest = *args.MixDigest
	}
	header := &types.Header{
		ParentHash: parent.Hash(),
		Number:     blockNumber,
		GasLimit:   gasLimit,
		Time:       timestamp,
		Difficulty: difficulty,
		Coinbase:   coinbase,
		BaseFee:    baseFee,
		MixDigest:  mixDigest,
	}

	// Setup context so it may be cancelled the call has completed
	// or, in case of unmetered gas, setup a context with a timeout.
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	// Make sure the context is cancelled when the call has completed
	// this makes sure resources are cleaned up.
	defer cancel()

	vmconfig := vm.Config{}

	// Setup the gas pool (also for unmetered requests)
	// and apply the message.
	gp := new(core.GasPool).AddGas(math.MaxUint64)

	var results []map[string]interface{}
	coinbaseBalanceBefore := state.GetBalance(coinbase)

	bundleHash := sha3.NewLegacyKeccak256()
	signer := types.MakeSigner(s.b.ChainConfig(), header.Number, header.Time)
	var totalGasUsed uint64
	gasFees := new(big.Int)
	for i, tx := range txs {
		coinbaseBalanceBeforeTx := state.GetBalance(coinbase)
		state.SetTxContext(tx.Hash(), i)

		accessListState := state.Copy() // create a copy just in case we use it later for access list creation

		receipt, result, err := core.ApplyTransaction(s.b.ChainConfig(), s.chain, &coinbase, gp, state, header, tx, &header.GasUsed, vmconfig)
		if err != nil {
			return nil, fmt.Errorf("err: %w; txhash %s", err, tx.Hash())
		}

		txHash := tx.Hash().String()
		from, err := types.Sender(signer, tx)
		if err != nil {
			return nil, fmt.Errorf("err: %w; txhash %s", err, tx.Hash())
		}
		to := "0x"
		if tx.To() != nil {
			to = tx.To().String()
		}
		jsonResult := map[string]interface{}{
			"txHash":      txHash,
			"gasUsed":     receipt.GasUsed,
			"fromAddress": from.String(),
			"toAddress":   to,
			"logs":        receipt.Logs,
		}
		totalGasUsed += receipt.GasUsed
		gasPrice, err := tx.EffectiveGasTip(header.BaseFee)
		if err != nil {
			return nil, fmt.Errorf("err: %w; txhash %s", err, tx.Hash())
		}
		gasFeesTx := new(big.Int).Mul(big.NewInt(int64(receipt.GasUsed)), gasPrice)
		gasFees.Add(gasFees, gasFeesTx)
		bundleHash.Write(tx.Hash().Bytes())
		if result.Err != nil {
			jsonResult["error"] = result.Err.Error()
			revert := result.Revert()
			if len(revert) > 0 {
				jsonResult["revert"] = string(revert)
			}
		} else {
			dst := make([]byte, hex.EncodedLen(len(result.Return())))
			hex.Encode(dst, result.Return())
			jsonResult["value"] = "0x" + string(dst)
		}
		//// if simulation logs are requested append it to logs
		//if args.SimulationLogs {
		//	jsonResult["logs"] = receipt.Logs
		//}
		// if an access list is requested create and append
		if args.CreateAccessList {
			// ifdk another way to fill all values so this will have to do - x2
			txArgGas := hexutil.Uint64(tx.Gas())
			txArgNonce := hexutil.Uint64(tx.Nonce())
			txArgData := hexutil.Bytes(tx.Data())
			txargs := TransactionArgs{
				From:    &from,
				To:      tx.To(),
				Gas:     &txArgGas,
				Nonce:   &txArgNonce,
				Data:    &txArgData,
				Value:   (*hexutil.Big)(tx.Value()),
				ChainID: (*hexutil.Big)(tx.ChainId()),
			}
			if tx.GasFeeCap().Cmp(big.NewInt(0)) == 0 { // no maxbasefee, set gasprice instead
				txargs.GasPrice = (*hexutil.Big)(tx.GasPrice())
			} else { // otherwise set base and priority fee
				txargs.MaxFeePerGas = (*hexutil.Big)(tx.GasFeeCap())
				txargs.MaxPriorityFeePerGas = (*hexutil.Big)(tx.GasTipCap())
			}
			acl, gasUsed, vmerr, err := AccessListOnState(ctx, s.b, header, accessListState, txargs)
			if err == nil {
				if gasUsed != receipt.GasUsed {
					log.Debug("Gas used in receipt differ from accesslist", "receipt", receipt.GasUsed, "acl", gasUsed) // weird bug but it works
				}
				if vmerr != nil {
					log.Info("CallBundle accesslist creation encountered vmerr", "vmerr", vmerr)
				}
				jsonResult["accessList"] = acl

			} else {
				log.Info("CallBundle accesslist creation encountered err", "err", err)
				jsonResult["accessList"] = acl //
			} // return the empty accesslist either way
		}
		coinbaseDiffTx := new(uint256.Int).Sub(state.GetBalance(coinbase), coinbaseBalanceBeforeTx)
		jsonResult["coinbaseDiff"] = coinbaseDiffTx.String()
		jsonResult["gasFees"] = gasFeesTx.String()
		jsonResult["ethSentToCoinbase"] = new(uint256.Int).Sub(coinbaseDiffTx, uint256.MustFromBig(gasFeesTx)).String()
		jsonResult["gasPrice"] = new(uint256.Int).Div(coinbaseDiffTx, uint256.NewInt(receipt.GasUsed)).String()
		jsonResult["gasUsed"] = receipt.GasUsed
		results = append(results, jsonResult)
	}

	ret := map[string]interface{}{}
	ret["results"] = results
	coinbaseDiff := new(uint256.Int).Sub(state.GetBalance(coinbase), coinbaseBalanceBefore)
	ret["coinbaseDiff"] = coinbaseDiff.String()
	ret["gasFees"] = gasFees.String()
	ret["ethSentToCoinbase"] = new(uint256.Int).Sub(coinbaseDiff, uint256.MustFromBig(gasFees)).String()
	ret["bundleGasPrice"] = new(uint256.Int).Div(coinbaseDiff, uint256.NewInt(totalGasUsed)).String()
	ret["totalGasUsed"] = totalGasUsed
	ret["stateBlockNumber"] = parent.Number.Int64()

	ret["bundleHash"] = "0x" + common.Bytes2Hex(bundleHash.Sum(nil))
	return ret, nil
}

// EstimateGasBundleArgs are possible args for eth_estimateGasBundle
type EstimateGasBundleArgs struct {
	Txs                    []TransactionArgs     `json:"txs"`
	BlockNumber            rpc.BlockNumber       `json:"blockNumber"`
	StateBlockNumberOrHash rpc.BlockNumberOrHash `json:"stateBlockNumber"`
	Coinbase               *string               `json:"coinbase"`
	Timestamp              *uint64               `json:"timestamp"`
	Timeout                *int64                `json:"timeout"`
	StateOverrides         *StateOverride        `json:"stateOverrides"`
	CreateAccessList       bool                  `json:"createAccessList"`
}

// EstimateGasBundle callbundle, but doesnt require signing
func (s *SearcherAPI) EstimateGasBundle(ctx context.Context, args EstimateGasBundleArgs) (map[string]interface{}, error) {
	if len(args.Txs) == 0 {
		return nil, errors.New("bundle missing txs")
	}
	if args.BlockNumber == 0 {
		return nil, errors.New("bundle missing blockNumber")
	}

	timeoutMS := int64(5000)
	if args.Timeout != nil {
		timeoutMS = *args.Timeout
	}
	timeout := time.Millisecond * time.Duration(timeoutMS)

	state, parent, err := s.b.StateAndHeaderByNumberOrHash(ctx, args.StateBlockNumberOrHash)
	if state == nil || err != nil {
		return nil, err
	}
	if err := args.StateOverrides.Apply(state); err != nil {
		return nil, err
	}

	blockNumber := big.NewInt(int64(args.BlockNumber))
	timestamp := parent.Time + 1
	if args.Timestamp != nil {
		timestamp = *args.Timestamp
	}
	coinbase := parent.Coinbase
	if args.Coinbase != nil {
		coinbase = common.HexToAddress(*args.Coinbase)
	}

	header := &types.Header{
		ParentHash: parent.Hash(),
		Number:     blockNumber,
		GasLimit:   parent.GasLimit,
		Time:       timestamp,
		Difficulty: parent.Difficulty,
		Coinbase:   coinbase,
		BaseFee:    parent.BaseFee,
	}

	// Setup context so it may be cancelled when the call
	// has completed or, in case of unmetered gas, setup
	// a context with a timeout
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}

	// Make sure the context is cancelled when the call has completed
	// This makes sure resources are cleaned up
	defer cancel()

	// RPC Call gas cap
	globalGasCap := s.b.RPCGasCap()

	// Results
	var results []map[string]interface{}

	// Copy the original db so we don't modify it
	statedb := state.Copy()

	// Gas pool
	gp := new(core.GasPool).AddGas(math.MaxUint64)

	// Block context
	blockContext := core.NewEVMBlockContext(header, s.chain, &coinbase)

	// Feed each of the transactions into the VM ctx
	// And try and estimate the gas used
	for i, txArgs := range args.Txs {
		// Since its a txCall we'll just prepare the
		// state with a random hash
		var randomHash common.Hash
		rand.Read(randomHash[:])

		// New random hash since its a call
		statedb.SetTxContext(randomHash, i)

		accessListState := statedb.Copy() // create a copy just in case we use it later for access list creation

		// Convert tx args to msg to apply state transition
		msg, err := txArgs.ToMessage(globalGasCap, header.BaseFee)
		if err != nil {
			return nil, err
		}

		// Prepare the hashes
		txContext := core.NewEVMTxContext(msg)

		// Get EVM Environment
		vmenv := vm.NewEVM(blockContext, txContext, statedb, s.b.ChainConfig(), vm.Config{NoBaseFee: true})

		// Apply state transition
		result, err := core.ApplyMessage(vmenv, msg, gp)
		if err != nil {
			return nil, err
		}

		// Modifications are committed to the state
		// Only delete empty objects if EIP158/161 (a.k.a Spurious Dragon) is in effect
		statedb.Finalise(vmenv.ChainConfig().IsEIP158(blockNumber))

		// Append result
		jsonResult := map[string]interface{}{
			"gasUsed": result.UsedGas,
		}

		if result.Err != nil {
			jsonResult["error"] = result.Err.Error()
			revert := result.Revert()
			if len(revert) > 0 {
				jsonResult["revert"] = string(revert)
			}
		}

		if len(result.ReturnData) > 0 {
			jsonResult["data"] = hexutil.Bytes(result.ReturnData)
		}

		// if simulation logs are requested append it to logs
		// if an access list is requested create and append
		if args.CreateAccessList {
			// welp guess we're copying these again sigh
			txArgFrom := msg.From
			txArgGas := hexutil.Uint64(msg.GasLimit)
			txArgNonce := hexutil.Uint64(msg.Nonce)
			txArgData := hexutil.Bytes(msg.Data)
			txargs := TransactionArgs{
				From:    &txArgFrom,
				To:      msg.To,
				Gas:     &txArgGas,
				Nonce:   &txArgNonce,
				Data:    &txArgData,
				ChainID: (*hexutil.Big)(s.chain.Config().ChainID),
				Value:   (*hexutil.Big)(msg.Value),
			}
			if msg.GasFeeCap.Cmp(big.NewInt(0)) == 0 { // no maxbasefee, set gasprice instead
				txargs.GasPrice = (*hexutil.Big)(msg.GasPrice)
			} else { // otherwise set base and priority fee
				txargs.MaxFeePerGas = (*hexutil.Big)(msg.GasFeeCap)
				txargs.MaxPriorityFeePerGas = (*hexutil.Big)(msg.GasTipCap)
			}
			acl, _, vmerr, err := AccessListOnState(ctx, s.b, header, accessListState, txargs)
			if err == nil {
				if vmerr != nil {
					log.Info("CallBundle accesslist creation encountered vmerr", "vmerr", vmerr)
				}
				jsonResult["accessList"] = acl

			} else {
				log.Info("CallBundle accesslist creation encountered err", "err", err)
				jsonResult["accessList"] = acl //
			} // return the empty accesslist either way
		}

		results = append(results, jsonResult)
	}

	// Return results
	ret := map[string]interface{}{}
	ret["results"] = results

	return ret, nil
}

// rpcMarshalCompact uses the generalized output filler, then adds the total difficulty field, which requires
// a `PublicBlockchainAPI`.
func (s *SearcherAPI) rpcMarshalCompactHeader(ctx context.Context, h *types.Header) map[string]interface{} {
	return RPCMarshalCompactHeader(h)
}

// GetCompactBlocks gets the compact block data for the given block's hash or number
// the logs in the block can also be requested
func (s *SearcherAPI) GetCompactBlocks(ctx context.Context, blockNrOrHashes []rpc.BlockNumberOrHash, returnLogs bool) ([]map[string]interface{}, error) {
	resultArray := make([]map[string]interface{}, 0, len(blockNrOrHashes))
	for _, blockNrOrHash := range blockNrOrHashes {
		header, err := s.b.HeaderByNumberOrHash(ctx, blockNrOrHash)
		if err != nil {
			return nil, err
		}
		result := s.rpcMarshalCompactHeader(ctx, header)
		logs := s.chain.GetLogsWithHeader(header)
		result["logs"] = RPCMarshalCompactLogs(logs)

		resultArray = append(resultArray, result)
	}
	return resultArray, nil
}

// AccessListOnState Creates an access list on top of given state
// identical to AccessList, except state is loaded in arguments
func AccessListOnState(ctx context.Context, b Backend, header *types.Header, db *state.StateDB, args TransactionArgs) (acl types.AccessList, gasUsed uint64, vmErr error, err error) {
	// If the gas amount is not set, extract this as it will depend on access
	// lists and we'll need to reestimate every time
	nogas := args.Gas == nil

	// Ensure any missing fields are filled, extract the recipient and input data
	if err := args.setDefaults(ctx, b, true); err != nil {
		return nil, 0, nil, err
	}
	var to common.Address
	if args.To != nil {
		to = *args.To
	} else {
		to = crypto.CreateAddress(args.from(), uint64(*args.Nonce))
	}
	// Retrieve the precompiles since they don't need to be added to the access list
	isPostMerge := header.Difficulty.Cmp(common.Big0) == 0
	// Retrieve the precompiles since they don't need to be added to the access list
	precompiles := vm.ActivePrecompiles(b.ChainConfig().Rules(header.Number, isPostMerge, header.Time))

	// Create an initial tracer
	prevTracer := logger.NewAccessListTracer(nil, args.from(), to, precompiles)
	if args.AccessList != nil {
		prevTracer = logger.NewAccessListTracer(*args.AccessList, args.from(), to, precompiles)
	}
	for {
		// Retrieve the current access list to expand
		accessList := prevTracer.AccessList()
		log.Trace("Creating access list", "input", accessList)

		// If no gas amount was specified, each unique access list needs it's own
		// gas calculation. This is quite expensive, but we need to be accurate
		// and it's convered by the sender only anyway.
		if nogas {
			args.Gas = nil
			if err := args.setDefaults(ctx, b, true); err != nil {
				return nil, 0, nil, err // shouldn't happen, just in case
			}
		}

		statedb := db.Copy() // woops shouldn't have removed this lol
		// Set the accesslist to the last al
		args.AccessList = &accessList
		msg, err := args.ToMessage(b.RPCGasCap(), header.BaseFee)
		if err != nil {
			return nil, 0, nil, err
		}

		// Apply the transaction with the access list tracer
		tracer := logger.NewAccessListTracer(accessList, args.from(), to, precompiles)
		config := vm.Config{Tracer: tracer, NoBaseFee: true}
		vmenv := b.GetEVM(ctx, msg, statedb, header, &config, nil)
		res, err := core.ApplyMessage(vmenv, msg, new(core.GasPool).AddGas(msg.GasLimit))
		if err != nil {
			return nil, 0, nil, fmt.Errorf("failed to apply transaction: %v err: %v", args.toTransaction().Hash(), err)
		}
		if tracer.Equal(prevTracer) {
			return accessList, res.UsedGas, res.Err, nil
		}
		prevTracer = tracer
	}
}

// Multicall multicall makes multiple eth_calls, on one state set by the provided block and overrides.
// returns an array of results [{data: 0x...}], and errors per call tx. the entire call fails if the requested state couldnt be found or overrides failed to be applied
func (s *BlockChainAPI) Multicall(ctx context.Context, txs []TransactionArgs, blockNrOrHash rpc.BlockNumberOrHash, overrides *StateOverride) ([]map[string]interface{}, error) {
	var results []map[string]interface{}
	state, header, err := s.b.StateAndHeaderByNumberOrHash(ctx, blockNrOrHash)
	if state == nil || err != nil {
		return nil, err
	}
	if err := overrides.Apply(state); err != nil {
		return nil, err
	}
	for _, tx := range txs {
		thisState := state.Copy() // copy the state, because while eth_calls shouldnt change state, theres nothing stopping someobdy from making a state changing call
		results = append(results, DoSingleMulticall(ctx, s.b, tx, thisState, header, s.b.RPCEVMTimeout(), s.b.RPCGasCap()))
	}
	return results, nil
}

// DoSingleMulticall single multicall makes a single call, given a header and state
// returns an object containing the return data, or error if one occured
// the result should be merged together later by multicall function
func DoSingleMulticall(ctx context.Context, b Backend, args TransactionArgs, state *state.StateDB, header *types.Header, timeout time.Duration, globalGasCap uint64) map[string]interface{} {

	defer func(start time.Time) {
		log.Debug("Executing EVM call finished", "runtime", time.Since(start))
	}(time.Now())

	// Setup context so it may be cancelled the call has completed
	// or, in case of unmetered gas, set up a context with a timeout.
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	// Make sure the context is cancelled when the call has completed
	// this makes sure resources are cleaned up.
	defer cancel()

	// Get a new instance of the EVM.
	msg, err := args.ToMessage(globalGasCap, header.BaseFee)
	if err != nil {
		return map[string]interface{}{
			"error": err,
		}
	}
	blockCtx := core.NewEVMBlockContext(header, NewChainContext(ctx, b), nil)
	// if blockOverrides != nil {
	// 	blockOverrides.Apply(&blockCtx)
	// }
	evm := b.GetEVM(ctx, msg, state, header, &vm.Config{NoBaseFee: true}, &blockCtx)
	// Wait for the context to be done and cancel the evm. Even if the
	// EVM has finished, cancelling may be done (repeatedly)
	go func() {
		<-ctx.Done()
		evm.Cancel()
	}()

	// Execute the message.
	gp := new(core.GasPool).AddGas(math.MaxUint64)
	result, err := core.ApplyMessage(evm, msg, gp)
	if err := state.Error(); err != nil {
		return map[string]interface{}{
			"error": err,
		}
	}

	// If the timer caused an abort, return an appropriate error message
	if evm.Cancelled() {
		return map[string]interface{}{
			"error": fmt.Errorf("execution aborted (timeout = %v)", timeout),
		}
	}
	if err != nil {
		return map[string]interface{}{
			"error": fmt.Errorf("err: %w (supplied gas %d)", err, msg.GasLimit),
		}
	}
	if len(result.Revert()) > 0 {
		revertErr := newRevertError(result.Revert())
		data, _ := json.Marshal(&revertErr)
		var result map[string]interface{}
		json.Unmarshal(data, &result)
		return result
	}
	if result.Err != nil {
		return map[string]interface{}{
			"error": "execution reverted",
		}
	}
	return map[string]interface{}{
		"data": hexutil.Bytes(result.Return()),
	}
}
