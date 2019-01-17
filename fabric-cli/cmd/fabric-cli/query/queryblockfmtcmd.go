/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package query

import (
	"github.com/hyperledger/fabric-sdk-go/pkg/client/ledger"
	fabricCommon "github.com/hyperledger/fabric-sdk-go/third_party/github.com/hyperledger/fabric/protos/common"
	"github.com/pkg/errors"
	"github.com/Shirikatsu/fabric-examples/fabric-cli/cmd/fabric-cli/action"
	cliconfig "github.com/Shirikatsu/fabric-examples/fabric-cli/cmd/fabric-cli/config"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var queryBlockFmtCmd = &cobra.Command{
	Use:   "block_formatted",
	Short: "Query formatted block",
	Long:  "Queries a block formatted for ion submission",
	Run: func(cmd *cobra.Command, args []string) {
		action, err := newQueryBlockFmtAction(cmd.Flags())
		if err != nil {
			cliconfig.Config().Logger().Errorf("Error while initializing queryBlockFmtAction: %v", err)
			return
		}

		defer action.Terminate()

		err = action.invoke()
		if err != nil {
			cliconfig.Config().Logger().Errorf("Error while running queryBlockFmtAction: %v", err)
		}
	},
}

func getQueryBlockFmtCmd() *cobra.Command {
	flags := queryBlockFmtCmd.Flags()
	cliconfig.InitChannelID(flags)
	cliconfig.InitBlockNum(flags)
	cliconfig.InitBlockHash(flags)
	cliconfig.InitTraverse(flags)
	cliconfig.InitPeerURL(flags, "", "The URL of the peer on which to install the chaincode, e.g. grpcs://localhost:7051")
	return queryBlockFmtCmd
}

type queryBlockFmtAction struct {
	action.Action
}

func newQueryBlockFmtAction(flags *pflag.FlagSet) (*queryBlockFmtAction, error) {
	action := &queryBlockFmtAction{}
	err := action.Initialize(flags)
	return action, err
}

func (a *queryBlockFmtAction) invoke() error {
	ledgerClient, err := a.LedgerClient()
	if err != nil {
		return errors.Errorf("Error getting admin channel client: %v", err)
	}

	var block *fabricCommon.Block
	if cliconfig.IsFlagSet(cliconfig.BlockNumFlag) {
		var err error
		block, err = ledgerClient.QueryBlock(cliconfig.Config().BlockNum())
		if err != nil {
			return err
		}
	} else if cliconfig.IsFlagSet(cliconfig.BlockHashFlag) {
		var err error

		hashBytes, err := Base64URLDecode(cliconfig.Config().BlockHash())
		if err != nil {
			return err
		}

		block, err = ledgerClient.QueryBlockByHash(hashBytes)
		if err != nil {
			return err
		}
	} else {
		return errors.Errorf("must specify either a block number of a block hash")
	}

	a.Printer().PrintFormattedBlock(block)

	a.traverse(ledgerClient, block, cliconfig.Config().Traverse()-1)

	return nil
}

func (a *queryBlockFmtAction) traverse(ledgerClient *ledger.Client, currentBlock *fabricCommon.Block, num int) error {
	if num <= 0 {
		return nil
	}

	block, err := ledgerClient.QueryBlockByHash(currentBlock.Header.PreviousHash)
	if err != nil {
		return err
	}

	a.Printer().PrintBlock(block)

	if block.Header.PreviousHash != nil {
		return a.traverse(ledgerClient, block, num-1)
	}
	return nil
}