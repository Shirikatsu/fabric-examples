/*
Copyright Clearmatics Technologies Ltd. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package printer

import (
	"fmt"
	"strings"
	fabriccmn "github.com/hyperledger/fabric-sdk-go/third_party/github.com/hyperledger/fabric/protos/common"
)

func (p *displayFormatter) encodeBlockIon(block *fabriccmn.Block) (string, error) {
	return block.ChannelId
}