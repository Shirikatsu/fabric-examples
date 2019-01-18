/*
Copyright Clearmatics Technologies Ltd. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package printer

import (
    "fmt"
    "math"
    "reflect"
    "encoding/hex"
    "encoding/asn1"

    "github.com/pkg/errors"
	fabriccmn "github.com/hyperledger/fabric-sdk-go/third_party/github.com/hyperledger/fabric/protos/common"
	pb "github.com/hyperledger/fabric-sdk-go/third_party/github.com/hyperledger/fabric/protos/peer"
	utils "github.com/hyperledger/fabric-sdk-go/third_party/github.com/hyperledger/fabric/protos/utils"
	"github.com/hyperledger/fabric-sdk-go/third_party/github.com/hyperledger/fabric/core/ledger/kvledger/txmgmt/rwsetutil"
	rlp "github.com/ethereum/go-ethereum/rlp"
	fabutil "github.com/hyperledger/fabric/common/util"
    "github.com/hyperledger/fabric/bccsp/factory"
)

type Encoder interface {
	// EncodeBlockIon outputs an Ion-compatible encoded block
	EncodeBlockIon(block *fabriccmn.Block) (string, error)
}

type encoder struct {
    Encoder
}

// NewEncoder returns a new encoder
func NewEncoder() Encoder {
    return &encoder{}
}

func (e *encoder) EncodeBlockIon(block *fabriccmn.Block) (string, error) {
    transactions := make([]interface{}, 0)

    for i := range block.Data.Data {
        payload := utils.ExtractPayloadOrPanic(utils.ExtractEnvelopeOrPanic(block, i))

        chdr, err := utils.UnmarshalChannelHeader(payload.Header.ChannelHeader)
        if err != nil {
            panic(err)
        }

        actions := make([]interface{}, 0)
        headerType := fabriccmn.HeaderType(chdr.Type)

        if headerType == fabriccmn.HeaderType_CONFIG {
            return "", errors.New("Config Block not yet supported")
        } else if headerType == fabriccmn.HeaderType_CONFIG_UPDATE {
            return "", errors.New("Config Block not yet supported")
        } else if headerType == fabriccmn.HeaderType_ENDORSER_TRANSACTION {
            tx, err := utils.GetTransaction(payload.Data)
            if err != nil {
                return "", errors.Errorf("Bad envelope: %v", err)
            }

            for _, action := range tx.Actions {
                chaPayload, err := utils.GetChaincodeActionPayload(action.Payload)
                if err != nil {
                    panic(err)
                }
                txAction := chaPayload.Action

                prp := &pb.ProposalResponsePayload{}
                unmarshalOrPanic(txAction.ProposalResponsePayload, prp)

                chaincodeAction := &pb.ChaincodeAction{}
                unmarshalOrPanic(prp.Extension, chaincodeAction)

                if len(chaincodeAction.Results) > 0 {
                    txRWSet := &rwsetutil.TxRwSet{}
                    if err := txRWSet.FromProtoBytes(chaincodeAction.Results); err != nil {
                        panic(err)
                    }
                    for _, nsRWSet := range txRWSet.NsRwSets {
                        readsets := make([]interface{}, 0)
                        writesets := make([]interface{}, 0)
                        for _, r := range nsRWSet.KvRwSet.Reads {
                            readsetKey := r.Key
                            readsetVersion := []uint64{}

                            readset := make([]interface{}, 0)
                            readset = append(readset, readsetKey)
                            if ReflectStructField(r, "Version") == nil && r.Version != nil {
                                if ReflectStructField(r.Version, "BlockNum") == nil {
                                    readsetVersion = append(readsetVersion, r.Version.BlockNum)
                                }
                                if ReflectStructField(r.Version, "TxNum") == nil {
                                    readsetVersion = append(readsetVersion, r.Version.TxNum)
                                }
                                readset = append(readset, readsetVersion)
                            }
                            readsets = append(readsets, readset)
                        }

                        for _, w := range nsRWSet.KvRwSet.Writes {
                            writesetKey := w.Key
                            writesetDelete := "false"
                            if w.IsDelete {
                                writesetDelete = "true"
                            }
                            writesetValue := string(w.Value[:])

                            writeset := make([]interface{}, 0)
                            writeset = append(writeset, writesetKey, writesetDelete, writesetValue)
                            writesets = append(writesets, writeset)
                        }

                        namespace := nsRWSet.NameSpace

                        action := make([]interface{}, 0)
                        action = append(action, namespace, readsets, writesets)
                        actions = append(actions, action)
                    }
                }
            }

            txId := chdr.TxId
            txn := make([]interface{}, 0)
            txn = append(txn, txId, actions)

            transactions = append(transactions, txn)
        } else {
            return "", errors.New("Unsupported Envelope")
        }
    }

    chdr, err := utils.UnmarshalChannelHeader(utils.ExtractPayloadOrPanic(utils.ExtractEnvelopeOrPanic(block, 0)).Header.ChannelHeader)
    if err != nil {
        return "", err
    }

    channelId := chdr.ChannelId

    block_no := block.Header.Number
    prev_hash := Base64URLEncode(block.Header.PreviousHash)
    data_hash := Base64URLEncode(block.Header.DataHash)

    block_hash := Base64URLEncode(hash(block.Header))

    timestamp := chdr.Timestamp

    // MUST CHANGE!! Casting int64/int32 to unsigned for initial PoC
    timestamp_s := uint64(timestamp.Seconds)
    timestamp_n := uint32(timestamp.Nanos)

    blk := make([]interface{}, 0)
    blk = append(blk, block_hash, block_no, prev_hash, data_hash, timestamp_s, timestamp_n, transactions)

    formattedBlock := make([]interface{}, 0)
    formattedBlock = append(formattedBlock, channelId, blk)

    fmt.Println(formattedBlock)

    encodedBlock, err := rlp.EncodeToBytes(formattedBlock)
    if err != nil {
        return "", err
    }

    return hex.EncodeToString(encodedBlock), nil
}

func hash(b *fabriccmn.BlockHeader) []byte {
    factory.InitFactories(nil);
    return fabutil.ComputeSHA256(Bytes(b))
}

type asn1Header struct {
	Number       int64
	PreviousHash []byte
	DataHash     []byte
}

func Bytes(b *fabriccmn.BlockHeader) []byte {
	asn1Header := asn1Header{
		PreviousHash: b.PreviousHash,
		DataHash:     b.DataHash,
	}
	if b.Number > uint64(math.MaxInt64) {
		panic(fmt.Errorf("Golang does not currently support encoding uint64 to asn1"))
	} else {
		asn1Header.Number = int64(b.Number)
	}
	result, err := asn1.Marshal(asn1Header)
	if err != nil {
		// Errors should only arise for types which cannot be encoded, since the
		// BlockHeader type is known a-priori to contain only encodable types, an
		// error here is fatal and should not be propogated
		panic(err)
	}
	return result
}

func ReflectStructField(Iface interface{}, FieldName string) error {
	ValueIface := reflect.ValueOf(Iface)

	// Check if the passed interface is a pointer
	if ValueIface.Type().Kind() != reflect.Ptr {
		// Create a new type of Iface's Type, so we have a pointer to work with
		ValueIface = reflect.New(reflect.TypeOf(Iface))
	}

	// 'dereference' with Elem() and get the field by name
	Field := ValueIface.Elem().FieldByName(FieldName)
	if !Field.IsValid() {
		return fmt.Errorf("Interface `%s` does not have the field `%s`", ValueIface.Type(), FieldName)
	}
	return nil
}