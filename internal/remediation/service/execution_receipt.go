package service

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/orka-agents/orka/internal/remediation/environment"
	"github.com/orka-agents/orka/internal/store"
)

func executionReceiptName(operationID string) string {
	return "execution-accepted-" + strings.TrimPrefix(Digest([]byte(operationID)), "sha256:")[:24] + ".json"
}

func (p *Pipeline) persistExecutionReceipt(ctx context.Context, session *Session, receipt environment.Receipt) error {
	name := executionReceiptName(receipt.Request.OperationID)
	_, existing, err := session.Read(ctx, name)
	if err == nil {
		var previous environment.Receipt
		if json.Unmarshal(existing, &previous) != nil || previous.OperationDigest != receipt.OperationDigest {
			return ErrInvalid
		}
		return nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	raw, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	_, err = session.Put(ctx, name, "application/json", raw)
	return err
}

func readExecutionReceipt(ctx context.Context, session *Session, operationID, runID string) (*environment.Receipt, error) {
	_, raw, err := session.Read(ctx, executionReceiptName(operationID))
	if err != nil {
		return nil, err
	}
	var receipt environment.Receipt
	if json.Unmarshal(raw, &receipt) != nil || receipt.Request.OperationID != operationID || receipt.Request.RunID != runID {
		return nil, ErrInvalid
	}
	return &receipt, nil
}
