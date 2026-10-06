package lab

import (
	"errors"
	"path/filepath"
	"reflect"
)

// ReadReceipt never executes a driver or repairs/retries an incomplete run.
// An absent or unknown final receipt requires explicit operator reconciliation.
func (bridge *Bridge) ReadReceipt(name string) (Receipt, error) {
	disk, err := bridge.openRun(name, false)
	if err != nil {
		return Receipt{}, err
	}
	defer disk.close()
	exists, err := disk.hasReceipt()
	if err != nil {
		return Receipt{}, err
	}
	if !exists {
		return Receipt{
			Version: Version, Name: name, ProfileDigest: bridge.digest, State: Unknown, TrustStatement: TrustStatement,
		}, ErrUnknown
	}
	receiptBytes, err := disk.read("receipt.json", MaxReceiptBytes)
	if err != nil {
		return Receipt{}, err
	}
	var receipt Receipt
	if err := decodeStrict(receiptBytes, MaxReceiptBytes, &receipt); err != nil {
		return Receipt{}, err
	}
	if receipt.Version != Version || receipt.Name != name || receipt.ProfileDigest != bridge.digest ||
		receipt.TrustStatement != TrustStatement || !digestPattern.MatchString(receipt.RequestDigest) ||
		(receipt.Operation != OperationBaseline && receipt.Operation != OperationVerify) {
		return Receipt{}, ErrUnknown
	}
	if receipt.State == Unknown {
		if receipt.Result != nil || receipt.ResultDigest != "" {
			return Receipt{}, ErrUnknown
		}
		return receipt, ErrUnknown
	}
	request, err := bridge.readRequest(disk, receipt)
	if err != nil {
		return Receipt{}, err
	}
	if err := readIntent(disk, request, receipt); err != nil {
		return Receipt{}, err
	}
	result, err := readResult(disk, receipt)
	if err != nil {
		return Receipt{}, err
	}
	validationErr := validateResult(request, receipt.RequestDigest, result)
	if receipt.State == Blocked && errors.Is(validationErr, ErrBlocked) {
		return receipt, ErrBlocked
	}
	if validationErr != nil || (receipt.State != BaselineReady && receipt.State != Verified) ||
		(receipt.State == BaselineReady && request.Operation != OperationBaseline) ||
		(receipt.State == Verified && request.Operation != OperationVerify) {
		return Receipt{}, ErrUnknown
	}
	return receipt, nil
}

func readIntent(disk *runDisk, request Request, receipt Receipt) error {
	var record intent
	intentBytes, err := disk.read("intent.json", MaxProfileBytes)
	if err != nil {
		return err
	}
	if err := decodeStrict(intentBytes, MaxProfileBytes, &record); err != nil {
		return err
	}
	if record != (intent{
		Version: Version, Name: request.Name, Operation: request.Operation,
		ProfileDigest: request.ProfileDigest, RequestDigest: receipt.RequestDigest,
	}) {
		return ErrUnknown
	}
	return nil
}

func readResult(disk *runDisk, receipt Receipt) (Result, error) {
	resultBytes, err := disk.read("result.json", MaxResultBytes)
	if err != nil {
		return Result{}, err
	}
	var result Result
	if err := decodeStrict(resultBytes, MaxResultBytes, &result); err != nil {
		return Result{}, err
	}
	if receipt.Result == nil || !reflect.DeepEqual(result, *receipt.Result) ||
		digest(resultBytes) != receipt.ResultDigest || validateResultShape(result) != nil {
		return Result{}, ErrUnknown
	}
	return result, nil
}

func (bridge *Bridge) readRequest(disk *runDisk, receipt Receipt) (Request, error) {
	content, err := disk.read("request.json", MaxRequestBytes)
	if err != nil {
		return Request{}, err
	}
	var request Request
	if err := decodeStrict(content, MaxRequestBytes, &request); err != nil {
		return Request{}, err
	}
	if digest(content) != receipt.RequestDigest || request.Version != Version ||
		request.Name != receipt.Name || request.Operation != receipt.Operation ||
		request.ProfileDigest != bridge.digest || !reflect.DeepEqual(request.Profile, bridge.profile) ||
		request.Configuration != (FileIdentity{
			Path: filepath.Join(disk.path, "configuration"), Digest: bridge.profile.Configuration.Digest,
		}) {
		return Request{}, ErrUnknown
	}
	switch request.Operation {
	case OperationBaseline:
		if request.Candidate != nil || request.Baseline != nil {
			return Request{}, ErrUnknown
		}
	case OperationVerify:
		if request.Candidate == nil || request.Baseline == nil ||
			request.Candidate.Patch.Path != filepath.Join(disk.path, "candidate.patch") ||
			!digestPattern.MatchString(request.Candidate.Patch.Digest) ||
			validateResultShape(*request.Baseline) != nil {
			return Request{}, ErrUnknown
		}
		original := Request{Version: Version, Operation: OperationBaseline, Profile: bridge.profile}
		if validateResult(original, request.Baseline.RequestDigest, *request.Baseline) != nil ||
			!validExpectedImage(request.Candidate.Image, request.Baseline.Original.Image, request.Baseline.Control.Image) {
			return Request{}, ErrUnknown
		}
	default:
		return Request{}, ErrUnknown
	}
	return request, nil
}
