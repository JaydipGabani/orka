package lab

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"slices"
)

// Bridge executes only the exact human-approved driver/configuration profile.
// Approval is a caller authorization assertion, not something a model may grant.
// Its private run root must not be exposed to candidate code or model tools.
// Independent run names may be used concurrently; one name is consumed forever.
type Bridge struct {
	profile Profile
	digest  string
	root    string
	rootID  directoryID
}

func New(profile Profile, privateRunsDir, approvedProfileDigest string) (*Bridge, error) {
	profileDigest, err := DigestProfile(profile)
	if err != nil {
		return nil, err
	}
	if profileDigest != approvedProfileDigest {
		return nil, ErrApproval
	}
	identity, err := inspectRoot(privateRunsDir)
	if err != nil {
		return nil, err
	}
	if _, _, err := readProfileFiles(profile); err != nil {
		return nil, err
	}
	profile.Scope, profile.Gaps = slices.Clone(profile.Scope), slices.Clone(profile.Gaps)
	return &Bridge{profile: profile, digest: profileDigest, root: privateRunsDir, rootID: identity}, nil
}

func (bridge *Bridge) Baseline(ctx context.Context, name string) (Receipt, error) {
	return bridge.run(ctx, name, nil, nil)
}

// Verify requires the exact old baseline receipt, re-read from private storage.
// Candidate supplies an inert patch and an optional expected image. Omitting the
// image delegates build-and-verify to the approved driver, not to model code.
func (bridge *Bridge) Verify(ctx context.Context, name string, baseline Receipt, candidate Candidate) (Receipt, error) {
	if bridge == nil || baseline.State != BaselineReady || baseline.Operation != OperationBaseline ||
		baseline.Result == nil || baseline.ProfileDigest != bridge.digest {
		return Receipt{}, ErrBaseline
	}
	stored, err := bridge.ReadReceipt(baseline.Name)
	if err != nil || !reflect.DeepEqual(stored, baseline) {
		return Receipt{}, ErrBaseline
	}
	if !validFileIdentity(candidate.Patch) ||
		!validExpectedImage(candidate.Image, stored.Result.Original.Image, stored.Result.Control.Image) ||
		candidate.Patch.Path == bridge.profile.Driver.Path || candidate.Patch.Path == bridge.profile.Configuration.Path {
		return Receipt{}, ErrInvalidInput
	}
	return bridge.run(ctx, name, stored.Result, &candidate)
}

func (bridge *Bridge) run(ctx context.Context, name string, baseline *Result, candidate *Candidate) (receipt Receipt, resultErr error) {
	if bridge == nil || ctx == nil || !namePattern.MatchString(name) {
		return Receipt{}, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return Receipt{}, err
	}
	driver, configuration, err := readProfileFiles(bridge.profile)
	if err != nil {
		return Receipt{}, err
	}
	var patch []byte
	if candidate != nil {
		patch, err = readApproved(candidate.Patch, MaxPatchBytes, false)
		if err != nil {
			return Receipt{}, err
		}
		if len(patch) == 0 {
			return Receipt{}, ErrInvalidInput
		}
	}
	disk, err := bridge.openRun(name, true)
	if err != nil {
		return Receipt{}, err
	}
	defer disk.close()
	request := bridge.request(name, disk.path, baseline, candidate)
	requestBytes, err := encode(request, MaxRequestBytes)
	if err != nil {
		return Receipt{}, err
	}
	receipt = Receipt{
		Version: Version, Name: name, Operation: request.Operation,
		ProfileDigest: bridge.digest, RequestDigest: digest(requestBytes),
		State: Unknown, TrustStatement: TrustStatement,
	}
	defer func() {
		if resultErr != nil && !errors.Is(resultErr, ErrBlocked) {
			receipt.State, receipt.Result, receipt.ResultDigest = Unknown, nil, ""
		}
		if err := saveReceipt(disk, receipt); err != nil {
			receipt.State, receipt.Result, receipt.ResultDigest = Unknown, nil, ""
			resultErr = errors.Join(ErrUnknown, err)
		}
	}()
	if err := prepareRun(disk, requestBytes, receipt, driver, configuration, patch); err != nil {
		return receipt, err
	}
	output, err := runDriver(ctx, disk, request.Operation)
	if err != nil {
		return receipt, err
	}
	if err := bridge.recheckInputs(request); err != nil {
		return receipt, err
	}
	storedRequest, err := disk.read("request.json", MaxRequestBytes)
	if err != nil || digest(storedRequest) != receipt.RequestDigest {
		return receipt, ErrDigestMismatch
	}
	var result Result
	if err := decodeStrict(output, MaxResultBytes, &result); err != nil {
		return receipt, ErrInvalidResult
	}
	if err := validateResultShape(result); err != nil {
		return receipt, err
	}
	resultErr = validateResult(request, receipt.RequestDigest, result)
	if resultErr != nil && !errors.Is(resultErr, ErrBlocked) {
		return receipt, resultErr
	}
	if err := disk.write("result.json", output, 0600); err != nil {
		return receipt, err
	}
	receipt.Result, receipt.ResultDigest = &result, digest(output)
	receipt.State = BaselineReady
	if request.Operation == OperationVerify {
		receipt.State = Verified
	}
	if resultErr != nil {
		receipt.State = Blocked
	}
	return receipt, resultErr
}

func (bridge *Bridge) request(name, runPath string, baseline *Result, candidate *Candidate) Request {
	request := Request{
		Version: Version, Name: name, Operation: OperationBaseline, ProfileDigest: bridge.digest,
		Profile: bridge.profile, Baseline: baseline,
		Configuration: FileIdentity{Path: filepath.Join(runPath, "configuration"), Digest: bridge.profile.Configuration.Digest},
	}
	if candidate != nil {
		request.Operation = OperationVerify
		request.Candidate = &Candidate{
			Patch: FileIdentity{Path: filepath.Join(runPath, "candidate.patch"), Digest: candidate.Patch.Digest},
			Image: candidate.Image,
		}
	}
	return request
}

func readProfileFiles(profile Profile) ([]byte, []byte, error) {
	driver, err := readApproved(profile.Driver, MaxDriverBytes, true)
	if err != nil {
		return nil, nil, err
	}
	configuration, err := readApproved(profile.Configuration, MaxConfigurationBytes, false)
	if err != nil {
		return nil, nil, err
	}
	if len(driver) == 0 || len(configuration) == 0 {
		return nil, nil, ErrInvalidInput
	}
	return driver, configuration, nil
}

func prepareRun(disk *runDisk, request []byte, receipt Receipt, driver, configuration, patch []byte) error {
	record := intent{
		Version: Version, Name: receipt.Name, Operation: receipt.Operation,
		ProfileDigest: receipt.ProfileDigest, RequestDigest: receipt.RequestDigest,
	}
	intentBytes, err := encode(record, MaxProfileBytes)
	if err != nil {
		return err
	}
	for _, file := range []struct {
		name string
		data []byte
		mode uint32
	}{
		{"intent.json", intentBytes, 0600},
		{"driver", driver, 0500},
		{"configuration", configuration, 0400},
		{"request.json", request, 0400},
	} {
		if err := disk.write(file.name, file.data, file.mode); err != nil {
			return err
		}
	}
	if patch != nil {
		return disk.write("candidate.patch", patch, 0400)
	}
	return nil
}

func saveReceipt(disk *runDisk, receipt Receipt) error {
	content, err := encode(receipt, MaxReceiptBytes)
	if err != nil {
		return err
	}
	return disk.write("receipt.json", content, 0600)
}

func (bridge *Bridge) recheckInputs(request Request) error {
	if _, _, err := readProfileFiles(bridge.profile); err != nil {
		return err
	}
	directory := filepath.Dir(request.Configuration.Path)
	for _, input := range []struct {
		file       FileIdentity
		limit      int
		executable bool
	}{
		{FileIdentity{Path: filepath.Join(directory, "driver"), Digest: bridge.profile.Driver.Digest}, MaxDriverBytes, true},
		{request.Configuration, MaxConfigurationBytes, false},
	} {
		if _, err := readApproved(input.file, input.limit, input.executable); err != nil {
			return err
		}
	}
	if request.Candidate != nil {
		if _, err := readApproved(request.Candidate.Patch, MaxPatchBytes, false); err != nil {
			return err
		}
	}
	return nil
}
