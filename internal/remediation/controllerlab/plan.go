package controllerlab

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"regexp"
	"slices"
	"strings"
)

var (
	digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
	commitPattern = regexp.MustCompile(`^[a-f0-9]{40}$`)
	idPattern     = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)
	imagePattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9./:_-]*@sha256:[a-f0-9]{64}$`)
)

func digest(value any) string {
	data, _ := json.Marshal(value)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func bytesDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func imageContentDigest(image string) string {
	_, value, _ := strings.Cut(image, "@sha256:")
	return value
}

// PlanDigest is a versioned identity of the entire semantic contract, including
// the public source and opaque operator recipe. Slice order is canonicalized.
func PlanDigest(p Plan) string {
	p.Actors = slices.Clone(p.Actors)
	p.Expected = slices.Clone(p.Expected)
	slices.Sort(p.Actors)
	slices.Sort(p.Expected)
	return digest(struct {
		Domain string
		Plan   Plan
	}{"orka.controllerlab.plan.v1", p})
}

// DecodePlan rejects duplicate/case-folded keys as well as unknown fields; the
// typed Go API is validated again by Step.
func DecodePlan(r io.Reader) (Plan, error) {
	var result Plan
	data, err := io.ReadAll(io.LimitReader(r, 16*1024+1))
	if err != nil || len(data) > 16*1024 || strictJSON(data, &result) != nil {
		return Plan{}, failure(NeedsAdapter, "invalid-plan-json")
	}
	return result, nil
}

func strictJSON(data []byte, result any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 20 {
			return failure(NeedsAdapter, "json-depth")
		}
		token, err := d.Token()
		if err != nil {
			return err
		}
		if delimiter, ok := token.(json.Delim); ok {
			switch delimiter {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					key, err := d.Token()
					text, ok := key.(string)
					if err != nil || !ok || seen[strings.ToLower(text)] {
						return failure(NeedsAdapter, "duplicate-json-field")
					}
					seen[strings.ToLower(text)] = true
					if err := walk(depth + 1); err != nil {
						return err
					}
				}
			case '[':
				for d.More() {
					if err := walk(depth + 1); err != nil {
						return err
					}
				}
			default:
				return failure(NeedsAdapter, "invalid-json")
			}
			_, err = d.Token()
			return err
		}
		return nil
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return failure(NeedsAdapter, "trailing-json")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode(result)
}

func (a *Adapter) validateRequest(r Request) (ImageBinding, error) {
	if !idPattern.MatchString(r.RunID) || !idPattern.MatchString(r.OperationID) {
		return ImageBinding{}, failure(NeedsAdapter, "invalid-run-identity")
	}
	p := r.Plan
	if err := ValidatePlan(p); err != nil {
		return ImageBinding{}, err
	}
	if p.BoundSource != a.config.Template.Source || p.RecipeID != a.config.Template.RecipeID ||
		(p.Capability == KEDAEventPublishing && !a.config.EnableEventPublishing) {
		return ImageBinding{}, failure(NeedsAdapter, "unsupported-controller-contract")
	}
	for _, binding := range a.config.Bindings {
		if binding.ID == r.BindingID {
			return binding, nil
		}
	}
	return ImageBinding{}, failure(NeedsAdapter, "unapproved-image-binding")
}

// ValidatePlan checks the immutable semantic surface without authorizing
// execution. Step additionally requires the matching operator config/binding.
func ValidatePlan(p Plan) error {
	if slices.Contains(p.Expected, SemanticOutcome("managed-aks-policy")) {
		return failure(OutsideScope, "managed-cloud-policy-not-represented")
	}
	if p.Version != Version || p.BoundSource.Repository != "https://github.com/kedacore/keda" ||
		!commitPattern.MatchString(p.BoundSource.Commit) || !idPattern.MatchString(p.RecipeID) {
		return failure(NeedsAdapter, "unsupported-controller-contract")
	}
	expected := []SemanticOutcome{NamespacedEventScope}
	switch p.Capability {
	case KEDANamespaceEvents:
	case KEDAEventPublishing:
		if p.BoundSource.Commit != kedaPublishingCommit {
			return failure(NeedsAdapter, "unsupported-publishing-source")
		}
		expected = append(expected, NamespacedEventCredentialScope, UndelegatedClusterCredentialScope)
	default:
		return failure(NeedsAdapter, "unsupported-controller-contract")
	}
	actors, outcomes := slices.Clone(p.Actors), slices.Clone(p.Expected)
	slices.Sort(actors)
	slices.Sort(outcomes)
	slices.Sort(expected)
	if !slices.Equal(actors, []ActorAccess{NamespaceAEventSource, NamespaceBEventSource}) ||
		!slices.Equal(outcomes, expected) {
		return failure(NeedsAdapter, "unsupported-actor-or-outcome")
	}
	return nil
}

func SupportedCapabilities() []Capability {
	return []Capability{KEDANamespaceEvents, KEDAEventPublishing}
}

// Compare is intentionally separate from a single candidate observation. A
// protected candidate is insufficient without positive original AND rebuilt
// control reproduction, the same semantic plan, and complete exact-UID cleanup.
func Compare(original, control, candidate State) error {
	states := []State{original, control, candidate}
	roles := []Role{Original, Control, Candidate}
	outcomes := []Outcome{Reproduced, Reproduced, Protected}
	operations := map[string]bool{}
	for i, state := range states {
		if state.Version != Version || state.Phase != Complete || state.Role != roles[i] ||
			state.Outcome != outcomes[i] || state.PlanDigest != original.PlanDigest ||
			state.Capability != original.Capability ||
			state.ConfigDigest != original.ConfigDigest || state.RunID != original.RunID ||
			!digestPattern.MatchString(state.OperationDigest) || operations[state.OperationDigest] ||
			state.Intent != nil || len(state.Receipts) == 0 ||
			!completedNamespaceBoundary(state) ||
			state.Evidence.InitialNormal != [2]bool{true, true} {
			return failure(InvalidState, "comparison-evidence-incomplete")
		}
		if err := completedPublishingEvidence(state); err != nil {
			return err
		}
		operations[state.OperationDigest] = true
		for _, receipt := range state.Receipts {
			if receipt.Object.UID == "" || !receipt.Deleted || !receipt.DeleteRequested {
				return failure(InvalidState, "comparison-cleanup-incomplete")
			}
		}
	}
	if !original.Evidence.CrossObserved || !control.Evidence.CrossObserved ||
		candidate.Evidence.CrossObserved || candidate.Evidence.FinalNormal != [2]bool{true, true} ||
		candidate.WindowStartedAt.IsZero() || candidate.TailStartedAt.IsZero() {
		return failure(InvalidState, "comparison-semantic-evidence-incomplete")
	}
	if publishing(candidate) && (candidate.ImageDigest == original.ImageDigest || candidate.ImageDigest == control.ImageDigest) {
		return failure(InvalidState, "comparison-candidate-image-unchanged")
	}
	return nil
}

func completedNamespaceBoundary(s State) bool {
	if !validPlacement(s.Placement, s.OperationDigest) || s.SubjectStartedAt.IsZero() {
		return false
	}
	if s.ObserverNamespace == "" || s.ObserverNamespace == s.Namespaces[0] ||
		s.ObserverNamespace == s.Namespaces[1] || s.Namespaces[0] == s.Namespaces[1] {
		return false
	}
	if !privateObserverIP(s.ObserverPodIP) || !digestPattern.MatchString(s.ObserverImageDigest) {
		return false
	}
	for _, namespace := range ownedNamespaces(s) {
		receipt := receiptFor(s, ref(namespaces, "", namespace))
		if receipt == nil || receipt.Object.UID == "" || !receipt.Deleted || !receipt.DeleteRequested {
			return false
		}
	}
	return true
}
