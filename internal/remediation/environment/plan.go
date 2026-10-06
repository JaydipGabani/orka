package environment

import (
	"bytes"
	"encoding/json"
	"io"
	"net/url"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// DecodePlan rejects unknown and duplicate fields, trailing JSON, and oversized
// documents before it allocates executor resources. Admission against Config is
// performed by FreezePlan.
func DecodePlan(reader io.Reader) (Plan, error) {
	var p Plan
	data, err := readBounded(reader, 256<<10)
	if err != nil || rejectDuplicateJSON(data) != nil {
		return p, failure(NeedsAdapter, "invalid-plan-json")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&p) != nil {
		return Plan{}, failure(NeedsAdapter, "invalid-plan-json")
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return Plan{}, failure(NeedsAdapter, "invalid-plan-json")
	}
	return p, nil
}

func rejectDuplicateJSON(data []byte) error {
	d := json.NewDecoder(bytes.NewReader(data))
	var value func(int) error
	value = func(depth int) error {
		if depth > 32 {
			return failure(NeedsAdapter, "plan-json-depth")
		}
		token, err := d.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				text, ok := key.(string)
				if err != nil || !ok || seen[strings.ToLower(text)] {
					return failure(NeedsAdapter, "duplicate-plan-field")
				}
				seen[strings.ToLower(text)] = true
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		default:
			return failure(NeedsAdapter, "invalid-plan-json")
		}
		_, err = d.Token()
		return err
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return failure(NeedsAdapter, "invalid-plan-json")
	}
	return nil
}

// ChecksDigest is a versioned, domain-separated identity of the complete
// declarative observation contract, including source and recipe bindings.
func ChecksDigest(p Plan) string {
	p.Bind.ChecksDigest = ""
	return jsonDigest(struct {
		Domain string `json:"domain"`
		Plan   Plan   `json:"plan"`
	}{"orka.remediation.environment.plan.v1", p})
}

func (a *Adapter) FreezePlan(p Plan) (Plan, error) {
	data, err := json.Marshal(p)
	if err != nil || int64(len(data)) > a.config.Limits.MaxPlanBytes {
		return Plan{}, failure(NeedsAdapter, "plan-size-limit")
	}
	p, err = DecodePlan(bytes.NewReader(data))
	if err != nil {
		return Plan{}, err
	}
	if err := a.validatePlan(p); err != nil {
		return Plan{}, err
	}
	expected := ChecksDigest(p)
	if p.Bind.ChecksDigest != "" && p.Bind.ChecksDigest != expected {
		return Plan{}, failure(NeedsAdapter, "checks-digest-mismatch")
	}
	p.Bind.ChecksDigest = expected
	return p, nil
}

func (a *Adapter) validateFrozen(p Plan) error {
	if !digestPattern.MatchString(p.Bind.ChecksDigest) || ChecksDigest(p) != p.Bind.ChecksDigest {
		return failure(NeedsAdapter, "frozen-checks-required")
	}
	data, err := json.Marshal(p)
	if err != nil || int64(len(data)) > a.config.Limits.MaxPlanBytes {
		return failure(NeedsAdapter, "plan-size-limit")
	}
	return a.validatePlan(p)
}

func (a *Adapter) policy(b Bind) (*RepositoryPolicy, *RecipePolicy, error) {
	approved, err := a.BindRecipe(b.SourceTarget, b.Recipe.ID)
	if err != nil || approved.Recipe != b.Recipe {
		return nil, nil, failure(NeedsAdapter, "unapproved-source-or-recipe")
	}
	for _, repo := range a.config.Repositories {
		if repo.URL != b.SourceTarget.Repository {
			continue
		}
		for _, recipe := range repo.Recipes {
			expected := RecipeIdentity{
				ID: recipe.ID, Repository: repo.RecipeRepository, Commit: recipe.Commit,
				Path: recipe.Path, ContentDigest: recipe.Files[recipe.Path],
				Target: recipe.Target, Platform: recipe.Platform,
				FrontendImage: recipe.FrontendImage, WorkerImage: recipe.WorkerImage,
			}
			if expected == b.Recipe {
				return &repo, &recipe, nil
			}
		}
	}
	return nil, nil, failure(NeedsAdapter, "unapproved-source-or-recipe")
}

func (a *Adapter) validatePlan(p Plan) error {
	if p.ExternalObservation != nil {
		return failure(NeedsAdapter, "external-observation-is-build-only")
	}
	repo, _, err := a.policy(p.Bind)
	if err != nil {
		return err
	}
	l := a.config.Limits
	if p.Version != Version || !commitPattern.MatchString(p.Bind.SourceTarget.Commit) ||
		len(p.Namespaces) == 0 || len(p.Namespaces) > l.MaxNamespaces ||
		len(p.Resources) == 0 || len(p.Resources) > l.MaxResources ||
		len(p.Checks) == 0 || len(p.Checks) > l.MaxChecks {
		return failure(NeedsAdapter, "invalid-plan-bounds")
	}
	resources, err := a.validateResources(p, *repo)
	if err != nil {
		return err
	}
	return a.validateChecks(p.Checks, resources, *repo)
}

func (a *Adapter) validateResources(p Plan, repo RepositoryPolicy) (map[string]bool, error) {
	namespaces := map[string]bool{}
	for _, ns := range p.Namespaces {
		if !idPattern.MatchString(ns.Alias) || namespaces[ns.Alias] {
			return nil, failure(NeedsAdapter, "invalid-namespace-alias")
		}
		namespaces[ns.Alias] = true
	}
	resources := map[string]bool{}
	for _, r := range p.Resources {
		if !idPattern.MatchString(r.ID) || resources[r.ID] || !namespaces[r.Namespace] ||
			!slices.Contains(a.config.AllowedGVKs, r.GVK) {
			return nil, failure(NeedsAdapter, "unapproved-resource")
		}
		if r.GVK.Group != "" || r.GVK.Version != "v1" || r.GVK.Kind != podKind || r.HTTP == nil {
			return nil, failure(NeedsAdapter, "resource-primitive-unavailable")
		}
		if !slices.Contains(repo.HTTPPorts, r.HTTP.Port) {
			return nil, failure(NeedsAdapter, "unapproved-http-port")
		}
		resources[r.ID] = true
	}
	return resources, nil
}

func (a *Adapter) validateChecks(selected []Check, resources map[string]bool, repo RepositoryPolicy) error {
	checks := map[string]bool{}
	classes := map[CheckClass]bool{}
	normalResources := map[string]bool{}
	for _, check := range selected {
		if !idPattern.MatchString(check.ID) || checks[check.ID] ||
			(check.Class != Reproduction && check.Class != Normal) ||
			!slices.Contains(repo.CheckCapabilities, check.Capability) {
			return failure(NeedsAdapter, "unapproved-check")
		}
		if check.Capability != HTTPExact || check.HTTP == nil || check.Event != nil {
			return failure(NeedsAdapter, "check-primitive-unavailable")
		}
		probe := check.HTTP
		if probe.Protocol != "http" {
			return failure(NeedsAdapter, "fresh-tls-adapter-required")
		}
		if !resources[probe.Resource] || !validHTTPProbe(*probe, check.Class, a.config.Limits.MaxBodyBytes) {
			return failure(NeedsAdapter, "invalid-http-check")
		}
		checks[check.ID], classes[check.Class] = true, true
		if check.Class == Normal {
			normalResources[probe.Resource] = true
		}
	}
	if !classes[Reproduction] || !classes[Normal] {
		return failure(NeedsAdapter, "reproduction-and-normal-checks-required")
	}
	for _, check := range selected {
		if check.Class == Reproduction && !normalResources[check.HTTP.Resource] {
			return failure(NeedsAdapter, "paired-normal-check-required")
		}
	}
	return nil
}

func validHTTPProbe(probe HTTPProbe, class CheckClass, maxBodyBytes int64) bool {
	if probe.ExpectedStatus != 0 || probe.ExpectedBody != "" || !probePath(probe.Path) ||
		!validHTTPExpectation(probe.Healthy, maxBodyBytes) {
		return false
	}
	if class == Normal {
		return probe.Failure == nil
	}
	return probe.Failure != nil && validHTTPExpectation(*probe.Failure, maxBodyBytes) &&
		*probe.Failure != probe.Healthy
}

func validHTTPExpectation(expected HTTPExpectation, maxBodyBytes int64) bool {
	return expected.Status >= 200 && expected.Status <= 599 &&
		int64(len(expected.Body)) <= maxBodyBytes && utf8.ValidString(expected.Body) &&
		!secretPattern.MatchString(expected.Body) && !strings.ContainsFunc(expected.Body, func(r rune) bool {
		return unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t'
	})
}

func probePath(value string) bool {
	u, err := url.ParseRequestURI(value)
	return err == nil && len(value) <= 256 && strings.HasPrefix(value, "/") &&
		!strings.HasPrefix(value, "//") && !strings.Contains(value, "..") &&
		u.Scheme == "" && u.Host == "" && u.RawQuery == "" && u.Fragment == "" &&
		!strings.ContainsAny(value, "?#\\\r\n\x00")
}
