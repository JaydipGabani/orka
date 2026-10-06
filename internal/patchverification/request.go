package patchverification

type Request struct {
	Action              Action                   `json:"action,omitempty"`
	EarlierValidation   string                   `json:"earlierValidation,omitempty"`
	DeclaredChanges     []DeclaredChange         `json:"declaredChanges,omitempty"`
	RequiredEnvironment []EnvironmentRequirement `json:"requiredEnvironment,omitempty"`
	ProvidedFields      map[string]bool          `json:"-"`
	Problem             string                   `json:"problem,omitempty"`
	Scope               []string                 `json:"scope,omitempty"`
	Gaps                []string                 `json:"gaps,omitempty"`
	Repository          string                   `json:"repository,omitempty"`
	OriginalCommit      string                   `json:"originalCommit,omitempty"`
	PatchedCommit       string                   `json:"patchedCommit,omitempty"`
	PatchFile           string                   `json:"patchFile,omitempty"`
	ChecksDir           string                   `json:"checksDir,omitempty"`
	Image               string                   `json:"image,omitempty"`
	Platform            string                   `json:"platform,omitempty"`
	Profile             string                   `json:"profile,omitempty"`
	Variables           map[string]string        `json:"variables,omitempty"`
	Dependencies        map[string]string        `json:"dependencies,omitempty"`
	Services            []Service                `json:"services,omitempty"`
	Checks              []Check                  `json:"checks,omitempty"`
}

type PreparedSources struct {
	Sources     Sources
	Files       []FrozenFile
	Provenance  map[string][]byte
	OriginalDir string
	PatchedDir  string
	ChecksDir   string
	Root        string
}
