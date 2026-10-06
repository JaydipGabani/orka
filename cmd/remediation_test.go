package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	remediationservice "github.com/orka-agents/orka/internal/remediation/service"
	"github.com/orka-agents/orka/internal/store"
	"github.com/orka-agents/orka/internal/store/sqlite"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

type remediationTestManager struct {
	client.Client
	runnables []manager.Runnable
}

func (m *remediationTestManager) GetClient() client.Client    { return m.Client }
func (m *remediationTestManager) GetAPIReader() client.Reader { return m.Client }
func (m *remediationTestManager) Add(r manager.Runnable) error {
	m.runnables = append(m.runnables, r)
	return nil
}

func remediationTestStore(t *testing.T) *sqlite.Store {
	t.Helper()
	filename := filepath.Join(t.TempDir(), "orka.db")
	db, err := sqlite.NewDB(filename)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return sqlite.NewStore(db, filename)
}

func TestRemediationDisabledDoesNotInitializeOrRegister(t *testing.T) {
	storage := remediationTestStore(t)
	service, err := setupRemediationService(t.Context(), nil, storage, remediationOptions{Namespace: "testing"})
	if err != nil || service != nil {
		t.Fatal("disabled ordinary installation acquired remediation behavior", err)
	}
	initialized, err := storage.RemediationStoreInitialized(t.Context())
	if err != nil || initialized {
		t.Fatal("disabled service created the optional schema", err)
	}
	task := &corev1alpha1.Task{}
	if err := remediationDispatchValidator(nil)(t.Context(), task, nil, nil); err != remediationservice.ErrDisabled {
		t.Fatal("disabled dispatch allowed a reserved proposal Task", err)
	}
}

func TestRemediationDisableRetainsCancellationService(t *testing.T) {
	storage := remediationTestStore(t)
	if err := storage.InitializeRemediationStore(t.Context()); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	digest := remediationservice.Digest([]byte("synthetic"))
	run, _, err := storage.CreateRemediationRun(t.Context(), &store.RemediationRun{
		Namespace: "testing", ID: "rm-" + strings.Repeat("a", 32), RequestID: "synthetic",
		SubmittedBy: "caller", Mode: "generate", PolicyDigest: digest, InputDigest: digest,
		RequestJSON: json.RawMessage(`{}`), PolicyJSON: json.RawMessage(`{}`), StateJSON: json.RawMessage(`{}`),
		Phase: store.RemediationPhaseQueued, CreatedAt: now, UpdatedAt: now, Deadline: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	scheme := runtime.NewScheme()
	if err := corev1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	mgr := &remediationTestManager{Client: fake.NewClientBuilder().WithScheme(scheme).Build()}
	service, err := setupRemediationService(t.Context(), mgr, storage, remediationOptions{
		Namespace: "testing", PolicyFile: "/unavailable/removed-policy.json",
	})
	if err != nil || service == nil || len(mgr.runnables) != 1 || !service.NeedLeaderElection() {
		t.Fatal("disabling admission stranded retained cleanup work", err)
	}
	current, err := storage.GetRemediationRun(t.Context(), "testing", run.ID)
	if err != nil || !current.CancelRequested || current.Phase != store.RemediationPhaseCancelling {
		t.Fatal("retained run was not durably cancelled", err)
	}
}

func TestRemediationConfigurationRequiresPrivateBoundaryAndPinnedWorker(t *testing.T) {
	for name, options := range map[string]remediationOptions{
		"missing private namespace": {AIWorkerImage: "registry.example/worker@sha256:" + strings.Repeat("a", 64)},
		"tagged worker":             {PrivateNamespaceAcknowledged: true, AIWorkerImage: "registry.example/worker:latest"},
		"temporary datastore": {
			PrivateNamespaceAcknowledged: true,
			AIWorkerImage:                "registry.example/worker@sha256:" + strings.Repeat("a", 64),
			StorePath:                    filepath.Join(t.TempDir(), "orka.db"),
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadRemediationPolicies(options); err == nil {
				t.Fatal("unsafe one-time deployment configuration was accepted")
			}
		})
	}
}

func TestRemediationPrivateDatastorePreflight(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(filepath.Dir(cwd), "bin")
	if err := os.MkdirAll(bin, 0700); err != nil {
		t.Fatal(err)
	}
	directory, err := os.MkdirTemp(bin, "remediation-wiring-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Error(err)
		}
	})
	filename := filepath.Join(directory, "orka.db")
	if err := os.WriteFile(filename, []byte("synthetic datastore placeholder"), 0600); err != nil {
		t.Fatal(err)
	}
	if root, err := remediationStoreRoot(filename); err != nil || root != directory {
		t.Fatal("private persistent location was rejected", err)
	}
}
