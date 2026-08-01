/*
Copyright (c) 2026.

MIT License - see LICENSE file for details.
*/

package controller

import (
	"os"
	"slices"
	"strings"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	"github.com/orka-agents/orka/internal/labels"
	"github.com/orka-agents/orka/internal/transactiontoken"
)

const (
	testClusterRoleKind  = "ClusterRole"
	testAIWorkerRoleName = "ai-worker-role"
)

func TestTaskTransactionRenewalAuthorityDiscoveryFailsClosed(t *testing.T) {
	tests := []struct {
		name    string
		objects func(*corev1alpha1.Task) []client.Object
	}{
		{name: "zero authority Secrets", objects: func(*corev1alpha1.Task) []client.Object { return nil }},
		{name: "multiple authority Secrets", objects: func(task *corev1alpha1.Task) []client.Object {
			first := directTaskTokenAuthoritySecretForTest(task, testRenewableSubjectToken)
			second := first.DeepCopy()
			second.Name += "-duplicate"
			return []client.Object{first, second}
		}},
		{name: "mismatched owner", objects: func(task *corev1alpha1.Task) []client.Object {
			authority := directTaskTokenAuthoritySecretForTest(task, testRenewableSubjectToken)
			authority.OwnerReferences[0].UID = types.UID("different-task-uid")
			return []client.Object{authority}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			task, workload, _ := renewableTaskTokenFixture(corev1alpha1.TaskTypeAI)
			objects := make([]client.Object, 0, 2+len(test.objects(task)))
			objects = append(objects, task, workload)
			objects = append(objects, test.objects(task)...)
			r := newUnitReconciler(newTestScheme(), objects...)
			if _, err := r.taskTransactionRenewalAuthoritySecret(t.Context(), task); err == nil {
				t.Fatal("authority discovery accepted an ambiguous or mismatched Secret set")
			}
		})
	}
}

func TestAIWorkerRoleCannotListTransactionRenewalAuthoritySecrets(t *testing.T) {
	data, err := os.ReadFile("../../config/rbac/worker_role.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var aiWorkerRole *rbacv1.ClusterRole
	for document := range strings.SplitSeq(string(data), "\n---") {
		var metadata struct {
			Kind     string            `yaml:"kind"`
			Metadata metav1.ObjectMeta `yaml:"metadata"`
		}
		if err := yaml.Unmarshal([]byte(document), &metadata); err != nil ||
			metadata.Kind != testClusterRoleKind || metadata.Metadata.Name != testAIWorkerRoleName {
			continue
		}
		role := &rbacv1.ClusterRole{}
		if err := yaml.Unmarshal([]byte(document), role); err != nil {
			t.Fatal(err)
		}
		aiWorkerRole = role
		break
	}
	if aiWorkerRole == nil {
		t.Fatal("ai-worker-role not found")
	}
	for _, rule := range aiWorkerRole.Rules {
		if !slices.Contains(rule.Resources, "secrets") {
			continue
		}
		if slices.Contains(rule.Verbs, "list") || slices.Contains(rule.Verbs, "watch") {
			t.Fatalf("ai-worker-role can enumerate Secrets: verbs=%v", rule.Verbs)
		}
	}
}

func TestWorkloadTokenSecretContainsNoRenewalAuthority(t *testing.T) {
	task, workload, authority := renewableTaskTokenFixture(corev1alpha1.TaskTypeAI)
	if workload.Labels[labels.LabelPurpose] != transactiontoken.WorkloadSecretPurpose ||
		workload.Labels[labels.LabelTaskUID] != labels.SelectorValue(string(task.UID)) {
		t.Fatal("workload token Secret identity labels are invalid")
	}
	if _, ok := workload.Data[transactiontoken.SubjectSecretKey]; ok {
		t.Fatal("workload token Secret contains raw renewal authority")
	}
	if task.Annotations[labels.AnnotationTransactionTokenSecret] != workload.Name {
		t.Fatal("Task does not reference the workload token Secret")
	}
	for _, value := range task.Annotations {
		if value == authority.Name {
			t.Fatal("Task annotation exposes the controller-only authority Secret name")
		}
	}
}
