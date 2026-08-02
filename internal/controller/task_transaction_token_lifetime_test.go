/*
Copyright (c) 2026.

MIT License - see LICENSE file for details.
*/

package controller

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	"github.com/orka-agents/orka/internal/contexttoken"
	"github.com/orka-agents/orka/internal/harness/harnesstest"
	"github.com/orka-agents/orka/internal/labels"
	"github.com/orka-agents/orka/internal/tokenexchange"
	"github.com/orka-agents/orka/internal/transactiontoken"
	workerpkg "github.com/orka-agents/orka/internal/worker"
)

const (
	testRenewableSubjectToken = "verified-renewable-caller-token"
	testRenewableSecretName   = "renewable-task-token"
	testTaskTokenEndpoint     = "https://transactions.example.test/token"
	testRuntimeRefName        = "fibey-agentkit"
	testSecretResourceName    = "secrets"
	testJobBackedTaskName     = "job-backed AI task"
	testRuntimeRefTaskName    = "runtimeRef agent task"
	testWorkerContainerName   = "worker"
)

func TestDirectTaskTransactionTokenRotatesBeyondOriginalTTL(t *testing.T) {
	start := time.Date(2026, time.August, 1, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name     string
		taskType corev1alpha1.TaskType
	}{
		{name: testJobBackedTaskName, taskType: corev1alpha1.TaskTypeAI},
		{name: testRuntimeRefTaskName, taskType: corev1alpha1.TaskTypeAgent},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			task, secret, authority := renewableTaskTokenFixture(test.taskType)
			initialSubject := taskTokenJWTForTest(t, start.Add(5*time.Minute), "caller-authority")
			authority.Data[transactiontoken.SubjectSecretKey] = []byte(initialSubject)
			exchanger := &queuedTaskTokenExchanger{tokens: []string{
				taskTokenJWTForTest(t, start.Add(5*time.Minute), "generation-1"),
				taskTokenJWTForTest(t, start.Add(7*time.Minute), "generation-2"),
				taskTokenJWTForTest(t, start.Add(11*time.Minute), "generation-3"),
			}}
			r := newUnitReconciler(newTestScheme(), task, secret, authority)
			r.BrokeredTransactionExchange = testTaskTransactionExchangeConfig(exchanger)

			ready, fatal, err := r.reconcilePendingTaskTransactionToken(context.Background(), task, start)
			if err != nil || fatal || !ready {
				t.Fatalf("initial token exchange = ready:%v fatal:%v err:%v", ready, fatal, err)
			}
			first := currentTaskTokenSecret(t, r, task)
			firstToken := string(first.Data[transactiontoken.TokenSecretKey])

			refreshAfter, fatal, err := r.reconcileActiveTaskTransactionToken(context.Background(), task, start.Add(2*time.Minute))
			if err != nil || fatal || refreshAfter <= 0 {
				t.Fatalf("first rotation = refreshAfter:%v fatal:%v err:%v", refreshAfter, fatal, err)
			}
			second := currentTaskTokenSecret(t, r, task)
			secondToken := string(second.Data[transactiontoken.TokenSecretKey])
			if secondToken == firstToken {
				t.Fatal("first refresh did not rotate the task token")
			}

			// This is beyond the original token's five-minute TTL. A healthy Task
			// still has renewable authority and receives another distinct token.
			refreshAfter, fatal, err = r.reconcileActiveTaskTransactionToken(context.Background(), task, start.Add(6*time.Minute))
			if err != nil || fatal || refreshAfter <= 0 {
				t.Fatalf("post-TTL rotation = refreshAfter:%v fatal:%v err:%v", refreshAfter, fatal, err)
			}
			third := currentTaskTokenSecret(t, r, task)
			thirdToken := string(third.Data[transactiontoken.TokenSecretKey])
			if thirdToken == secondToken || thirdToken == firstToken {
				t.Fatal("post-TTL refresh did not rotate the task token")
			}
			if _, ok := third.Data[transactiontoken.SubjectSecretKey]; ok {
				t.Fatal("workload Secret exposed raw renewal authority")
			}
			currentAuthority := &corev1.Secret{}
			if err := r.Get(context.Background(), client.ObjectKeyFromObject(authority), currentAuthority); err != nil ||
				string(currentAuthority.Data[transactiontoken.SubjectSecretKey]) != initialSubject {
				t.Fatal("controller-only renewal authority was not retained")
			}
			requireRollingTaskTokenSubjects(t, exchanger.requests, initialSubject, firstToken, secondToken)
			if string(third.Data[taskTokenGenerationSecretKey]) != "3" || exchanger.calls != 3 {
				t.Fatalf("rotation generation/calls = %q/%d, want 3/3",
					third.Data[taskTokenGenerationSecretKey], exchanger.calls)
			}
			for index, request := range exchanger.requests {
				if request.RequestDetails[taskTokenRequestRotationKey] != uint64(index+1) {
					t.Fatalf("rotation request %d generation = %#v", index+1, request.RequestDetails)
				}
			}
			if test.taskType == corev1alpha1.TaskTypeAI {
				job := &batchv1.Job{Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: testWorkerContainerName}}},
				}}}
				r.JobBuilder.addTransactionTokenSecret(job, task)
				found := false
				for _, volume := range job.Spec.Template.Spec.Volumes {
					if volume.Secret != nil && volume.Secret.SecretName == testRenewableSecretName {
						found = len(volume.Secret.Items) == 1 && volume.Secret.Items[0].Key == transactiontoken.TokenSecretKey
					}
				}
				if !found {
					t.Fatal("Job-backed task does not mount the rotatable token key")
				}
			}
			if test.taskType == corev1alpha1.TaskTypeAgent {
				runtimeToken, _, err := r.harnessBrokeredTransactionAuthority(context.Background(), task)
				if err != nil {
					t.Fatalf("runtimeRef authority: %v", err)
				}
				if runtimeToken != thirdToken {
					t.Fatal("runtimeRef did not resolve the latest rotated token")
				}
			}
		})
	}
}

func requireRollingTaskTokenSubjects(
	t *testing.T,
	requests []contexttoken.ExchangeRequest,
	initialSubject, firstToken, secondToken string,
) {
	t.Helper()
	if len(requests) != 3 ||
		requests[0].SubjectToken != initialSubject ||
		requests[1].SubjectToken != firstToken ||
		requests[2].SubjectToken != secondToken {
		t.Fatalf("rotation subjects = %#v, want caller then rolling task-bound tokens", requests)
	}
	for i := 1; i < len(requests); i++ {
		if requests[i].SubjectTokenType != transactiontoken.SubjectTokenTypeTransactionToken {
			t.Fatalf("rotation %d subject type = %q, want transaction token", i, requests[i].SubjectTokenType)
		}
	}
}

func TestDelegatedServiceAccountRenewalChainsToTransactionTokenReplacement(t *testing.T) {
	now := time.Now().UTC()
	task, workload, _ := renewableTaskTokenFixture(corev1alpha1.TaskTypeAI)
	authority := directTaskTokenAuthoritySecretWithTypeForTest(task, testRenewableSubjectToken, transactiontoken.SubjectTokenTypeAccessToken)
	firstToken := taskTokenJWTForTest(t, now.Add(5*time.Minute), "service-account-child-1")
	exchanger := &queuedTaskTokenExchanger{tokens: []string{
		firstToken,
		taskTokenJWTForTest(t, now.Add(10*time.Minute), "service-account-child-2"),
	}}
	r := newUnitReconciler(newTestScheme(), task, workload, authority)
	r.BrokeredTransactionExchange = testTaskTransactionExchangeConfig(exchanger)
	r.BrokeredTransactionExchange.TTS.TokenSource = contexttoken.TTSTokenSourceServiceAccount
	ready, fatal, err := r.reconcilePendingTaskTransactionToken(context.Background(), task, now)
	if err != nil || fatal || !ready {
		t.Fatalf("service-account delegated setup = ready:%v fatal:%v err:%v", ready, fatal, err)
	}
	refreshAfter, fatal, err := r.reconcileActiveTaskTransactionToken(context.Background(), task, now.Add(2*time.Minute))
	if err != nil || fatal || refreshAfter <= 0 {
		t.Fatalf("service-account delegated refresh = after:%v fatal:%v err:%v", refreshAfter, fatal, err)
	}
	if len(exchanger.requests) != 2 ||
		exchanger.requests[0].SubjectTokenType != contexttoken.SubjectTokenTypeForSource(contexttoken.TTSTokenSourceServiceAccount) ||
		exchanger.requests[1].SubjectToken != firstToken ||
		exchanger.requests[1].SubjectTokenType != transactiontoken.SubjectTokenTypeTransactionToken {
		t.Fatalf("delegated service-account rotation subjects = %#v", exchanger.requests)
	}
}

func TestDelegatedChildTransactionTokenRotatesBeyondTTL(t *testing.T) {
	start := time.Date(2026, time.August, 1, 14, 0, 0, 0, time.UTC)
	for _, taskType := range []corev1alpha1.TaskType{
		corev1alpha1.TaskTypeAI, corev1alpha1.TaskTypeAgent, corev1alpha1.TaskTypeContainer,
	} {
		t.Run(string(taskType), func(t *testing.T) {
			task, _, _ := renewableTaskTokenFixture(taskType)
			task.Name = "delegated-" + string(taskType)
			task.UID = types.UID("delegated-" + string(taskType) + "-uid")
			const parentTaskName = "parent-task"
			task.Labels = map[string]string{labels.LabelParentTask: labels.SelectorValue(parentTaskName)}
			task.Annotations[labels.AnnotationParentTaskName] = parentTaskName
			if taskType == corev1alpha1.TaskTypeAgent {
				task.Spec.AgentRef = &corev1alpha1.AgentReference{Name: "delegated-agent"}
			}
			workload := directTaskTokenWorkloadSecretForTest(task, testRenewableSecretName+"-"+string(taskType))
			task.Annotations[labels.AnnotationTransactionTokenSecret] = workload.Name
			authority := directTaskTokenAuthoritySecretForTest(task, testRenewableSubjectToken)
			exchanger := &queuedTaskTokenExchanger{tokens: []string{
				taskTokenJWTForTest(t, start.Add(5*time.Minute), "delegated-1"),
				taskTokenJWTForTest(t, start.Add(20*time.Minute), "delegated-2"),
			}}
			r := newUnitReconciler(newTestScheme(), task, workload, authority)
			r.BrokeredTransactionExchange = testTaskTransactionExchangeConfig(exchanger)
			ready, fatal, err := r.reconcilePendingTaskTransactionToken(context.Background(), task, start)
			if err != nil || fatal || !ready {
				t.Fatalf("delegated setup = ready:%v fatal:%v err:%v", ready, fatal, err)
			}
			refreshAfter, fatal, err := r.reconcileActiveTaskTransactionToken(context.Background(), task, start.Add(2*time.Minute))
			if err != nil || fatal || refreshAfter <= 0 {
				t.Fatalf("delegated pre-expiry rotation = after:%v fatal:%v err:%v", refreshAfter, fatal, err)
			}
			refreshAfter, fatal, err = r.reconcileActiveTaskTransactionToken(context.Background(), task, start.Add(6*time.Minute))
			if err != nil || fatal || refreshAfter <= 0 {
				t.Fatalf("delegated post-original-TTL state = after:%v fatal:%v err:%v", refreshAfter, fatal, err)
			}
			latest := currentTaskTokenSecret(t, r, task)
			_, exposed := latest.Data[transactiontoken.SubjectSecretKey]
			if string(latest.Data[taskTokenGenerationSecretKey]) != "2" || exposed {
				t.Fatal("delegated workload Secret did not rotate confidentially")
			}
			details := exchanger.requests[0].RequestDetails
			wantOperation := taskTokenRequestOperationDelegateTask
			if taskType == corev1alpha1.TaskTypeContainer {
				wantOperation = taskTokenRequestOperationCreateContainerTask
			}
			if details[taskTokenRequestOperationKey] != wantOperation ||
				details[taskTokenRequestParentTaskKey] != parentTaskName ||
				details[taskTokenRequestTaskNameKey] != task.Name ||
				details[taskTokenRequestTaskUIDKey] != string(task.UID) {
				t.Fatalf("delegated request details = %#v", details)
			}
			if taskType == corev1alpha1.TaskTypeAgent && details[taskTokenRequestAgentKey] != task.Spec.AgentRef.Name {
				t.Fatalf("delegated agent request details = %#v", details)
			}
			if taskType == corev1alpha1.TaskTypeAgent {
				resolved, _, err := r.harnessBrokeredTransactionAuthority(context.Background(), task)
				if err != nil || resolved != string(latest.Data[transactiontoken.TokenSecretKey]) {
					t.Fatal("delegated runtimeRef did not resolve latest token")
				}
			}
		})
	}
}

func TestTransactionalRuntimeRefStartsOnSecondReconcileWithLatestToken(t *testing.T) {
	server := harnesstest.NewFakeHarnessServer(harnesstest.FakeHarnessConfig{
		Behavior: harnesstest.BehaviorLongRunning, RuntimeName: testRuntimeRefName,
	})
	defer server.Close()

	now := time.Now().UTC()
	task, agent := harnessWrapperTaskAndAgent()
	task.Finalizers = []string{labels.TaskFinalizer}
	task.Spec.Transaction = &corev1alpha1.TaskTransaction{
		ID: "txn-runtime-second-reconcile", Scope: directTokenMemoryReadScope,
		Scopes: []string{directTokenMemoryReadScope},
	}
	task.Annotations = map[string]string{
		labels.AnnotationTransactionTokenPending:      scheduledRunLabelValue,
		labels.AnnotationTransactionTokenPendingSince: now.Add(-time.Second).Format(time.RFC3339Nano),
		labels.AnnotationTransactionTokenSecret:       testRenewableSecretName,
	}
	agent.Spec.Runtime = &corev1alpha1.AgentCLIRuntime{
		RuntimeRef: &corev1alpha1.AgentRuntimeReference{Name: testRuntimeRefName},
	}
	workload := directTaskTokenWorkloadSecretForTest(task, testRenewableSecretName)
	authority := directTaskTokenAuthoritySecretForTest(task, testRenewableSubjectToken)
	runtime, runtimeAuth := harnessWrapperReadyAgentRuntime(task.Namespace, server.URL())
	latestToken := taskTokenJWTForTest(t, now.Add(5*time.Minute), "runtime-latest")
	exchanger := &queuedTaskTokenExchanger{tokens: []string{latestToken}}
	r := newUnitReconciler(newTestScheme(), task, agent, workload, authority, runtime, runtimeAuth)
	r.BrokeredTransactionExchange = testTaskTransactionExchangeConfig(exchanger)
	request := ctrl.Request{NamespacedName: types.NamespacedName{Name: task.Name, Namespace: task.Namespace}}

	if _, err := r.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("first Reconcile() error = %v", err)
	}
	current := &corev1alpha1.Task{}
	if err := r.Get(context.Background(), client.ObjectKeyFromObject(task), current); err != nil {
		t.Fatalf("get planned runtimeRef Task: %v", err)
	}
	if !taskHasPlannedHarnessWrapperTurn(current) || taskHasHarnessWrapperTurn(current) {
		t.Fatalf("first reconciliation did not stop at durable turn planning: %#v", current.Annotations)
	}
	freshReader := r.Client
	r.APIReader = freshReader
	r.Client = interceptor.NewClient(freshReader.(client.WithWatch), interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, object client.Object, opts ...client.GetOption) error {
			if secret, ok := object.(*corev1.Secret); ok && key.Name == workload.Name {
				stale := workload.DeepCopy()
				stale.DeepCopyInto(secret)
				return nil
			}
			return c.Get(ctx, key, object, opts...)
		},
	})

	if _, err := r.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("second Reconcile() error = %v", err)
	}
	if err := r.Get(context.Background(), client.ObjectKeyFromObject(task), current); err != nil {
		t.Fatalf("get running runtimeRef Task: %v", err)
	}
	if current.Status.Phase != corev1alpha1.TaskPhaseRunning || !taskHasHarnessWrapperTurn(current) {
		t.Fatalf("runtimeRef Task did not start on second reconciliation: phase=%s annotations=%#v",
			current.Status.Phase, current.Annotations)
	}
	resolvedToken, _, err := r.harnessBrokeredTransactionAuthority(context.Background(), current)
	if err != nil {
		t.Fatalf("resolve latest runtimeRef token: %v", err)
	}
	if resolvedToken != latestToken || exchanger.calls != 1 {
		t.Fatalf("runtimeRef authority/calls did not use the latest rotation: calls=%d", exchanger.calls)
	}
}

func TestTaskTransactionTokenRotationConflictRecovery(t *testing.T) {
	tests := []struct {
		name          string
		installWinner bool
	}{
		{name: "preserves concurrent completed rotation", installWinner: true},
		{name: "retries intended rotation once"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			now := time.Now().UTC()
			task, workload, authority := renewableTaskTokenFixture(corev1alpha1.TaskTypeAI)
			initial := taskTokenJWTForTest(t, now.Add(5*time.Minute), "conflict-initial")
			setRenewableTaskTokenSecret(workload, initial, now.Add(-time.Second), 1)
			base := newUnitReconciler(newTestScheme(), task, workload, authority)
			freshReader := base.Client
			base.APIReader = freshReader
			intended := taskTokenJWTForTest(t, now.Add(10*time.Minute), "conflict-intended")
			winner := taskTokenJWTForTest(t, now.Add(12*time.Minute), "conflict-winner")
			exchanger := &queuedTaskTokenExchanger{tokens: []string{intended}}
			base.BrokeredTransactionExchange = testTaskTransactionExchangeConfig(exchanger)
			conflicted := false
			base.Client = interceptor.NewClient(freshReader.(client.WithWatch), interceptor.Funcs{
				Update: func(ctx context.Context, c client.WithWatch, object client.Object, opts ...client.UpdateOption) error {
					secret, ok := object.(*corev1.Secret)
					if !ok || secret.Name != workload.Name || conflicted {
						return c.Update(ctx, object, opts...)
					}
					conflicted = true
					if test.installWinner {
						current := &corev1.Secret{}
						if err := freshReader.Get(ctx, client.ObjectKeyFromObject(workload), current); err != nil {
							return err
						}
						setRenewableTaskTokenSecret(current, winner, now.Add(3*time.Minute), 2)
						if err := freshReader.Update(ctx, current); err != nil {
							return err
						}
					}
					return apierrors.NewConflict(schema.GroupResource{Group: "", Resource: testSecretResourceName}, secret.Name, errors.New("resource version changed"))
				},
			})

			refreshAfter, fatal, err := base.reconcileActiveTaskTransactionToken(context.Background(), task, now)
			if err != nil || fatal || refreshAfter <= 0 {
				t.Fatalf("conflict recovery = refreshAfter:%v fatal:%v err:%v", refreshAfter, fatal, err)
			}
			current := currentTaskTokenSecret(t, base, task)
			want := intended
			if test.installWinner {
				want = winner
			}
			if string(current.Data[transactiontoken.TokenSecretKey]) != want {
				t.Fatal("conflict recovery overwrote or lost the completed rotation")
			}
		})
	}
}

func TestJobBackedTaskTransactionTokenRequiresPropagationSafeLifetime(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	tests := []struct {
		name      string
		lifetime  time.Duration
		wantFatal bool
	}{
		{name: "too short", lifetime: transactiontoken.MinimumProjectedTokenRemainingLifetime - time.Second, wantFatal: true},
		{name: "safe", lifetime: transactiontoken.MinimumProjectedTokenRemainingLifetime + time.Minute},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			task, workload, authority := renewableTaskTokenFixture(corev1alpha1.TaskTypeAI)
			exchanger := &queuedTaskTokenExchanger{tokens: []string{
				taskTokenJWTForTest(t, now.Add(test.lifetime), "projected-"+test.name),
			}}
			r := newUnitReconciler(newTestScheme(), task, workload, authority)
			r.BrokeredTransactionExchange = testTaskTransactionExchangeConfig(exchanger)
			ready, fatal, err := r.reconcilePendingTaskTransactionToken(t.Context(), task, now)
			if test.wantFatal {
				if err == nil || !fatal || ready {
					t.Fatalf("short projected token = ready:%v fatal:%v err:%v", ready, fatal, err)
				}
				return
			}
			if err != nil || fatal || !ready {
				t.Fatalf("safe projected token = ready:%v fatal:%v err:%v", ready, fatal, err)
			}
		})
	}
}

func TestPendingTaskTransactionTokenTransientInitialExchangeRetriesBeforeSetupDeadline(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{name: "timeout", err: context.DeadlineExceeded},
		{name: "network", err: &net.DNSError{Err: "temporary resolver failure", Name: "transactions.example.test", IsTemporary: true}},
		{name: "rate limited", err: &tokenexchange.ExchangeError{StatusCode: http.StatusTooManyRequests}},
		{name: "server failure", err: &tokenexchange.ExchangeError{StatusCode: http.StatusServiceUnavailable}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pendingSince := time.Now().UTC().Add(-time.Second)
			task, workload, authority := pendingDirectTaskTokenFixture(pendingSince)
			exchanger := &queuedTaskTokenExchanger{err: test.err}
			r := newUnitReconciler(newTestScheme(), task, workload, authority)
			r.BrokeredTransactionExchange = testTaskTransactionExchangeConfig(exchanger)

			result, err := r.handleTransactionTokenPending(t.Context(), task)
			if err != nil {
				t.Fatalf("handleTransactionTokenPending() error = %v", err)
			}
			if result.RequeueAfter <= 0 || result.RequeueAfter > time.Second {
				t.Fatalf("RequeueAfter = %v, want retry within the pending setup deadline", result.RequeueAfter)
			}
			if exchanger.calls != 1 {
				t.Fatalf("exchange calls = %d, want 1", exchanger.calls)
			}

			updated := &corev1alpha1.Task{}
			if err := r.Get(t.Context(), client.ObjectKeyFromObject(task), updated); err != nil {
				t.Fatalf("get pending Task: %v", err)
			}
			if updated.Status.Phase != corev1alpha1.TaskPhasePending || !taskTransactionTokenPending(updated) {
				t.Fatalf("Task state = %s pending:%v, want blocked Pending Task", updated.Status.Phase, taskTransactionTokenPending(updated))
			}
			if got := updated.Annotations[labels.AnnotationTransactionTokenPendingSince]; got != pendingSince.Format(time.RFC3339Nano) {
				t.Fatalf("pending since = %q, want unchanged %q", got, pendingSince.Format(time.RFC3339Nano))
			}
			current := currentTaskTokenSecret(t, r, task)
			if token := strings.TrimSpace(string(current.Data[transactiontoken.TokenSecretKey])); token != "" {
				t.Fatal("transient initial exchange published a workload token")
			}
			if err := r.Get(t.Context(), client.ObjectKeyFromObject(authority), &corev1.Secret{}); err != nil {
				t.Fatalf("renewal authority Secret was removed: %v", err)
			}
			jobs := &batchv1.JobList{}
			if err := r.List(t.Context(), jobs, client.InNamespace(task.Namespace)); err != nil {
				t.Fatalf("list Jobs: %v", err)
			}
			if len(jobs.Items) != 0 {
				t.Fatalf("created %d Jobs while initial token exchange was retrying", len(jobs.Items))
			}
		})
	}
}

func TestPendingTaskTransactionTokenSuccessfulInitialExchangeWithMalformedDeadlineFailsClosed(t *testing.T) {
	for _, value := range []string{"not-a-time", "   "} {
		t.Run(strconv.Quote(value), func(t *testing.T) {
			task, workload, authority := renewableTaskTokenFixture(corev1alpha1.TaskTypeAI)
			task.Status.Phase = corev1alpha1.TaskPhasePending
			task.Annotations[labels.AnnotationTransactionTokenPending] = scheduledRunLabelValue
			task.Annotations[labels.AnnotationTransactionTokenPendingSince] = value
			exchanger := &queuedTaskTokenExchanger{
				tokens: []string{taskTokenJWTForTest(t, time.Now().UTC().Add(5*time.Minute), "malformed-deadline")},
			}
			r := newUnitReconciler(newTestScheme(), task, workload, authority)
			r.BrokeredTransactionExchange = testTaskTransactionExchangeConfig(exchanger)

			ready, fatal, err := r.reconcilePendingTaskTransactionToken(t.Context(), task, time.Now().UTC())
			if err == nil || !fatal || ready {
				t.Fatalf("malformed-deadline successful exchange = ready:%v fatal:%v err:%v", ready, fatal, err)
			}
			if exchanger.calls != 0 {
				t.Fatalf("exchange calls = %d, want no exchange with malformed deadline", exchanger.calls)
			}
		})
	}
}

func TestPendingTaskTransactionTokenTransientInitialExchangeWithoutDeadlineFailsClosed(t *testing.T) {
	task, workload, authority := renewableTaskTokenFixture(corev1alpha1.TaskTypeAI)
	task.Status.Phase = corev1alpha1.TaskPhasePending
	task.Annotations[labels.AnnotationTransactionTokenPending] = scheduledRunLabelValue
	exchanger := &queuedTaskTokenExchanger{
		err: &tokenexchange.ExchangeError{StatusCode: http.StatusServiceUnavailable},
	}
	r := newUnitReconciler(newTestScheme(), task, workload, authority)
	r.BrokeredTransactionExchange = testTaskTransactionExchangeConfig(exchanger)

	ready, fatal, err := r.reconcilePendingTaskTransactionToken(t.Context(), task, time.Now().UTC())
	if err == nil || !fatal || ready {
		t.Fatalf("missing-deadline transient exchange = ready:%v fatal:%v err:%v", ready, fatal, err)
	}
}

func TestPendingTaskTransactionTokenPermanentInitialExchangeFailsClosed(t *testing.T) {
	task, workload, authority := pendingDirectTaskTokenFixture(time.Now().UTC().Add(-time.Second))
	exchanger := &queuedTaskTokenExchanger{
		err: &tokenexchange.ExchangeError{StatusCode: http.StatusBadRequest, Code: "invalid_scope"},
	}
	r := newUnitReconciler(newTestScheme(), task, workload, authority)
	r.BrokeredTransactionExchange = testTaskTransactionExchangeConfig(exchanger)

	if _, err := r.handleTransactionTokenPending(t.Context(), task); err != nil {
		t.Fatalf("handleTransactionTokenPending() error = %v", err)
	}
	if exchanger.calls != 1 {
		t.Fatalf("exchange calls = %d, want 1", exchanger.calls)
	}
	assertPendingTaskTransactionTokenFailedClosed(t, r, task, workload, authority)
}

func TestPendingTaskTransactionTokenFailsClosedAtSetupDeadline(t *testing.T) {
	task, workload, authority := pendingDirectTaskTokenFixture(
		time.Now().UTC().Add(-taskTransactionTokenPendingTimeout - time.Second),
	)
	exchanger := &queuedTaskTokenExchanger{
		err: &tokenexchange.ExchangeError{StatusCode: http.StatusServiceUnavailable},
	}
	r := newUnitReconciler(newTestScheme(), task, workload, authority)
	r.BrokeredTransactionExchange = testTaskTransactionExchangeConfig(exchanger)

	if _, err := r.handleTransactionTokenPending(t.Context(), task); err != nil {
		t.Fatalf("handleTransactionTokenPending() error = %v", err)
	}
	if exchanger.calls != 0 {
		t.Fatalf("exchange calls = %d, want no exchange at the setup deadline", exchanger.calls)
	}
	assertPendingTaskTransactionTokenFailedClosed(t, r, task, workload, authority)
}

func TestPendingTaskTransactionTokenSuccessfulInitialExchangeFailsClosedWhenSetupDeadlineElapses(t *testing.T) {
	now := time.Date(2026, time.August, 2, 12, 0, 0, 0, time.UTC)
	task, workload, authority := pendingDirectTaskTokenFixture(
		now.Add(-taskTransactionTokenPendingTimeout + 50*time.Millisecond),
	)
	exchanger := &queuedTaskTokenExchanger{
		tokens: []string{taskTokenJWTForTest(t, now.Add(5*time.Minute), "late-success")},
		delay:  100 * time.Millisecond,
	}
	r := newUnitReconciler(newTestScheme(), task, workload, authority)
	r.BrokeredTransactionExchange = testTaskTransactionExchangeConfig(exchanger)

	ready, fatal, err := r.reconcilePendingTaskTransactionToken(t.Context(), task, now)
	if err == nil || !fatal || ready {
		t.Fatalf("deadline-crossing successful exchange = ready:%v fatal:%v err:%v", ready, fatal, err)
	}
	if exchanger.calls != 1 {
		t.Fatalf("exchange calls = %d, want 1", exchanger.calls)
	}
}

func TestPendingTaskTransactionTokenTransientInitialExchangeFailsClosedWhenSetupDeadlineElapses(t *testing.T) {
	now := time.Date(2026, time.August, 2, 12, 0, 0, 0, time.UTC)
	task, workload, authority := pendingDirectTaskTokenFixture(
		now.Add(-taskTransactionTokenPendingTimeout + 50*time.Millisecond),
	)
	exchanger := &queuedTaskTokenExchanger{
		err: &tokenexchange.ExchangeError{StatusCode: http.StatusServiceUnavailable}, delay: 100 * time.Millisecond,
	}
	r := newUnitReconciler(newTestScheme(), task, workload, authority)
	r.BrokeredTransactionExchange = testTaskTransactionExchangeConfig(exchanger)

	ready, fatal, err := r.reconcilePendingTaskTransactionToken(t.Context(), task, now)
	if err == nil || !fatal || ready {
		t.Fatalf("deadline-crossing initial exchange = ready:%v fatal:%v err:%v", ready, fatal, err)
	}
	if exchanger.calls != 1 {
		t.Fatalf("exchange calls = %d, want 1", exchanger.calls)
	}
}

func TestActiveTaskTransactionTokenRefreshCapsRequeue(t *testing.T) {
	now := time.Now().UTC()
	task, secret, authority := renewableTaskTokenFixture(corev1alpha1.TaskTypeAI)
	token := taskTokenJWTForTest(t, now.Add(9*time.Minute), "scheduled-refresh")
	setRenewableTaskTokenSecret(secret, token, now.Add(2*time.Minute), 1)
	r := newUnitReconciler(newTestScheme(), task, secret, authority)

	result, err := r.handleWithTaskTransactionTokenRefresh(
		context.Background(), task,
		func(context.Context, *corev1alpha1.Task) (ctrl.Result, error) {
			return ctrl.Result{RequeueAfter: 10 * time.Minute}, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.RequeueAfter <= 0 || result.RequeueAfter > 2*time.Minute {
		t.Fatalf("RequeueAfter = %v, want capped at token refresh deadline", result.RequeueAfter)
	}
}

func TestActiveTaskTransactionTokenTransientRefreshFailureRetriesBeforeExpiry(t *testing.T) {
	now := time.Date(2026, time.August, 2, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name string
		err  error
	}{
		{name: "deadline", err: context.DeadlineExceeded},
		{name: "network", err: &net.DNSError{Err: "temporary resolver failure", Name: "transactions.example.test", IsTemporary: true}},
		{name: "redacted network", err: errors.New(taskTokenEndpointRequestFailed)},
		{name: "HTTP timeout", err: &tokenexchange.ExchangeError{StatusCode: http.StatusRequestTimeout}},
		{name: "rate limited", err: &tokenexchange.ExchangeError{StatusCode: http.StatusTooManyRequests}},
		{name: "server failure", err: &tokenexchange.ExchangeError{StatusCode: http.StatusServiceUnavailable}},
		{name: "OAuth server error", err: &tokenexchange.ExchangeError{StatusCode: http.StatusBadRequest, Code: "server_error"}},
		{name: "OAuth temporarily unavailable", err: &tokenexchange.ExchangeError{StatusCode: http.StatusBadRequest, Code: "temporarily_unavailable"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			task, secret, authority := renewableTaskTokenFixture(corev1alpha1.TaskTypeAI)
			token := taskTokenJWTForTest(t, now.Add(30*time.Second), "transient-"+test.name)
			setRenewableTaskTokenSecret(secret, token, now.Add(-time.Second), 1)
			exchanger := &queuedTaskTokenExchanger{err: test.err}
			r := newUnitReconciler(newTestScheme(), task, secret, authority)
			r.BrokeredTransactionExchange = testTaskTransactionExchangeConfig(exchanger)

			refreshAfter, fatal, err := r.reconcileActiveTaskTransactionToken(t.Context(), task, now)
			if err == nil || fatal {
				t.Fatalf("transient refresh = after:%v fatal:%v err:%v", refreshAfter, fatal, err)
			}
			if refreshAfter <= 0 || refreshAfter > taskTokenTransientRetryDelay || refreshAfter >= 30*time.Second {
				t.Fatalf("refreshAfter = %v, want a bounded retry before token expiry", refreshAfter)
			}
			if exchanger.calls != 1 {
				t.Fatalf("exchange calls = %d, want 1", exchanger.calls)
			}
			current := currentTaskTokenSecret(t, r, task)
			if got := string(current.Data[transactiontoken.TokenSecretKey]); got != token {
				t.Fatal("transient refresh failure replaced the still-valid token")
			}
			if got := string(current.Data[taskTokenGenerationSecretKey]); got != "1" {
				t.Fatalf("token generation = %q, want unchanged generation 1", got)
			}
		})
	}
}

func TestActiveTaskTransactionTokenPermanentRefreshFailureRemainsFatal(t *testing.T) {
	now := time.Date(2026, time.August, 2, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name string
		err  error
	}{
		{name: "canceled", err: context.Canceled},
		{name: "generic", err: errors.New("exchange unavailable")},
		{name: "permanent DNS", err: &net.DNSError{Err: "no such host", Name: "transactions.invalid", IsNotFound: true}},
		{name: "invalid scope", err: &tokenexchange.ExchangeError{StatusCode: http.StatusBadRequest, Code: "invalid_scope"}},
		{name: "unauthorized", err: &tokenexchange.ExchangeError{StatusCode: http.StatusUnauthorized, Code: "invalid_grant"}},
		{name: "unauthorized transient code", err: &tokenexchange.ExchangeError{StatusCode: http.StatusUnauthorized, Code: "temporarily_unavailable"}},
		{name: "forbidden", err: &tokenexchange.ExchangeError{StatusCode: http.StatusForbidden, Code: "access_denied"}},
		{name: "not found", err: &tokenexchange.ExchangeError{StatusCode: http.StatusNotFound}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			task, secret, authority := renewableTaskTokenFixture(corev1alpha1.TaskTypeAI)
			token := taskTokenJWTForTest(t, now.Add(30*time.Second), "permanent-"+test.name)
			setRenewableTaskTokenSecret(secret, token, now.Add(-time.Second), 1)
			r := newUnitReconciler(newTestScheme(), task, secret, authority)
			r.BrokeredTransactionExchange = testTaskTransactionExchangeConfig(&queuedTaskTokenExchanger{err: test.err})

			refreshAfter, fatal, err := r.reconcileActiveTaskTransactionToken(t.Context(), task, now)
			if err == nil || !fatal || refreshAfter != 0 {
				t.Fatalf("permanent refresh = after:%v fatal:%v err:%v", refreshAfter, fatal, err)
			}
		})
	}
}

func TestActiveTaskTransactionTokenTransientRefreshFailurePreservesTaskAndRequeues(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	task, secret, authority := renewableTaskTokenFixture(corev1alpha1.TaskTypeAI)
	token := taskTokenJWTForTest(t, now.Add(time.Minute), "transient-handler")
	setRenewableTaskTokenSecret(secret, token, now.Add(-time.Second), 1)
	r := newUnitReconciler(newTestScheme(), task, secret, authority)
	r.BrokeredTransactionExchange = testTaskTransactionExchangeConfig(
		&queuedTaskTokenExchanger{err: &tokenexchange.ExchangeError{StatusCode: http.StatusServiceUnavailable}},
	)
	handlerCalled := false

	result, err := r.handleWithTaskTransactionTokenRefresh(
		t.Context(), task,
		func(context.Context, *corev1alpha1.Task) (ctrl.Result, error) {
			handlerCalled = true
			return ctrl.Result{RequeueAfter: time.Minute}, nil
		},
	)
	if err != nil {
		t.Fatalf("handleWithTaskTransactionTokenRefresh() error = %v", err)
	}
	if handlerCalled {
		t.Fatal("task execution handler ran before the overdue token refresh was retried")
	}
	if result.RequeueAfter <= 0 || result.RequeueAfter > taskTokenTransientRetryDelay {
		t.Fatalf("RequeueAfter = %v, want bounded transient refresh retry", result.RequeueAfter)
	}
	updated := &corev1alpha1.Task{}
	if err := r.Get(t.Context(), client.ObjectKeyFromObject(task), updated); err != nil {
		t.Fatalf("get active Task: %v", err)
	}
	if updated.Status.Phase != corev1alpha1.TaskPhaseRunning {
		t.Fatalf("Task phase = %s, want Running", updated.Status.Phase)
	}
	if err := r.Get(t.Context(), client.ObjectKeyFromObject(secret), &corev1.Secret{}); err != nil {
		t.Fatalf("still-valid workload token Secret was removed: %v", err)
	}
	if err := r.Get(t.Context(), client.ObjectKeyFromObject(authority), &corev1.Secret{}); err != nil {
		t.Fatalf("renewal authority Secret was removed: %v", err)
	}
}

func TestActiveTaskTransactionTokenTransientFailureThatCrossesExpiryIsFatal(t *testing.T) {
	expiresAt := time.Date(2026, time.August, 2, 12, 0, 1, 0, time.UTC)
	now := expiresAt.Add(-50 * time.Millisecond)
	task, secret, authority := renewableTaskTokenFixture(corev1alpha1.TaskTypeAI)
	token := taskTokenJWTForTest(t, expiresAt, "expires-during-refresh")
	setRenewableTaskTokenSecret(secret, token, now.Add(-time.Second), 1)
	exchanger := &queuedTaskTokenExchanger{
		err: &tokenexchange.ExchangeError{StatusCode: http.StatusServiceUnavailable}, delay: 100 * time.Millisecond,
	}
	r := newUnitReconciler(newTestScheme(), task, secret, authority)
	r.BrokeredTransactionExchange = testTaskTransactionExchangeConfig(exchanger)

	refreshAfter, fatal, err := r.reconcileActiveTaskTransactionToken(t.Context(), task, now)
	if err == nil || !fatal || refreshAfter != 0 {
		t.Fatalf("expiry-crossing refresh = after:%v fatal:%v err:%v", refreshAfter, fatal, err)
	}
}

func TestActiveTaskTransactionTokenFailsClosedAtOrAfterExpiry(t *testing.T) {
	expiresAt := time.Date(2026, time.August, 2, 12, 0, 30, 0, time.UTC)
	for _, now := range []time.Time{expiresAt, expiresAt.Add(time.Second)} {
		t.Run(now.Format(time.RFC3339), func(t *testing.T) {
			task, secret, authority := renewableTaskTokenFixture(corev1alpha1.TaskTypeAI)
			token := taskTokenJWTForTest(t, expiresAt, "expired-transient")
			setRenewableTaskTokenSecret(secret, token, expiresAt.Add(-time.Second), 1)
			exchanger := &queuedTaskTokenExchanger{err: &tokenexchange.ExchangeError{StatusCode: http.StatusServiceUnavailable}}
			r := newUnitReconciler(newTestScheme(), task, secret, authority)
			r.BrokeredTransactionExchange = testTaskTransactionExchangeConfig(exchanger)

			refreshAfter, fatal, err := r.reconcileActiveTaskTransactionToken(t.Context(), task, now)
			if err == nil || !fatal || refreshAfter != 0 {
				t.Fatalf("expired refresh = after:%v fatal:%v err:%v", refreshAfter, fatal, err)
			}
			if exchanger.calls != 0 {
				t.Fatalf("exchange calls = %d, want no exchange at/after expiry", exchanger.calls)
			}
		})
	}
}

func TestActiveTaskTransactionTokenRefreshFailureCleansUpAndFailsClosed(t *testing.T) {
	now := time.Now().UTC()
	task, secret, authority := renewableTaskTokenFixture(corev1alpha1.TaskTypeAI)
	task.Status.Phase = corev1alpha1.TaskPhaseRunning
	token := taskTokenJWTForTest(t, now.Add(5*time.Minute), "refresh-failure")
	setRenewableTaskTokenSecret(secret, token, now.Add(-time.Second), 1)
	r := newUnitReconciler(newTestScheme(), task, secret, authority)
	r.BrokeredTransactionExchange = testTaskTransactionExchangeConfig(
		&queuedTaskTokenExchanger{err: errors.New("exchange unavailable")},
	)
	handlerCalled := false

	if _, err := r.handleWithTaskTransactionTokenRefresh(
		context.Background(), task,
		func(context.Context, *corev1alpha1.Task) (ctrl.Result, error) {
			handlerCalled = true
			return ctrl.Result{}, nil
		},
	); err != nil {
		t.Fatalf("handleWithTaskTransactionTokenRefresh() error = %v", err)
	}
	if handlerCalled {
		t.Fatal("task execution handler ran after token refresh failure")
	}
	updated := &corev1alpha1.Task{}
	if err := r.Get(context.Background(), client.ObjectKeyFromObject(task), updated); err != nil {
		t.Fatalf("get failed Task: %v", err)
	}
	if updated.Status.Phase != corev1alpha1.TaskPhaseFailed ||
		strings.Contains(updated.Status.Message, testRenewableSubjectToken) {
		t.Fatalf("failed Task status = %s/%q", updated.Status.Phase, updated.Status.Message)
	}
	if err := r.Get(context.Background(), client.ObjectKeyFromObject(secret), &corev1.Secret{}); !apierrors.IsNotFound(err) {
		t.Fatalf("renewal authority Secret remained after refresh failure: %v", err)
	}
}

func TestHandleCompletedCleansTaskTransactionTokenSecret(t *testing.T) {
	task, secret, authority := renewableTaskTokenFixture(corev1alpha1.TaskTypeAgent)
	task.Status.Phase = corev1alpha1.TaskPhaseSucceeded
	r := newUnitReconciler(newTestScheme(), task, secret, authority)

	if _, err := r.handleCompleted(context.Background(), task); err != nil {
		t.Fatalf("handleCompleted() error = %v", err)
	}
	if err := r.Get(context.Background(), client.ObjectKeyFromObject(secret), &corev1.Secret{}); !apierrors.IsNotFound(err) {
		t.Fatalf("terminal Task transaction token Secret remained: %v", err)
	}
	if err := r.Get(context.Background(), client.ObjectKeyFromObject(authority), &corev1.Secret{}); !apierrors.IsNotFound(err) {
		t.Fatalf("terminal Task renewal authority remained: %v", err)
	}
}

func renewableTaskTokenFixture(taskType corev1alpha1.TaskType) (*corev1alpha1.Task, *corev1.Secret, *corev1.Secret) {
	task := &corev1alpha1.Task{
		ObjectMeta: metav1.ObjectMeta{
			Name: "renewable-task", Namespace: defaultNS, UID: types.UID("renewable-task-uid"),
			Annotations: map[string]string{labels.AnnotationTransactionTokenSecret: testRenewableSecretName},
		},
		Spec: corev1alpha1.TaskSpec{
			Type: taskType,
			Transaction: &corev1alpha1.TaskTransaction{
				ID: "txn-renewable", Scope: directTokenMemoryReadScope,
				Scopes: []string{directTokenMemoryReadScope},
			},
		},
		Status: corev1alpha1.TaskStatus{Phase: corev1alpha1.TaskPhaseRunning},
	}
	secret := directTaskTokenWorkloadSecretForTest(task, testRenewableSecretName)
	authority := directTaskTokenAuthoritySecretForTest(task, testRenewableSubjectToken)
	return task, secret, authority
}

func pendingDirectTaskTokenFixture(pendingSince time.Time) (*corev1alpha1.Task, *corev1.Secret, *corev1.Secret) {
	task, workload, authority := renewableTaskTokenFixture(corev1alpha1.TaskTypeAI)
	task.Status.Phase = corev1alpha1.TaskPhasePending
	task.Annotations[labels.AnnotationTransactionTokenPending] = scheduledRunLabelValue
	task.Annotations[labels.AnnotationTransactionTokenPendingSince] = pendingSince.Format(time.RFC3339Nano)
	return task, workload, authority
}

func assertPendingTaskTransactionTokenFailedClosed(
	t *testing.T,
	r *TaskReconciler,
	task *corev1alpha1.Task,
	workload, authority *corev1.Secret,
) {
	t.Helper()
	updated := &corev1alpha1.Task{}
	if err := r.Get(t.Context(), client.ObjectKeyFromObject(task), updated); err != nil {
		t.Fatalf("get failed Task: %v", err)
	}
	if updated.Status.Phase != corev1alpha1.TaskPhaseFailed {
		t.Fatalf("Task phase = %s, want Failed", updated.Status.Phase)
	}
	if err := r.Get(t.Context(), client.ObjectKeyFromObject(workload), &corev1.Secret{}); !apierrors.IsNotFound(err) {
		t.Fatalf("workload token Secret remained after fail-closed cleanup: %v", err)
	}
	if err := r.Get(t.Context(), client.ObjectKeyFromObject(authority), &corev1.Secret{}); !apierrors.IsNotFound(err) {
		t.Fatalf("renewal authority Secret remained after fail-closed cleanup: %v", err)
	}
	jobs := &batchv1.JobList{}
	if err := r.List(t.Context(), jobs, client.InNamespace(task.Namespace)); err != nil {
		t.Fatalf("list Jobs: %v", err)
	}
	if len(jobs.Items) != 0 {
		t.Fatalf("created %d Jobs after fail-closed token setup", len(jobs.Items))
	}
}

func directTaskTokenWorkloadSecretForTest(task *corev1alpha1.Task, name string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: task.Namespace, UID: types.UID("uid-" + name),
			Labels: map[string]string{
				labels.LabelPurpose: transactiontoken.WorkloadSecretPurpose,
				labels.LabelTaskUID: labels.SelectorValue(string(task.UID)),
			},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: corev1alpha1.GroupVersion.String(), Kind: taskTransactionTokenOwnerKind,
				Name: task.Name, UID: task.UID,
			}},
		},
		Type: corev1.SecretTypeOpaque, Data: map[string][]byte{},
	}
}

func directTaskTokenAuthoritySecretForTest(task *corev1alpha1.Task, subject string) *corev1.Secret {
	return directTaskTokenAuthoritySecretWithTypeForTest(task, subject, transactiontoken.SubjectTokenTypeTransactionToken)
}

func directTaskTokenAuthoritySecretWithTypeForTest(task *corev1alpha1.Task, subject, subjectTokenType string) *corev1.Secret {
	requestDetails := taskTransactionTokenRequestDetails(task, 0)
	delete(requestDetails, taskTokenRequestRotationKey)
	encodedRequestDetails, err := json.Marshal(requestDetails)
	if err != nil {
		panic(err)
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: testRenewableSecretName + "-authority", Namespace: task.Namespace,
			UID: types.UID("uid-" + task.Name + "-authority"),
			Labels: map[string]string{
				labels.LabelPurpose: transactiontoken.AuthoritySecretPurpose,
				labels.LabelTaskUID: labels.SelectorValue(string(task.UID)),
			},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: corev1alpha1.GroupVersion.String(), Kind: taskTransactionTokenOwnerKind,
				Name: task.Name, UID: task.UID,
			}},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			transactiontoken.SubjectSecretKey:          []byte(subject),
			transactiontoken.SubjectTokenTypeSecretKey: []byte(subjectTokenType),
			transactiontoken.RequestDetailsSecretKey:   encodedRequestDetails,
		},
	}
}

func testTaskTransactionExchangeConfig(exchanger contexttoken.Exchanger) *workerpkg.TransactionExchangeConfig {
	return &workerpkg.TransactionExchangeConfig{
		TTS: contexttoken.TTSConfig{
			Endpoint:      testTaskTokenEndpoint,
			TokenSource:   contexttoken.TTSTokenSourceIncoming,
			ChildTokenTTL: 5 * time.Minute,
		},
		Exchanger: exchanger,
	}
}

func currentTaskTokenSecret(t *testing.T, r *TaskReconciler, task *corev1alpha1.Task) *corev1.Secret {
	t.Helper()
	secret := &corev1.Secret{}
	if err := r.Get(context.Background(), types.NamespacedName{
		Namespace: task.Namespace, Name: task.Annotations[labels.AnnotationTransactionTokenSecret],
	}, secret); err != nil {
		t.Fatalf("get task token Secret: %v", err)
	}
	return secret
}

func setRenewableTaskTokenSecret(secret *corev1.Secret, token string, refreshAt time.Time, generation uint64) {
	expiresAt, err := unverifiedTaskTokenExpiry(token)
	if err != nil {
		panic(err)
	}
	secret.Data = map[string][]byte{
		transactiontoken.TokenSecretKey: []byte(token),
		taskTokenExpiresAtSecretKey:     []byte(expiresAt.Format(time.RFC3339Nano)),
		taskTokenRefreshAtSecretKey:     []byte(refreshAt.UTC().Format(time.RFC3339Nano)),
		taskTokenGenerationSecretKey:    []byte(strconv.FormatUint(generation, 10)),
	}
}

func taskTokenJWTForTest(t *testing.T, expiresAt time.Time, marker string) string {
	t.Helper()
	header, err := json.Marshal(map[string]any{"alg": "none", "typ": "txntoken+jwt"})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{"exp": expiresAt.Unix(), "jti": marker})
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(payload) + ".signature"
}

type queuedTaskTokenExchanger struct {
	tokens   []string
	requests []contexttoken.ExchangeRequest
	err      error
	delay    time.Duration
	calls    int
}

func (e *queuedTaskTokenExchanger) Exchange(ctx context.Context, request contexttoken.ExchangeRequest) (string, error) {
	e.calls++
	if e.delay > 0 {
		timer := time.NewTimer(e.delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	e.requests = append(e.requests, request)
	if e.err != nil {
		return "", e.err
	}
	if len(e.tokens) == 0 {
		return "", errors.New("no queued task token")
	}
	token := e.tokens[0]
	e.tokens = e.tokens[1:]
	return token, nil
}

func TestTaskTransactionTokenRotationUsesPersistedSubjectTypeAcrossRollout(t *testing.T) {
	now := time.Now().UTC()
	tests := []struct {
		name          string
		persistedType string
		currentSource string
	}{
		{name: "incoming authority after serviceAccount rollout", persistedType: transactiontoken.SubjectTokenTypeTransactionToken, currentSource: contexttoken.TTSTokenSourceServiceAccount},
		{name: "serviceAccount authority after incoming rollout", persistedType: transactiontoken.SubjectTokenTypeAccessToken, currentSource: contexttoken.TTSTokenSourceIncoming},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			task, workload, _ := renewableTaskTokenFixture(corev1alpha1.TaskTypeAgent)
			authority := directTaskTokenAuthoritySecretWithTypeForTest(task, testRenewableSubjectToken, tt.persistedType)
			exchanger := &queuedTaskTokenExchanger{tokens: []string{taskTokenJWTForTest(t, now.Add(5*time.Minute), tt.name)}}
			// A new reconciler models controller restart after the global tokenSource rollout.
			r := newUnitReconciler(newTestScheme(), task, workload, authority)
			r.BrokeredTransactionExchange = testTaskTransactionExchangeConfig(exchanger)
			r.BrokeredTransactionExchange.TTS.TokenSource = tt.currentSource
			ready, fatal, err := r.reconcilePendingTaskTransactionToken(context.Background(), task, now)
			if err != nil || fatal || !ready {
				t.Fatalf("rotation = ready:%v fatal:%v err:%v", ready, fatal, err)
			}
			if got := exchanger.requests[0].SubjectTokenType; got != tt.persistedType {
				t.Fatalf("subject type = %q, want persisted %q", got, tt.persistedType)
			}
		})
	}
}
