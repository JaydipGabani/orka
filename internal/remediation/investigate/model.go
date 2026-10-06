package investigate

import (
	"context"
	"errors"

	modelagent "github.com/orka-agents/orka/internal/remediation/agent"
	"k8s.io/apimachinery/pkg/util/validation"
)

func (engine Engine) generate(ctx context.Context, state State, prompt string, config Config) (State, string, bool, error) {
	if engine.Generator == nil {
		return blocked(state, NeedsAdapter, "model_adapter_required"), "", false, nil
	}
	state, index, err := prepareTask(state, prompt, config)
	if err != nil {
		return state, "", false, err
	}
	if index < 0 {
		return state, "", false, nil
	}
	task := &state.ModelTasks[index]
	// Repository/Commit deliberately stay empty. The model has only bounded
	// report/inventory data, never a checkout, driver configuration or credentials.
	result, generateErr := engine.Generator.Generate(ctx, modelagent.Request{
		TaskName: task.TaskName, ExpectedTaskUID: task.TaskUID, Prompt: prompt, MaxTurns: config.MaxTurns,
	})
	if !acceptTaskResult(task, result, generateErr) {
		return blocked(state, NeedsInput, "model_task_identity_mismatch"), "", false, ErrState
	}
	if err := cancellation(ctx, generateErr); err != nil {
		state.SafeError = "model_operation_cancelled"
		return state, "", false, err
	}
	if generateErr != nil {
		state.SafeError = "model_operation_incomplete"
		return state, "", false, ErrModelOperation
	}
	task.Completed = true
	return state, result.Output, true, nil
}

func prepareTask(state State, prompt string, config Config) (State, int, error) {
	if len(validation.IsDNS1123Subdomain(config.RequestTaskName)) != 0 ||
		(config.ExpectedTaskUID != "" && !validUID(config.ExpectedTaskUID)) {
		return state, -1, ErrConfig
	}
	requestDigest := digest([]byte(prompt))
	if last := len(state.ModelTasks) - 1; last >= 0 && !state.ModelTasks[last].Completed {
		task := &state.ModelTasks[last]
		if task.Stage != state.Stage || task.TaskName != config.RequestTaskName || task.RequestDigest != requestDigest ||
			(config.ExpectedTaskUID != "" && task.TaskUID != "" && config.ExpectedTaskUID != task.TaskUID) {
			return state, -1, ErrState
		}
		if task.TaskUID == "" {
			task.TaskUID = config.ExpectedTaskUID
		}
		return state, last, nil
	}
	for _, task := range state.ModelTasks {
		if task.TaskName == config.RequestTaskName {
			return state, -1, ErrState
		}
	}
	round := 0
	switch state.Stage {
	case Identifying:
		if state.DiscoveryRounds >= config.MaxDiscoveryRounds {
			return blocked(state, NeedsInput, "discovery_budget_exhausted"), -1, nil
		}
		state.DiscoveryRounds++
		round = state.DiscoveryRounds
	case Selecting:
		if state.SelectionRounds >= config.MaxSelectionRounds {
			return blocked(state, NeedsInput, "selection_budget_exhausted"), -1, nil
		}
		state.SelectionRounds++
		round = state.SelectionRounds
	default:
		return state, -1, ErrState
	}
	state.ModelTasks = append(state.ModelTasks, TaskIdentity{
		TaskName: config.RequestTaskName, TaskUID: config.ExpectedTaskUID, Stage: state.Stage, Round: round, RequestDigest: requestDigest,
	})
	return state, len(state.ModelTasks) - 1, nil
}

func acceptTaskResult(task *TaskIdentity, result modelagent.Result, operationErr error) bool {
	if result.TaskName != "" && result.TaskName != task.TaskName {
		return false
	}
	if result.TaskUID != "" {
		if result.TaskName != task.TaskName || !validUID(result.TaskUID) || (task.TaskUID != "" && result.TaskUID != task.TaskUID) {
			return false
		}
		task.TaskUID = result.TaskUID
	}
	return operationErr != nil || (result.TaskName == task.TaskName && result.TaskUID != "")
}

func validUID(value string) bool {
	return requirementName.MatchString(value)
}

func cancellation(ctx context.Context, operationErr error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, err := range []error{context.Canceled, context.DeadlineExceeded} {
		if errors.Is(operationErr, err) {
			return err
		}
	}
	return nil
}
