/*
Copyright (c) 2026.

MIT License - see LICENSE file for details.
*/

package api

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/gofiber/fiber/v3"

	"github.com/orka-agents/orka/internal/store"
)

func requireMemoryStore(memoryStore store.MemoryStore) error {
	if memoryStore == nil {
		return fiber.NewError(fiber.StatusNotImplemented, "memory store not configured")
	}
	return nil
}

func requireMemoryProposalStore(proposalStore store.MemoryProposalStore) error {
	if proposalStore == nil {
		return fiber.NewError(fiber.StatusNotImplemented, "memory proposal store not configured")
	}
	return nil
}

func listMemories(ctx context.Context, memoryStore store.MemoryStore, filter store.MemoryFilter) ([]store.Memory, error) {
	memories, err := memoryStore.ListMemories(ctx, filter)
	if err != nil {
		return nil, memoryStoreError("list memories", "memory", err)
	}
	return memories, nil
}

func createMemory(ctx context.Context, memoryStore store.MemoryStore, memory *store.Memory) error {
	if strings.TrimSpace(memory.Content) == "" {
		return fiber.NewError(fiber.StatusBadRequest, "content is required")
	}
	if err := memoryStore.CreateMemory(ctx, memory); err != nil {
		return memoryStoreError("create memory", "memory", err)
	}
	return nil
}

func getMemory(ctx context.Context, memoryStore store.MemoryStore, namespace, id string) (*store.Memory, error) {
	memory, err := memoryStore.GetMemory(ctx, namespace, id)
	if err != nil {
		return nil, memoryStoreError("get memory", "memory", err)
	}
	return memory, nil
}

func updateMemory(
	ctx context.Context,
	memoryStore store.MemoryStore,
	namespace, id string,
	req store.Memory,
) (*store.Memory, error) {
	memory, err := getMemory(ctx, memoryStore, namespace, id)
	if err != nil {
		return nil, err
	}
	applyMemoryUpdate(memory, req)
	memory.Namespace = namespace
	memory.ID = id
	if strings.TrimSpace(memory.Content) == "" {
		return nil, fiber.NewError(fiber.StatusBadRequest, "content is required")
	}
	if err := memoryStore.UpdateMemory(ctx, memory); err != nil {
		return nil, memoryStoreError("update memory", "memory", err)
	}
	return getMemory(ctx, memoryStore, namespace, id)
}

func deleteMemory(ctx context.Context, memoryStore store.MemoryStore, namespace, id string) error {
	if err := memoryStore.DeleteMemory(ctx, namespace, id); err != nil {
		return memoryStoreError("delete memory", "memory", err)
	}
	return nil
}

func setMemoryDisabled(
	ctx context.Context,
	memoryStore store.MemoryStore,
	namespace, id string,
	disabled bool,
) error {
	if err := memoryStore.SetMemoryDisabled(ctx, namespace, id, disabled); err != nil {
		return memoryStoreError("update memory", "memory", err)
	}
	return nil
}

func listMemoryProposals(
	ctx context.Context,
	proposalStore store.MemoryProposalStore,
	filter store.MemoryProposalFilter,
) ([]store.MemoryProposal, error) {
	proposals, err := proposalStore.ListMemoryProposals(ctx, filter)
	if err != nil {
		return nil, memoryStoreError("list memory proposals", "memory proposal", err)
	}
	return proposals, nil
}

func createMemoryProposal(
	ctx context.Context,
	proposalStore store.MemoryProposalStore,
	proposal *store.MemoryProposal,
) error {
	if strings.TrimSpace(proposal.Title) == "" {
		return fiber.NewError(fiber.StatusBadRequest, "title is required")
	}
	if err := proposalStore.CreateMemoryProposal(ctx, proposal); err != nil {
		return memoryStoreError("create memory proposal", "memory proposal", err)
	}
	return nil
}

func getMemoryProposal(
	ctx context.Context,
	proposalStore store.MemoryProposalStore,
	namespace, id string,
) (*store.MemoryProposal, error) {
	proposal, err := proposalStore.GetMemoryProposal(ctx, namespace, id)
	if err != nil {
		return nil, memoryStoreError("get memory proposal", "memory proposal", err)
	}
	return proposal, nil
}

func reviewMemoryProposal(
	ctx context.Context,
	proposalStore store.MemoryProposalStore,
	review store.MemoryProposalReview,
) error {
	if err := proposalStore.ReviewMemoryProposal(ctx, review); err != nil {
		return memoryStoreError("review memory proposal", "memory proposal", err)
	}
	return nil
}

func archiveMemoryProposal(
	ctx context.Context,
	proposalStore store.MemoryProposalStore,
	namespace, id string,
) error {
	if err := proposalStore.ArchiveMemoryProposal(ctx, namespace, id); err != nil {
		return memoryStoreError("archive memory proposal", "memory proposal", err)
	}
	return nil
}

func applyMemoryProposal(
	ctx context.Context,
	proposalStore store.MemoryProposalStore,
	apply store.MemoryProposalApply,
) (*store.Memory, error) {
	memory, err := proposalStore.ApplyMemoryProposal(ctx, apply)
	if err != nil {
		return nil, memoryStoreError("apply memory proposal", "memory proposal", err)
	}
	return memory, nil
}

func applyMemoryUpdate(memory *store.Memory, req store.Memory) {
	if req.SessionName != "" {
		memory.SessionName = req.SessionName
	}
	if req.AgentName != "" {
		memory.AgentName = req.AgentName
	}
	if req.TaskName != "" {
		memory.TaskName = req.TaskName
	}
	if req.ParentTask != "" {
		memory.ParentTask = req.ParentTask
	}
	if req.Source != "" {
		memory.Source = req.Source
	}
	if req.Content != "" {
		memory.Content = req.Content
	}
	if req.Tags != nil {
		memory.Tags = req.Tags
	}
	if req.Disabled {
		memory.Disabled = true
	}
	if req.Deleted {
		memory.Deleted = true
	}
}

func memoryStoreError(action, resource string, err error) error {
	if errors.Is(err, store.ErrNotFound) {
		return fiber.NewError(fiber.StatusNotFound, fmt.Sprintf("%s not found", resource))
	}
	if errors.Is(err, store.ErrConflict) {
		return fiber.NewError(fiber.StatusConflict, err.Error())
	}
	if isStoreValidationError(err) {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	return fiber.NewError(fiber.StatusInternalServerError, fmt.Sprintf("failed to %s: %v", action, err))
}

func isStoreValidationError(err error) bool {
	return errors.Is(err, store.ErrValidation)
}
