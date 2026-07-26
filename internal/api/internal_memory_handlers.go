/*
Copyright (c) 2026.

MIT License - see LICENSE file for details.
*/

package api

import (
	"github.com/gofiber/fiber/v3"

	"github.com/orka-agents/orka/internal/store"
)

func (h *InternalHandlers) internalNamespace(c fiber.Ctx) (string, error) {
	namespace := c.Params("namespace")
	if namespace == "" {
		return "", fiber.NewError(fiber.StatusBadRequest, "namespace is required")
	}
	if err := h.internalCallerAuthorizer().verifyNamespace(c, namespace); err != nil {
		return "", err
	}
	return namespace, nil
}

// ListMemories lists memories for the namespace in the internal route.
func (h *InternalHandlers) ListMemories(c fiber.Ctx) error {
	namespace, err := h.internalNamespace(c)
	if err != nil {
		return err
	}
	if err := requireMemoryStore(h.memoryStore); err != nil {
		return err
	}
	filter, err := parseMemoryFilter(c, namespace)
	if err != nil {
		return err
	}
	memories, err := listMemories(c.Context(), h.memoryStore, filter)
	if err != nil {
		return err
	}
	return c.JSON(memories)
}

// CreateMemory creates a memory in the namespace in the internal route.
func (h *InternalHandlers) CreateMemory(c fiber.Ctx) error {
	namespace, err := h.internalNamespace(c)
	if err != nil {
		return err
	}
	if err := requireMemoryStore(h.memoryStore); err != nil {
		return err
	}
	var memory store.Memory
	if err := c.Bind().JSON(&memory); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}
	if memory.Namespace != "" && memory.Namespace != namespace {
		return fiber.NewError(fiber.StatusBadRequest, "memory namespace mismatch")
	}
	memory.Namespace = namespace
	if err := createMemory(c.Context(), h.memoryStore, &memory); err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(memory)
}

// GetMemory gets a memory by ID from the namespace in the internal route.
func (h *InternalHandlers) GetMemory(c fiber.Ctx) error {
	namespace, err := h.internalNamespace(c)
	if err != nil {
		return err
	}
	if err := requireMemoryStore(h.memoryStore); err != nil {
		return err
	}
	memory, err := getMemory(c.Context(), h.memoryStore, namespace, c.Params("id"))
	if err != nil {
		return err
	}
	return c.JSON(memory)
}

// UpdateMemory updates a memory in the namespace in the internal route.
func (h *InternalHandlers) UpdateMemory(c fiber.Ctx) error {
	namespace, err := h.internalNamespace(c)
	if err != nil {
		return err
	}
	if err := requireMemoryStore(h.memoryStore); err != nil {
		return err
	}
	var req store.Memory
	if err := c.Bind().JSON(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}
	if req.Namespace != "" && req.Namespace != namespace {
		return fiber.NewError(fiber.StatusBadRequest, "memory namespace mismatch")
	}
	updated, err := updateMemory(c.Context(), h.memoryStore, namespace, c.Params("id"), req)
	if err != nil {
		return err
	}
	return c.JSON(updated)
}

// DeleteMemory soft-deletes a memory in the namespace in the internal route.
func (h *InternalHandlers) DeleteMemory(c fiber.Ctx) error {
	namespace, err := h.internalNamespace(c)
	if err != nil {
		return err
	}
	if err := requireMemoryStore(h.memoryStore); err != nil {
		return err
	}
	if err := deleteMemory(c.Context(), h.memoryStore, namespace, c.Params("id")); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// DisableMemory disables a memory for recall in the namespace in the internal route.
func (h *InternalHandlers) DisableMemory(c fiber.Ctx) error {
	return h.setMemoryDisabled(c, true)
}

// EnableMemory enables a memory for recall in the namespace in the internal route.
func (h *InternalHandlers) EnableMemory(c fiber.Ctx) error {
	return h.setMemoryDisabled(c, false)
}

func (h *InternalHandlers) setMemoryDisabled(c fiber.Ctx, disabled bool) error {
	namespace, err := h.internalNamespace(c)
	if err != nil {
		return err
	}
	if err := requireMemoryStore(h.memoryStore); err != nil {
		return err
	}
	if err := setMemoryDisabled(c.Context(), h.memoryStore, namespace, c.Params("id"), disabled); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// ListMemoryProposals lists memory proposals for the namespace in the internal route.
func (h *InternalHandlers) ListMemoryProposals(c fiber.Ctx) error {
	namespace, err := h.internalNamespace(c)
	if err != nil {
		return err
	}
	if err := requireMemoryProposalStore(h.memoryProposalStore); err != nil {
		return err
	}
	filter, err := parseMemoryProposalFilter(c, namespace)
	if err != nil {
		return err
	}
	proposals, err := listMemoryProposals(c.Context(), h.memoryProposalStore, filter)
	if err != nil {
		return err
	}
	return c.JSON(proposals)
}

// CreateMemoryProposal creates a memory governance proposal in the namespace in the internal route.
func (h *InternalHandlers) CreateMemoryProposal(c fiber.Ctx) error {
	namespace, err := h.internalNamespace(c)
	if err != nil {
		return err
	}
	if err := requireMemoryProposalStore(h.memoryProposalStore); err != nil {
		return err
	}
	var proposal store.MemoryProposal
	if err := c.Bind().JSON(&proposal); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}
	if proposal.Namespace != "" && proposal.Namespace != namespace {
		return fiber.NewError(fiber.StatusBadRequest, "memory proposal namespace mismatch")
	}
	proposal.Namespace = namespace
	if err := createMemoryProposal(c.Context(), h.memoryProposalStore, &proposal); err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(proposal)
}

// GetMemoryProposal gets a memory proposal by ID from the namespace in the internal route.
func (h *InternalHandlers) GetMemoryProposal(c fiber.Ctx) error {
	namespace, err := h.internalNamespace(c)
	if err != nil {
		return err
	}
	if err := requireMemoryProposalStore(h.memoryProposalStore); err != nil {
		return err
	}
	proposal, err := getMemoryProposal(c.Context(), h.memoryProposalStore, namespace, c.Params("id"))
	if err != nil {
		return err
	}
	return c.JSON(proposal)
}

// ReviewMemoryProposal records a review decision without applying the proposal automatically.
func (h *InternalHandlers) ReviewMemoryProposal(c fiber.Ctx) error {
	namespace, err := h.internalNamespace(c)
	if err != nil {
		return err
	}
	if err := requireMemoryProposalStore(h.memoryProposalStore); err != nil {
		return err
	}
	review, err := bindMemoryProposalReview(c, namespace, c.Params("id"))
	if err != nil {
		return err
	}
	if review.Namespace != namespace {
		return fiber.NewError(fiber.StatusBadRequest, "memory proposal namespace mismatch")
	}
	if review.Reviewer == "" {
		if ui := GetUserInfo(c); ui != nil {
			review.Reviewer = ui.Username
		}
	}
	if err := reviewMemoryProposal(c.Context(), h.memoryProposalStore, review); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// ArchiveMemoryProposal archives a proposal in the namespace in the internal route without applying it.
func (h *InternalHandlers) ArchiveMemoryProposal(c fiber.Ctx) error {
	namespace, err := h.internalNamespace(c)
	if err != nil {
		return err
	}
	if err := requireMemoryProposalStore(h.memoryProposalStore); err != nil {
		return err
	}
	if err := archiveMemoryProposal(c.Context(), h.memoryProposalStore, namespace, c.Params("id")); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// ApplyMemoryProposal applies an accepted memory proposal into durable memory in the namespace in the internal route.
func (h *InternalHandlers) ApplyMemoryProposal(c fiber.Ctx) error {
	namespace, err := h.internalNamespace(c)
	if err != nil {
		return err
	}
	if err := requireMemoryProposalStore(h.memoryProposalStore); err != nil {
		return err
	}
	apply, err := bindMemoryProposalApply(c, namespace, c.Params("id"))
	if err != nil {
		return err
	}
	if apply.Namespace != namespace {
		return fiber.NewError(fiber.StatusBadRequest, "memory proposal namespace mismatch")
	}
	if apply.AppliedBy == "" {
		if ui := GetUserInfo(c); ui != nil {
			apply.AppliedBy = ui.Username
		}
	}
	memory, err := applyMemoryProposal(c.Context(), h.memoryProposalStore, apply)
	if err != nil {
		return err
	}
	return c.JSON(memory)
}
