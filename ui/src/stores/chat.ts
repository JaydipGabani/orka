import { create } from 'zustand'
import { persist, type PersistStorage, type StorageValue } from 'zustand/middleware'
import type { ChatMessage, ChatUsage } from '@/schemas/chat'

interface ChatState {
  messages: ChatMessage[]
  currentSessionId: string | null
  isStreaming: boolean
  // Provider CRD name and model sent with each turn; empty means "server default".
  provider: string
  model: string
  // Actions
  setProvider: (provider: string) => void
  setModel: (model: string) => void
  addMessage: (message: ChatMessage) => void
  updateLastAssistantMessage: (content: string) => void
  setSessionId: (id: string) => void
  setStreaming: (streaming: boolean) => void
  newSession: () => void
  setUsageOnLastAssistant: (usage: ChatUsage, tasksCreatedNames?: string[]) => void
}

// Browser localStorage when available; an in-memory fallback otherwise (Node
// exposes a bare `localStorage` global that is unusable without a backing file,
// and some jsdom setups have none). The fallback keeps the picker working for
// the page lifetime without persisting across reloads.
function rawStorage(): Pick<Storage, 'getItem' | 'setItem' | 'removeItem'> {
  try {
    if (typeof window !== 'undefined' && window.localStorage) return window.localStorage
  } catch {
    // Access can throw (opaque origin, blocked site data); fall through.
  }
  const memory = new Map<string, string>()
  return {
    getItem: (key) => memory.get(key) ?? null,
    setItem: (key, value) => {
      memory.set(key, value)
    },
    removeItem: (key) => {
      memory.delete(key)
    },
  }
}

type PersistedChatState = Pick<ChatState, 'provider' | 'model'>

// Hand-rolled JSON storage (instead of createJSONStorage) so test suites that
// stub `zustand/middleware` with only `persist` keep working.
function chatStorage(): PersistStorage<PersistedChatState> {
  const raw = rawStorage()
  return {
    getItem: (name) => {
      const value = raw.getItem(name)
      if (!value) return null
      try {
        return JSON.parse(value) as StorageValue<PersistedChatState>
      } catch {
        return null
      }
    },
    setItem: (name, value) => raw.setItem(name, JSON.stringify(value)),
    removeItem: (name) => raw.removeItem(name),
  }
}

let msgCounter = 0
export function generateMessageId(): string {
  return `msg-${Date.now()}-${++msgCounter}`
}

export const useChatStore = create<ChatState>()(
  persist(
    (set) => ({
  messages: [],
  currentSessionId: null,
  isStreaming: false,
  provider: '',
  model: '',

  setProvider: (provider) => set({ provider }),
  setModel: (model) => set({ model }),

  addMessage: (message) =>
    set((state) => ({ messages: [...state.messages, message] })),

  updateLastAssistantMessage: (content) =>
    set((state) => {
      const msgs = [...state.messages]
      for (let i = msgs.length - 1; i >= 0; i--) {
        if (msgs[i].role === 'assistant') {
          msgs[i] = { ...msgs[i], content }
          break
        }
      }
      return { messages: msgs }
    }),

  setSessionId: (id) => set({ currentSessionId: id }),
  setStreaming: (streaming) => set({ isStreaming: streaming }),
  newSession: () => set({ messages: [], currentSessionId: null }),

  setUsageOnLastAssistant: (usage, tasksCreatedNames) =>
    set((state) => {
      const msgs = [...state.messages]
      for (let i = msgs.length - 1; i >= 0; i--) {
        if (msgs[i].role === 'assistant') {
          msgs[i] = {
            ...msgs[i],
            usage,
            ...(tasksCreatedNames && tasksCreatedNames.length > 0
              ? { tasksCreatedNames }
              : {}),
          }
          break
        }
      }
      return { messages: msgs }
    }),
    }),
    // Only the picker choice survives reloads; transcripts stay per-page.
    {
      name: 'orka-chat',
      storage: chatStorage(),
      partialize: (state) => ({ provider: state.provider, model: state.model }),
    },
  ),
)
