import { describe, it, expect, vi, beforeEach } from 'vitest'

vi.mock('zustand/middleware', async () => {
  const actual = await vi.importActual('zustand/middleware')
  return { ...actual, persist: (fn: any) => fn }
})

vi.mock('@/hooks/use-chat', () => ({
  useSendMessage: () => vi.fn(),
  useChatConfig: () => ({ data: { model: 'claude-sonnet-4-20250514', provider: 'anthropic', enabled: true } }),
}))

vi.mock('@/hooks/use-providers', () => ({
  useProviderList: () => ({
    data: {
      items: [
        { name: 'anthropic', type: 'anthropic', defaultModel: 'claude-sonnet-4-20250514', ready: true },
        { name: 'openai-proxy', type: 'openai', defaultModel: 'gpt-5', ready: true },
      ],
    },
  }),
}))

import { fireEvent, waitFor } from '@testing-library/react'

import { render, screen } from '@/test/test-utils'
import { ChatPage } from './chat-page'
import { useUIStore } from '@/stores/ui'
import { useAuthStore } from '@/stores/auth'
import { useChatStore } from '@/stores/chat'
import type { ChatMessage } from '@/schemas/chat'

beforeEach(() => {
  useUIStore.setState({ namespace: 'default', sidebarCollapsed: false, theme: 'light' })
  useAuthStore.setState({ token: 'test-token' })
  useChatStore.setState({ messages: [], currentSessionId: null, isStreaming: false, provider: '', model: '' })
  Element.prototype.scrollIntoView = vi.fn()
  if (!Element.prototype.hasPointerCapture) Element.prototype.hasPointerCapture = () => false
  if (!Element.prototype.setPointerCapture) Element.prototype.setPointerCapture = () => {}
  if (!Element.prototype.releasePointerCapture) Element.prototype.releasePointerCapture = () => {}
})

describe('ChatPage', () => {
  it('renders "Chat" heading', () => {
    render(<ChatPage />)
    expect(screen.getByText('Chat')).toBeInTheDocument()
  })

  it('renders without crashing', () => {
    const { container } = render(<ChatPage />)
    expect(container).toBeTruthy()
  })

  it('New Chat button appears when messages exist', () => {
    const msgs: ChatMessage[] = [
      { id: 'msg-1', role: 'user', content: 'Hello', timestamp: new Date().toISOString() },
    ]
    useChatStore.setState({ messages: msgs })
    render(<ChatPage />)
    expect(screen.getByText('New Chat')).toBeInTheDocument()
  })

  it('offers the server default plus Provider CRDs and prefills the model on pick', async () => {
    render(<ChatPage />)
    expect(screen.getByRole('combobox', { name: 'Chat provider' })).toHaveTextContent('Server default (anthropic / claude-sonnet-4-20250514)')

    fireEvent.pointerDown(screen.getByRole('combobox', { name: 'Chat provider' }), { button: 0, pointerId: 1, pointerType: 'mouse' })
    fireEvent.click(await screen.findByRole('option', { name: /openai-proxy/ }))

    await waitFor(() => expect(useChatStore.getState().provider).toBe('openai-proxy'))
    expect(useChatStore.getState().model).toBe('gpt-5')
    expect(screen.getByRole('textbox', { name: 'Chat model' })).toHaveValue('gpt-5')
    expect(screen.getByText('gpt-5')).toBeInTheDocument()
  })

  it('model input edits the persisted model override', () => {
    useChatStore.setState({ provider: 'anthropic', model: 'claude-sonnet-4-20250514' })
    render(<ChatPage />)
    fireEvent.change(screen.getByRole('textbox', { name: 'Chat model' }), { target: { value: 'claude-opus-4-1' } })
    expect(useChatStore.getState().model).toBe('claude-opus-4-1')
  })

  it('session ID badge shown when currentSessionId is set', () => {
    useChatStore.setState({ currentSessionId: 'session-abc-123' })
    render(<ChatPage />)
    expect(screen.getByText('session-abc-123')).toBeInTheDocument()
  })
})
