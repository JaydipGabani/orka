import { ChatMessageList } from './chat-message-list'
import { ChatInput } from './chat-input'
import { useSendMessage, useChatConfig } from '@/hooks/use-chat'
import { useProviderList } from '@/hooks/use-providers'
import { useChatStore } from '@/stores/chat'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Plus } from 'lucide-react'

const SERVER_DEFAULT = '__default__'

export function ChatPage() {
  const sendMessage = useSendMessage()
  const { data: config } = useChatConfig()
  const { data: providersData } = useProviderList()
  const { currentSessionId, newSession, messages, provider, model, setProvider, setModel, isStreaming } = useChatStore()
  const providers = providersData?.items ?? []
  const serverDefaultLabel = config?.provider
    ? `Server default (${config.provider}${config.model ? ` / ${config.model}` : ''})`
    : 'Server default'
  const effectiveModel = model || (provider ? providers.find((p) => p.name === provider)?.defaultModel : config?.model)

  const handleProviderChange = (value: string) => {
    const next = value === SERVER_DEFAULT ? '' : value
    setProvider(next)
    // Prefill the model with the provider's default so a plain pick just works;
    // the user can still overwrite it.
    setModel(next ? providers.find((p) => p.name === next)?.defaultModel ?? '' : '')
  }

  return (
    <div className="flex h-full flex-col -m-6">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-border bg-card px-4 py-2">
        <div className="flex items-center gap-3">
          <h1 className="text-sm font-semibold">Chat</h1>
          {currentSessionId && (
            <Badge variant="secondary" className="font-mono text-[10px]">
              {currentSessionId}
            </Badge>
          )}
          {effectiveModel && (
            <Badge variant="outline" className="text-[10px]">
              {effectiveModel}
            </Badge>
          )}
        </div>
        <div className="flex flex-wrap items-center justify-end gap-2">
          <Select value={provider || SERVER_DEFAULT} onValueChange={handleProviderChange} disabled={isStreaming}>
            <SelectTrigger className="h-7 w-auto min-w-40 text-xs" aria-label="Chat provider">
              <SelectValue placeholder="Provider" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={SERVER_DEFAULT}>{serverDefaultLabel}</SelectItem>
              {providers.map((p) => (
                <SelectItem key={p.name} value={p.name}>
                  {p.name}
                  {p.type && ` (${p.type})`}
                  {p.ready === false && ' — not ready'}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Input
            aria-label="Chat model"
            value={model}
            onChange={(e) => setModel(e.target.value)}
            placeholder={provider ? providers.find((p) => p.name === provider)?.defaultModel || 'model' : config?.model || 'model (server default)'}
            disabled={isStreaming}
            className="h-7 w-48 text-xs"
          />
          {messages.length > 0 && (
            <Button variant="ghost" size="sm" onClick={newSession} className="h-7 text-xs">
              <Plus className="mr-1 h-3 w-3" /> New Chat
            </Button>
          )}
        </div>
      </div>

      {/* Messages */}
      <ChatMessageList />

      {/* Input */}
      <ChatInput onSend={sendMessage} />
    </div>
  )
}
