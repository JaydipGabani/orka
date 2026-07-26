import { render, type RenderOptions } from '@testing-library/react'
import {
  QueryClient,
  QueryClientProvider,
  type QueryClientConfig,
} from '@tanstack/react-query'
import type { ReactElement, ReactNode } from 'react'

function createTestQueryClient(options?: QueryClientConfig) {
  return new QueryClient(options ?? {
    defaultOptions: {
      queries: { retry: false, gcTime: 0 },
      mutations: { retry: false },
    },
  })
}

interface TestQueryClientWrapperOptions {
  client?: QueryClient
  clientOptions?: QueryClientConfig
}

function createTestQueryClientWrapper({
  clientOptions,
  client = createTestQueryClient(clientOptions),
}: TestQueryClientWrapperOptions = {}) {
  return function TestQueryClientWrapper({ children }: { children: ReactNode }) {
    return (
      <QueryClientProvider client={client}>{children}</QueryClientProvider>
    )
  }
}

function AllProviders({ children }: { children: ReactNode }) {
  const queryClient = createTestQueryClient()
  return (
    <QueryClientProvider client={queryClient}>
      {children}
    </QueryClientProvider>
  )
}

function customRender(ui: ReactElement, options?: Omit<RenderOptions, 'wrapper'>) {
  return render(ui, { wrapper: AllProviders, ...options })
}

export * from '@testing-library/react'
export {
  customRender as render,
  createTestQueryClient,
  createTestQueryClientWrapper,
}
