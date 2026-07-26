import { act, renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { http, HttpResponse } from 'msw'
import type { ReactNode } from 'react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { server } from '@/test/mocks/server'

vi.mock('zustand/middleware', () => ({
  persist: (fn: unknown) => fn,
}))

import { useUIStore } from '@/stores/ui'
import {
  useCreateRepositoryMonitor,
  useCreateRepositoryMonitorCommand,
  useRepositoryMonitorActions,
  useRepositoryMonitorCommands,
  useRepositoryMonitorImplementationJobs,
  useRepositoryMonitorItems,
  useRepositoryMonitorMutations,
  useRepositoryMonitorRuns,
  useRepositoryMonitorWorkActions,
  useRunRepositoryMonitor,
} from './use-monitors'

function createTestQueryClient() {
  return new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0 }, mutations: { retry: false } },
  })
}

function createWrapper(queryClient: QueryClient) {
  return ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  )
}

function useRepositoryMonitorCollections(name: string) {
  return {
    runs: useRepositoryMonitorRuns(name),
    items: useRepositoryMonitorItems(name),
    issueItems: useRepositoryMonitorItems(name, 'issue'),
    actions: useRepositoryMonitorActions(name),
    commands: useRepositoryMonitorCommands(name),
    workActions: useRepositoryMonitorWorkActions(name),
    implementationJobs: useRepositoryMonitorImplementationJobs(name),
    mutations: useRepositoryMonitorMutations(name),
  }
}

beforeEach(() => {
  useUIStore.setState({ namespace: 'default', sidebarCollapsed: false, theme: 'light' })
})

describe('repository monitor collection hooks', () => {
  it('preserves collection URLs, parameters, keys, and polling intervals', async () => {
    useUIStore.setState({ namespace: 'team-a' })
    const queryClient = createTestQueryClient()
    const requests: URL[] = []
    const respond = ({ request }: { request: Request }) => {
      requests.push(new URL(request.url))
      return HttpResponse.json({ items: [], metadata: {} })
    }

    server.use(
      http.get('/api/v1/monitors/repositories/:name/runs', respond),
      http.get('/api/v1/monitors/repositories/:name/items', respond),
      http.get('/api/v1/monitors/actions', respond),
      http.get('/api/v1/monitors/commands', respond),
      http.get('/api/v1/monitors/work-actions', respond),
      http.get('/api/v1/monitors/implementation-jobs', respond),
      http.get('/api/v1/monitors/mutations', respond),
    )

    const { result } = renderHook(() => useRepositoryMonitorCollections('example-app'), {
      wrapper: createWrapper(queryClient),
    })

    await waitFor(() => {
      expect(Object.values(result.current).every((query) => query.isSuccess)).toBe(true)
    })

    const expectedQueries = [
      {
        key: ['monitors', 'runs', 'team-a', 'example-app'],
        path: '/api/v1/monitors/repositories/example-app/runs',
        params: { namespace: 'team-a' },
      },
      {
        key: ['monitors', 'items', 'team-a', 'example-app', 'pull_request'],
        path: '/api/v1/monitors/repositories/example-app/items',
        params: { namespace: 'team-a', kind: 'pull_request' },
      },
      {
        key: ['monitors', 'items', 'team-a', 'example-app', 'issue'],
        path: '/api/v1/monitors/repositories/example-app/items',
        params: { namespace: 'team-a', kind: 'issue' },
      },
      {
        key: ['monitors', 'actions', 'team-a', 'example-app'],
        path: '/api/v1/monitors/actions',
        params: { namespace: 'team-a', name: 'example-app' },
      },
      {
        key: ['monitors', 'commands', 'team-a', 'example-app'],
        path: '/api/v1/monitors/commands',
        params: { namespace: 'team-a', name: 'example-app' },
      },
      {
        key: ['monitors', 'work-actions', 'team-a', 'example-app'],
        path: '/api/v1/monitors/work-actions',
        params: { namespace: 'team-a', name: 'example-app' },
      },
      {
        key: ['monitors', 'implementation-jobs', 'team-a', 'example-app'],
        path: '/api/v1/monitors/implementation-jobs',
        params: { namespace: 'team-a', name: 'example-app' },
      },
      {
        key: ['monitors', 'mutations', 'team-a', 'example-app'],
        path: '/api/v1/monitors/mutations',
        params: { namespace: 'team-a', name: 'example-app' },
      },
    ]

    expect(requests).toHaveLength(expectedQueries.length)
    for (const expected of expectedQueries) {
      const request = requests.find((candidate) =>
        candidate.pathname === expected.path
        && Object.entries(expected.params).every(([key, value]) => candidate.searchParams.get(key) === value),
      )
      expect(request, `${expected.path} ${JSON.stringify(expected.params)}`).toBeDefined()
      expect(Object.fromEntries(request?.searchParams ?? [])).toEqual(expected.params)

      const query = queryClient.getQueryCache().find({ queryKey: expected.key, exact: true })
      expect(query).toBeDefined()
      expect(query?.options.refetchInterval).toBe(10000)
    }
  })

  it('does not fetch collections until a monitor name is available', () => {
    const queryClient = createTestQueryClient()
    const { result } = renderHook(() => useRepositoryMonitorCollections(''), {
      wrapper: createWrapper(queryClient),
    })

    expect(Object.values(result.current).every((query) => query.fetchStatus === 'idle')).toBe(true)

    const expectedKeys = [
      ['monitors', 'runs', 'default', ''],
      ['monitors', 'items', 'default', '', 'pull_request'],
      ['monitors', 'items', 'default', '', 'issue'],
      ['monitors', 'actions', 'default', ''],
      ['monitors', 'commands', 'default', ''],
      ['monitors', 'work-actions', 'default', ''],
      ['monitors', 'implementation-jobs', 'default', ''],
      ['monitors', 'mutations', 'default', ''],
    ]

    for (const key of expectedKeys) {
      const query = queryClient.getQueryCache().find({ queryKey: key, exact: true })
      expect(query).toBeDefined()
      expect(query?.options.enabled).toBe(false)
      expect(query?.options.refetchInterval).toBe(10000)
    }
  })
})

describe('useCreateRepositoryMonitorCommand', () => {
  it('posts the command and invalidates every affected monitor query', async () => {
    const queryClient = createTestQueryClient()
    const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries')
    let receivedBody: unknown

    server.use(
      http.post('/api/v1/monitors/repositories/:name/commands', async ({ request }) => {
        receivedBody = await request.json()
        return HttpResponse.json({ id: 'command-1' }, { status: 201 })
      }),
    )

    const body = { kind: 'pull_request', number: 42, intent: 'review', targetSHA: 'abc123' }
    const { result } = renderHook(() => useCreateRepositoryMonitorCommand('example-app'), {
      wrapper: createWrapper(queryClient),
    })

    await act(async () => {
      await result.current.mutateAsync(body)
    })

    expect(receivedBody).toEqual(body)
    expect(invalidateSpy.mock.calls.map(([filters]) => filters.queryKey)).toEqual([
      ['monitors', 'commands', 'default', 'example-app'],
      ['monitors', 'runs', 'default', 'example-app'],
      ['monitors', 'work-actions', 'default', 'example-app'],
      ['monitors', 'implementation-jobs', 'default', 'example-app'],
      ['monitors', 'mutations', 'default', 'example-app'],
      ['monitors', 'items', 'default', 'example-app'],
      ['monitors', 'repository', 'default', 'example-app'],
    ])
  })
})

describe('useCreateRepositoryMonitor', () => {
  it('posts the create request and invalidates monitor list/detail queries', async () => {
    const queryClient = createTestQueryClient()
    const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries')
    let receivedBody: unknown

    server.use(
      http.post('/api/v1/monitors/repositories', async ({ request }) => {
        receivedBody = await request.json()
        return HttpResponse.json({
          metadata: { name: 'example-app', namespace: 'default' },
          spec: { repoURL: 'https://github.com/example/app' },
        }, { status: 201 })
      }),
    )

    const body = {
      name: 'example-app',
      namespace: 'default',
      spec: {
        repoURL: 'https://github.com/example/app',
        agents: { reviewer: { name: 'repo-reviewer' } },
      },
    }

    const { result } = renderHook(() => useCreateRepositoryMonitor(), { wrapper: createWrapper(queryClient) })

    await act(async () => {
      await result.current.mutateAsync(body)
    })

    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(receivedBody).toEqual(body)
    expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['monitors', 'repositories'] })
    expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['monitors', 'repositories', 'default'] })
    expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['monitors', 'repository', 'default', 'example-app'] })
  })
})

describe('useRunRepositoryMonitor', () => {
  it('starts a run and invalidates run, detail, and list queries', async () => {
    const queryClient = createTestQueryClient()
    const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries')

    server.use(
      http.post('/api/v1/monitors/repositories/:name/runs', () => (
        HttpResponse.json({ id: 'run-1' }, { status: 201 })
      )),
    )

    const { result } = renderHook(() => useRunRepositoryMonitor('example-app'), {
      wrapper: createWrapper(queryClient),
    })

    await act(async () => {
      await result.current.mutateAsync()
    })

    expect(invalidateSpy.mock.calls.map(([filters]) => filters.queryKey)).toEqual([
      ['monitors', 'runs', 'default', 'example-app'],
      ['monitors', 'repository', 'default', 'example-app'],
      ['monitors', 'repositories', 'default'],
    ])
  })
})
