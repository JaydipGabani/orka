import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { http, HttpResponse } from 'msw'
import { server } from '@/test/mocks/server'

import { createTestQueryClientWrapper as createWrapper } from '@/test/test-utils'

vi.mock('zustand/middleware', () => ({ persist: (fn: unknown) => fn }))

import { useUIStore } from '@/stores/ui'
import { useAuthStore } from '@/stores/auth'
import {
  downloadTaskArtifact,
  useTaskArtifacts,
  taskArtifactDownloadUrl,
} from './use-task-artifacts'

beforeEach(() => {
  useUIStore.setState({ namespace: 'default', sidebarCollapsed: false, theme: 'light' })
  useAuthStore.setState({ token: 'test-auth-token' })
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('useTaskArtifacts', () => {
  it('lists artifacts', async () => {
    server.use(http.get('/api/v1/tasks/t1/artifacts', () => HttpResponse.json({
      artifacts: [{ filename: 'a.txt', contentType: 'text/plain', size: 10, createdAt: '2026-06-28T00:00:00Z' }],
    })))
    const { result } = renderHook(() => useTaskArtifacts('t1'), { wrapper: createWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data?.artifacts).toHaveLength(1)
  })

  it('polls when a refetch interval is provided', async () => {
    let calls = 0
    server.use(http.get('/api/v1/tasks/t-live/artifacts', () => {
      calls += 1
      return HttpResponse.json({
        artifacts: calls === 1
          ? []
          : [{ filename: 'later.txt', contentType: 'text/plain', size: 1 }],
      })
    }))

    const { result } = renderHook(() => useTaskArtifacts('t-live', true, undefined, 20), { wrapper: createWrapper() })

    await waitFor(() => expect(calls).toBeGreaterThan(1))
    await waitFor(() => expect(result.current.data?.artifacts[0]?.filename).toBe('later.txt'))
  })

  it('handles empty artifact response', async () => {
    server.use(http.get('/api/v1/tasks/t2/artifacts', () => HttpResponse.json({ artifacts: [] })))
    const { result } = renderHook(() => useTaskArtifacts('t2'), { wrapper: createWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data?.artifacts).toEqual([])
  })
})

describe('taskArtifactDownloadUrl', () => {
  it('encodes filename and namespace', () => {
    expect(taskArtifactDownloadUrl('t1', 'a b.txt', 'ns')).toBe('/api/v1/tasks/t1/artifacts/a%20b.txt?namespace=ns')
  })
})

describe('downloadTaskArtifact', () => {
  it('downloads the authenticated blob through a temporary object URL', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(new Blob(['artifact body'], { type: 'text/plain' }), { status: 200 }),
    )
    const createObjectURL = vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:artifact')
    const revokeObjectURL = vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {})
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})

    await downloadTaskArtifact('t1', 'report a.txt', 'team-a')

    expect(fetchSpy.mock.calls[0][0]).toBe(
      '/api/v1/tasks/t1/artifacts/report%20a.txt?namespace=team-a',
    )
    expect(new Headers(fetchSpy.mock.calls[0][1]?.headers).get('Authorization')).toBe(
      'Bearer test-auth-token',
    )
    expect(createObjectURL).toHaveBeenCalledWith(expect.any(Blob))
    const clickedAnchor = click.mock.instances[0]
    expect(clickedAnchor.download).toBe('report a.txt')
    expect(clickedAnchor.href).toBe('blob:artifact')
    expect(revokeObjectURL).toHaveBeenCalledWith('blob:artifact')
  })

  it('preserves the download error and clears auth on 401', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response('Unauthorized', { status: 401 }),
    )

    await expect(downloadTaskArtifact('t1', 'report.txt', 'default')).rejects.toMatchObject({
      status: 401,
      message: 'failed to download report.txt',
    })
    expect(useAuthStore.getState().token).toBeNull()
  })
})
