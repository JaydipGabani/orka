import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { ApiError, api, isForbiddenError } from '@/lib/api-client'

// Client errors (403/404/400) do not clear on retry; only transient failures
// do. 408 (request timeout) and 429 (throttled) are client statuses that an
// ingress or API throttle returns transiently, so they keep retrying.
const transientClientStatuses = new Set([408, 429])
export const retryUnlessClientError = (failureCount: number, error: unknown) =>
  failureCount < 3 &&
  !(error instanceof ApiError && error.status >= 400 && error.status < 500 && !transientClientStatuses.has(error.status))
import { useUIStore } from '@/stores/ui'
import type { Session, SessionListItem } from '@/schemas/session'

interface ListResponse<T> {
  items: T[]
  metadata: { continue?: string; remainingItemCount?: number }
}

export function useSessionList(limit = '25') {
  const namespace = useUIStore((s) => s.namespace)
  return useQuery({
    queryKey: ['sessions', namespace, limit],
    queryFn: () => api.get<ListResponse<SessionListItem>>('/sessions', { namespace, limit }),
    retry: retryUnlessClientError,
    // A 403 will not clear on its own; polling it just spams the audit log.
    refetchInterval: (query) => (isForbiddenError(query.state.error) ? false : 15000),
  })
}

export function useSession(id: string) {
  const namespace = useUIStore((s) => s.namespace)
  return useQuery({
    queryKey: ['session', id, namespace],
    queryFn: () => api.get<Session>(`/sessions/${id}`, { namespace }),
    retry: retryUnlessClientError,
  })
}

export function useDeleteSession() {
  const queryClient = useQueryClient()
  const namespace = useUIStore((s) => s.namespace)
  return useMutation({
    mutationFn: (id: string) => api.delete<void>(`/sessions/${id}`, { namespace }),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['sessions'] }) },
  })
}
