import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api-client'
import { useUIStore } from '@/stores/ui'
import type { MonitorAction, MonitorCommand, MonitorImplementationJob, MonitorItem, MonitorMutation, MonitorRun, MonitorWorkAction, RepositoryMonitor } from '@/schemas/monitor'

interface ListResponse<T> {
  items: T[]
  metadata?: { continue?: string }
}

const MONITOR_REFETCH_INTERVAL = 10000

const monitorKeys = {
  repositoryLists: ['monitors', 'repositories'] as const,
  repositories: (namespace: string) => ['monitors', 'repositories', namespace] as const,
  repository: (namespace: string, name: string) => ['monitors', 'repository', namespace, name] as const,
  runs: (namespace: string, name: string) => ['monitors', 'runs', namespace, name] as const,
  items: (namespace: string, name: string) => ['monitors', 'items', namespace, name] as const,
  itemsByKind: (namespace: string, name: string, kind: string) => ['monitors', 'items', namespace, name, kind] as const,
  actions: (namespace: string, name: string) => ['monitors', 'actions', namespace, name] as const,
  commands: (namespace: string, name: string) => ['monitors', 'commands', namespace, name] as const,
  workActions: (namespace: string, name: string) => ['monitors', 'work-actions', namespace, name] as const,
  implementationJobs: (namespace: string, name: string) => ['monitors', 'implementation-jobs', namespace, name] as const,
  mutations: (namespace: string, name: string) => ['monitors', 'mutations', namespace, name] as const,
}

interface RepositoryMonitorCollectionOptions<T> {
  name: string
  queryKey: (namespace: string) => readonly unknown[]
  queryFn: (namespace: string) => Promise<ListResponse<T>>
}

function useRepositoryMonitorCollection<T>({ name, queryKey, queryFn }: RepositoryMonitorCollectionOptions<T>) {
  const namespace = useUIStore((s) => s.namespace)
  return useQuery({
    queryKey: queryKey(namespace),
    queryFn: () => queryFn(namespace),
    enabled: !!name,
    refetchInterval: MONITOR_REFETCH_INTERVAL,
  })
}

export interface CreateRepositoryMonitorBody {
  name: string
  namespace?: string
  metadata?: { name?: string; namespace?: string }
  spec: RepositoryMonitor['spec']
}

export function useRepositoryMonitors() {
  const namespace = useUIStore((s) => s.namespace)
  return useQuery({
    queryKey: monitorKeys.repositories(namespace),
    queryFn: () => api.get<ListResponse<RepositoryMonitor>>('/monitors/repositories', { namespace }),
    refetchInterval: MONITOR_REFETCH_INTERVAL,
  })
}

export function useRepositoryMonitor(name: string) {
  const namespace = useUIStore((s) => s.namespace)
  return useQuery({
    queryKey: monitorKeys.repository(namespace, name),
    queryFn: () => api.get<RepositoryMonitor>(`/monitors/repositories/${name}`, { namespace }),
    enabled: !!name,
    refetchInterval: MONITOR_REFETCH_INTERVAL,
  })
}

export function useRepositoryMonitorRuns(name: string) {
  return useRepositoryMonitorCollection<MonitorRun>({
    name,
    queryKey: (namespace) => monitorKeys.runs(namespace, name),
    queryFn: (namespace) => api.get<ListResponse<MonitorRun>>(`/monitors/repositories/${name}/runs`, { namespace }),
  })
}

export function useRepositoryMonitorItems(name: string, kind = 'pull_request') {
  return useRepositoryMonitorCollection<MonitorItem>({
    name,
    queryKey: (namespace) => monitorKeys.itemsByKind(namespace, name, kind),
    queryFn: (namespace) => api.get<ListResponse<MonitorItem>>(`/monitors/repositories/${name}/items`, { namespace, kind }),
  })
}

export function useRepositoryMonitorActions(name: string) {
  return useRepositoryMonitorCollection<MonitorAction>({
    name,
    queryKey: (namespace) => monitorKeys.actions(namespace, name),
    queryFn: (namespace) => api.get<ListResponse<MonitorAction>>('/monitors/actions', { namespace, name }),
  })
}

export function useRepositoryMonitorCommands(name: string) {
  return useRepositoryMonitorCollection<MonitorCommand>({
    name,
    queryKey: (namespace) => monitorKeys.commands(namespace, name),
    queryFn: (namespace) => api.get<ListResponse<MonitorCommand>>('/monitors/commands', { namespace, name }),
  })
}

export function useRepositoryMonitorWorkActions(name: string) {
  return useRepositoryMonitorCollection<MonitorWorkAction>({
    name,
    queryKey: (namespace) => monitorKeys.workActions(namespace, name),
    queryFn: (namespace) => api.get<ListResponse<MonitorWorkAction>>('/monitors/work-actions', { namespace, name }),
  })
}

export function useRepositoryMonitorImplementationJobs(name: string) {
  return useRepositoryMonitorCollection<MonitorImplementationJob>({
    name,
    queryKey: (namespace) => monitorKeys.implementationJobs(namespace, name),
    queryFn: (namespace) => api.get<ListResponse<MonitorImplementationJob>>('/monitors/implementation-jobs', { namespace, name }),
  })
}

export function useRepositoryMonitorMutations(name: string) {
  return useRepositoryMonitorCollection<MonitorMutation>({
    name,
    queryKey: (namespace) => monitorKeys.mutations(namespace, name),
    queryFn: (namespace) => api.get<ListResponse<MonitorMutation>>('/monitors/mutations', { namespace, name }),
  })
}

export interface CreateRepositoryMonitorCommandBody {
  kind: string
  number: number
  intent: string
  targetSHA?: string
}

export function useCreateRepositoryMonitorCommand(name: string) {
  const queryClient = useQueryClient()
  const namespace = useUIStore((s) => s.namespace)
  return useMutation({
    mutationFn: (body: CreateRepositoryMonitorCommandBody) => api.post<MonitorCommand>(`/monitors/repositories/${name}/commands`, body, { namespace }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: monitorKeys.commands(namespace, name) })
      queryClient.invalidateQueries({ queryKey: monitorKeys.runs(namespace, name) })
      queryClient.invalidateQueries({ queryKey: monitorKeys.workActions(namespace, name) })
      queryClient.invalidateQueries({ queryKey: monitorKeys.implementationJobs(namespace, name) })
      queryClient.invalidateQueries({ queryKey: monitorKeys.mutations(namespace, name) })
      queryClient.invalidateQueries({ queryKey: monitorKeys.items(namespace, name) })
      queryClient.invalidateQueries({ queryKey: monitorKeys.repository(namespace, name) })
    },
  })
}

export function useCreateRepositoryMonitor() {
  const queryClient = useQueryClient()
  const namespace = useUIStore((s) => s.namespace)
  return useMutation({
    mutationFn: (body: CreateRepositoryMonitorBody) => api.post<RepositoryMonitor>('/monitors/repositories', body),
    onSuccess: (monitor, variables) => {
      const createdNamespace = monitor.metadata.namespace ?? variables.namespace ?? variables.metadata?.namespace ?? namespace
      const createdName = monitor.metadata.name ?? variables.name ?? variables.metadata?.name

      queryClient.invalidateQueries({ queryKey: monitorKeys.repositoryLists })
      queryClient.invalidateQueries({ queryKey: monitorKeys.repositories(createdNamespace) })
      if (createdName) {
        queryClient.invalidateQueries({ queryKey: monitorKeys.repository(createdNamespace, createdName) })
      }
    },
  })
}

export function useRunRepositoryMonitor(name: string) {
  const queryClient = useQueryClient()
  const namespace = useUIStore((s) => s.namespace)
  return useMutation({
    mutationFn: () => api.post<MonitorRun>(`/monitors/repositories/${name}/runs`, {}, { namespace }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: monitorKeys.runs(namespace, name) })
      queryClient.invalidateQueries({ queryKey: monitorKeys.repository(namespace, name) })
      queryClient.invalidateQueries({ queryKey: monitorKeys.repositories(namespace) })
    },
  })
}
