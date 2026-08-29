import { useQuery } from '@tanstack/react-query'
import { api } from '@/lib/api-client'
import { providerListResponseSchema } from '@/schemas/provider'
import { useUIStore } from '@/stores/ui'

export function useProviderList() {
  const namespace = useUIStore((s) => s.namespace)
  return useQuery({
    queryKey: ['providers', namespace],
    queryFn: async () =>
      providerListResponseSchema.parse(await api.get<unknown>('/providers', { namespace, limit: '100' })),
    staleTime: 60 * 1000,
  })
}
