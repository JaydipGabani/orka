import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { RouterProvider, createRouter } from '@tanstack/react-router'
import { routeTree } from './routeTree.gen'
import { useAuthStore } from './stores/auth'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30 * 1000,
      retry: 1,
    },
  },
})

// Cached query data belongs to the token that fetched it. On any identity
// change (logout, or signing in as someone else) the cache is cleared so a
// new session can never read the previous token's data — for example Agent
// names surfacing in a selector while the new token's list request 403s.
let lastToken = useAuthStore.getState().token
useAuthStore.subscribe((state) => {
  if (state.token !== lastToken) {
    lastToken = state.token
    queryClient.clear()
  }
})

const router = createRouter({ routeTree })

declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router
  }
}

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  )
}
