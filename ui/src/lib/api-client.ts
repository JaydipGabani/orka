import { useAuthStore } from '@/stores/auth'
import { API_BASE_URL } from './constants'

type QueryParams = Record<string, string> | URLSearchParams

interface FetchResponseOptions extends RequestInit {
  params?: QueryParams
  // Overrides the stored bearer token. Pass null to intentionally omit auth.
  authToken?: string | null
}

interface RequestOptions extends Omit<FetchResponseOptions, 'headers' | 'authToken'> {
  headers?: Record<string, string>
}

class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message)
    this.name = 'ApiError'
  }
}

function withApiBase(path: string): string {
  if (
    path === API_BASE_URL ||
    path.startsWith(`${API_BASE_URL}/`) ||
    path.startsWith(`${API_BASE_URL}?`)
  ) {
    return path
  }
  return `${API_BASE_URL}${path.startsWith('/') ? path : `/${path}`}`
}

function withQueryParams(path: string, params?: QueryParams): string {
  if (!params) return path

  const searchParams = params instanceof URLSearchParams ? params : new URLSearchParams()
  if (!(params instanceof URLSearchParams)) {
    for (const [key, value] of Object.entries(params)) {
      if (value) searchParams.set(key, value)
    }
  }

  const query = searchParams.toString()
  if (!query) return path
  return `${path}${path.includes('?') ? '&' : '?'}${query}`
}

async function fetchResponse(
  path: string,
  options: FetchResponseOptions = {},
): Promise<Response> {
  const { params, authToken, headers: inputHeaders, ...fetchOptions } = options
  const headers = new Headers(inputHeaders)
  const storedToken = useAuthStore.getState().token
  const usesStoredToken = authToken === undefined
  const token = usesStoredToken ? storedToken : authToken

  if (token) {
    headers.set('Authorization', `Bearer ${token}`)
  } else if (authToken === null) {
    headers.delete('Authorization')
  }

  const response = await fetch(withQueryParams(withApiBase(path), params), {
    ...fetchOptions,
    headers,
  })

  if (response.status === 401 && usesStoredToken) {
    const auth = useAuthStore.getState()
    if (auth.token === storedToken) auth.clearToken()
  }

  return response
}

async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const response = await fetchResponse(path, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
  })

  if (!response.ok) {
    const text = await response.text().catch(() => 'Unknown error')
    throw new ApiError(response.status, text)
  }

  if (response.status === 204) {
    return undefined as T
  }

  return response.json()
}

export const api = {
  fetchResponse,

  get: <T>(path: string, params?: Record<string, string>) =>
    request<T>(path, { method: 'GET', params }),

  post: <T>(path: string, body?: unknown, params?: Record<string, string>, headers?: Record<string, string>) =>
    request<T>(path, { method: 'POST', body: body ? JSON.stringify(body) : undefined, params, headers }),

  put: <T>(path: string, body?: unknown, params?: Record<string, string>) =>
    request<T>(path, { method: 'PUT', body: body ? JSON.stringify(body) : undefined, params }),

  delete: <T>(path: string, params?: Record<string, string>) =>
    request<T>(path, { method: 'DELETE', params }),
}

export { ApiError }
export type { FetchResponseOptions }
