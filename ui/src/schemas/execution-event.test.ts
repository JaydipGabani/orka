import { describe, expect, it } from 'vitest'
import {
  executionEventSchema,
  listExecutionEventsResponseSchema,
} from './execution-event'
import {
  executionEventSchema as taskExecutionEventSchema,
  taskEventsResponseSchema,
} from './task'
import type {
  ExecutionEvent as TaskExecutionEvent,
  TaskEventsResponse,
} from './task'

const sessionEvent = {
  id: 'event-1',
  namespace: 'default',
  streamType: 'session',
  streamID: 'session-1',
  seq: 12,
  type: 'ModelRequestCompleted',
  severity: 'info',
  taskName: 'task-1',
  sessionName: 'session-1',
  provider: 'openai',
  model: 'gpt-5',
  stopReason: 'stop',
  inputTokens: 42,
  outputTokens: 9,
  summary: 'completed',
  contentText: 'response',
  truncation: {
    summaryTruncated: true,
    summaryOriginalChars: 100,
    contentTextTruncated: true,
    contentTextOriginalChars: 200,
    contentJsonTruncated: true,
    contentJsonOriginalBytes: 300,
  },
  createdAt: '2026-07-26T00:00:00Z',
  taskSeq: 7,
  taskStreamID: 'task-stream-1',
}

describe('execution event schema compatibility', () => {
  it('re-exports the canonical schemas from the task module', () => {
    expect(taskExecutionEventSchema).toBe(executionEventSchema)
    expect(taskEventsResponseSchema).toBe(listExecutionEventsResponseSchema)
  })

  it('retains truncation and session-only fields through task compatibility exports', () => {
    const response: TaskEventsResponse = {
      namespace: 'default',
      streamType: 'session',
      streamID: 'session-1',
      afterSeq: 0,
      latestSeq: 12,
      events: [sessionEvent satisfies TaskExecutionEvent],
    }

    expect(taskEventsResponseSchema.parse(response)).toEqual(response)
  })
})
