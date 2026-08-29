import { describe, it, expect } from 'vitest'
import { splitShellWords } from './shell-words'

describe('splitShellWords', () => {
  it('splits on whitespace', () => {
    expect(splitShellWords('ls -la  /tmp')).toEqual({ words: ['ls', '-la', '/tmp'] })
  })

  it('returns no words for an empty or blank string', () => {
    expect(splitShellWords('')).toEqual({ words: [] })
    expect(splitShellWords('   ')).toEqual({ words: [] })
  })

  it('keeps double-quoted text as one word without the quotes', () => {
    expect(splitShellWords('sh -c "echo UI_TASK_OK"')).toEqual({ words: ['sh', '-c', 'echo UI_TASK_OK'] })
  })

  it('keeps single-quoted text literally', () => {
    expect(splitShellWords(`sh -c 'echo "$HOME" \\n'`)).toEqual({ words: ['sh', '-c', 'echo "$HOME" \\n'] })
  })

  it('preserves empty quoted words and joins adjacent quoted segments', () => {
    expect(splitShellWords(`printf "" ''`)).toEqual({ words: ['printf', '', ''] })
    expect(splitShellWords(`echo foo"bar baz"'qux'`)).toEqual({ words: ['echo', 'foobar bazqux'] })
  })

  it('honors backslash escapes outside quotes', () => {
    expect(splitShellWords('echo hello\\ world \\"quoted\\"')).toEqual({ words: ['echo', 'hello world', '"quoted"'] })
  })

  it('honors backslash escapes of " \\ $ inside double quotes only', () => {
    expect(splitShellWords('echo "a \\"b\\" \\$c \\\\ \\n"')).toEqual({ words: ['echo', 'a "b" $c \\ \\n'] })
  })

  it('rejects unterminated double and single quotes', () => {
    expect(splitShellWords('sh -c "echo hi')).toEqual({ error: 'Unterminated double quote in command' })
    expect(splitShellWords("sh -c 'echo hi")).toEqual({ error: 'Unterminated single quote in command' })
  })
})
