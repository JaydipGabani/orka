/**
 * Split a command line into words the way a POSIX shell would, without
 * expansions: whitespace separates words, single quotes preserve everything
 * literally, double quotes preserve everything except backslash escapes of
 * `"` `\` and `$`, and an unquoted backslash escapes the next character.
 *
 * Returns `{ words }` on success or `{ error }` when a quote is left open, so
 * `sh -c "echo hi"` becomes `["sh", "-c", "echo hi"]` instead of the naive
 * whitespace split that leaves the quote characters inside the words.
 */
export function splitShellWords(input: string): { words: string[] } | { error: string } {
  const words: string[] = []
  let current = ''
  let inWord = false
  let quote: '"' | "'" | null = null

  for (let i = 0; i < input.length; i++) {
    const ch = input[i]

    if (quote === "'") {
      if (ch === "'") {
        quote = null
      } else {
        current += ch
      }
      continue
    }

    if (quote === '"') {
      if (ch === '"') {
        quote = null
      } else if (ch === '\\' && i + 1 < input.length && '"\\$`'.includes(input[i + 1])) {
        current += input[++i]
      } else {
        current += ch
      }
      continue
    }

    if (ch === '"' || ch === "'") {
      quote = ch
      inWord = true
      continue
    }
    if (ch === '\\') {
      if (i + 1 < input.length) {
        current += input[++i]
        inWord = true
      }
      continue
    }
    if (/\s/.test(ch)) {
      if (inWord) {
        words.push(current)
        current = ''
        inWord = false
      }
      continue
    }
    current += ch
    inWord = true
  }

  if (quote) {
    return { error: `Unterminated ${quote === '"' ? 'double' : 'single'} quote in command` }
  }
  if (inWord) words.push(current)
  return { words }
}
