import { shouldRenderAppShell } from './index'

describe('shouldRenderAppShell', () => {
  test('does not render the shell on the login route', () => {
    expect(shouldRenderAppShell('/login', null)).toBe(false)
  })

  test('does not render the shell before a session is available', () => {
    expect(shouldRenderAppShell('/tasks', null)).toBe(false)
  })

  test('renders the shell for authenticated protected routes', () => {
    expect(shouldRenderAppShell('/tasks', 'token')).toBe(true)
  })
})
