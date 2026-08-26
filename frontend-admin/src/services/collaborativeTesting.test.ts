import { validateCollaborativeTarget } from './collaborativeTesting';

describe('collaborative testing session', () => {
  it('accepts only http targets', () => {
    expect(validateCollaborativeTarget('https://example.test')).toBe(true);
    expect(validateCollaborativeTarget('file:///tmp/a.js')).toBe(false);
    expect(validateCollaborativeTarget('not a url')).toBe(false);
  });
});
