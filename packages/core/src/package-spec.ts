/** Parse an npm package spec without invoking a package manager. */
export interface ParsedPackageSpec {
  name: string;
  version: string;
}

/**
 * Accept `name`, `name@version`, `@scope/name`, and `@scope/name@version`.
 * This deliberately accepts npm dist-tags/ranges; pacote is the resolver.
 */
export function parsePackageSpec(spec: string): ParsedPackageSpec | null {
  if (typeof spec !== 'string') return null;
  const trimmed = spec.trim();
  if (!trimmed) return null;
  if (trimmed.startsWith('@')) {
    const slash = trimmed.indexOf('/');
    if (slash < 2) return null;
    const rest = trimmed.slice(slash + 1);
    if (!rest) return null;
    const at = rest.indexOf('@');
    if (at === -1) return { name: trimmed, version: 'latest' };
    const localName = rest.slice(0, at);
    if (!localName) return null;
    return { name: `${trimmed.slice(0, slash)}/${localName}`, version: rest.slice(at + 1) || 'latest' };
  }
  const at = trimmed.indexOf('@');
  const name = at === -1 ? trimmed : trimmed.slice(0, at);
  if (!name) return null;
  return { name, version: at === -1 ? 'latest' : (trimmed.slice(at + 1) || 'latest') };
}
