/**
 * Central FS hot-path pattern list — used by both fs.new-hotpath-write and
 * fs.new-hotpath-read detectors. Adding a pattern here strengthens BOTH.
 */

export const HOT_PATH_PATTERNS: RegExp[] = [
  // Credentials / auth
  /\.ssh(\/|$)/i,
  /(^|\/)\.npmrc$/i,
  /(^|\/)\.git\/config$/i,
  /(^|\/)\.git-credentials$/i,
  /(^|\/)id_rsa/i,
  /(^|\/)id_ed25519/i,
  /\.aws\/credentials/i,
  /\.docker\/config\.json/i,
  /(^|\/)netrc$/i,
  /(^|\/)\.netrc$/i,
  // Crypto wallets
  /wallet\.dat/i,
  /keystore/i,
  /(^|\/)keychain/i,
  /Ethereum\/keystore/i,
  /(^|\/)\.electrum/i,
  /Solana\/id\.json/i,
  // Shell histories
  /\.bash_history/i,
  /\.zsh_history/i,
  // Browser profile paths (extension-based wallet drainer target)
  /(^|\/)Local Storage(\/|$)/i,
  /(^|\/)IndexedDB(\/|$)/i,
  /BrowserData/i,
  // User desktop / documents — hot for protestware
  /(^|\/)Desktop(\/|$)/,
  /(^|\/)Documents(\/|$)/,
  // Home-relative paths
  /^~/,
  // Absolute system paths
  /^\/etc\//,
  /^\/root\//,
  /^\/var\/log\//,
  /^C:\\Windows/i,
];
