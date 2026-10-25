export interface AccountCredentialUpdate {
  id: string
  accessToken?: string
  refreshToken?: string
  expiresAt?: number
  profileArn?: string
}

interface CredentialAccount {
  credentials?: {
    accessToken?: string
    refreshToken?: string
    expiresAt?: number
    profileArn?: string
  }
  profileArn?: string
  status?: string
  lastError?: string
}

export interface AccountDataSnapshot {
  accounts?: Record<string, CredentialAccount>
}

function isExpiredCredentialError(error?: string): boolean {
  if (!error) return false
  // A refresh fixes stale authentication, not suspension, quota or network errors.
  if (/suspend|封禁|\b423\b/i.test(error)) return false
  return /token expired|token.*已过期|bearer token.*invalid|invalid token/i.test(error)
}

/** Apply token-only and profile-only events without discarding unrelated credentials. */
export function applyAccountCredentialUpdate<T extends CredentialAccount>(
  account: T,
  update: AccountCredentialUpdate
): T {
  if (update.expiresAt !== undefined && update.expiresAt < (account.credentials?.expiresAt || 0))
    return account

  const credentials = { ...account.credentials }
  if (update.accessToken) credentials.accessToken = update.accessToken
  if (update.refreshToken) credentials.refreshToken = update.refreshToken
  if (update.expiresAt !== undefined) credentials.expiresAt = update.expiresAt
  if (update.profileArn) credentials.profileArn = update.profileArn

  const next = { ...account, credentials }
  if (update.profileArn) next.profileArn = update.profileArn
  if (update.accessToken && isExpiredCredentialError(account.lastError)) {
    next.status = 'active'
    next.lastError = undefined
  }
  return next
}

/** Keep account edits/deletions, but don't let an old renderer save roll back a refresh. */
export function preserveNewerAccountCredentials<T extends AccountDataSnapshot>(
  incoming: T,
  persisted?: AccountDataSnapshot | null
): T {
  if (!incoming?.accounts || !persisted?.accounts) return incoming
  const accounts = { ...incoming.accounts }
  for (const [id, account] of Object.entries(accounts)) {
    const saved = persisted.accounts[id]
    if (
      !saved ||
      !saved.credentials?.accessToken ||
      (saved.credentials.expiresAt || 0) <= (account.credentials?.expiresAt || 0)
    )
      continue
    accounts[id] = applyAccountCredentialUpdate(account, {
      id,
      ...saved.credentials,
      profileArn: saved.profileArn || saved.credentials.profileArn
    })
  }
  return { ...incoming, accounts }
}
