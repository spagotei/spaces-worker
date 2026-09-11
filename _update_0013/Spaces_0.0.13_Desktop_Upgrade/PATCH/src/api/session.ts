import type {
  WorkspaceSession,
} from '../types/spaces'

const SESSION_STORAGE_KEY =
  'spaces_standalone_session_v1'

export function saveWorkspaceSession(
  session: WorkspaceSession,
): void {
  try {
    localStorage.setItem(
      SESSION_STORAGE_KEY,
      JSON.stringify(
        session,
      ),
    )
  } catch {
    // Current session can continue even if embedded storage is unavailable.
  }
}

export function loadWorkspaceSession():
  WorkspaceSession |
  null {
  try {
    const raw =
      localStorage.getItem(
        SESSION_STORAGE_KEY,
      )

    if (!raw) {
      return null
    }

    const parsed =
      JSON.parse(
        raw,
      ) as
        Partial<WorkspaceSession>

    if (
      typeof parsed.token !==
        'string' ||
      typeof parsed.expiresAt !==
        'number' ||
      !parsed.profile ||
      parsed.expiresAt <=
        Date.now()
    ) {
      clearWorkspaceSession()
      return null
    }

    return parsed as
      WorkspaceSession
  } catch {
    clearWorkspaceSession()
    return null
  }
}

export function clearWorkspaceSession():
  void {
  try {
    localStorage.removeItem(
      SESSION_STORAGE_KEY,
    )
  } catch {
    // Nothing else to clear.
  }
}
