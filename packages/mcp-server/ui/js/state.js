const state = {
  activeToken: localStorage.getItem("sv_session_token") || "",
  stepUpToken: "",
  pendingStepUpResource: "",
  pendingRegenerateClientId: "",
  pendingRegenerateAppName: "",
  pendingRevealSecretName: null,
  pendingRevealClientId: null,
  currentRotateSecretName: null,
  currentRevealedKey: "",
  revealTimerInterval: null,
  currentUser: null,
  currentUserHasPasskey: false,
  currentUserHasTotp: false,
  currentBackupCodesRemaining: 0,
  pendingBackupCodes: [],
  secretsList: [],
  clientAppsList: [],
  activityRows: [],
  activeClientLogs: [],
  activeResetUserId: null,
  allUniqueTags: [],
  resourceStates: {
    secrets: { loading: false, error: null },
    clients: { loading: false, error: null },
    profiles: { loading: false, error: null },
    users: { loading: false, error: null },
    passkeys: { loading: false, error: null },
    logs: { loading: false, error: null },
  },
};

export function getState() {
  return state;
}

export function setState(partial) {
  Object.assign(state, partial);
}

export function setResourceState(resource, partial) {
  const current = state.resourceStates[resource] || {};
  state.resourceStates[resource] = { ...current, ...partial };
}

export function getResourceState(resource) {
  return state.resourceStates[resource] || { loading: false, error: null };
}
