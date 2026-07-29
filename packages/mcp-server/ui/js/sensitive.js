import { getState, setState } from "./state.js";

export function clearSensitiveState() {
  const s = getState();
  if (s.revealTimerInterval) {
    clearInterval(s.revealTimerInterval);
  }
  setState({
    currentRevealedKey: "",
    revealTimerInterval: null,
    stepUpToken: "",
    pendingStepUpResource: "",
    pendingRevealSecretName: null,
    pendingRevealClientId: null,
    pendingRegenerateClientId: "",
    pendingRegenerateAppName: "",
    currentRotateSecretName: null,
    pendingBackupCodes: [],
  });
  clearSensitiveDomElements();
}

export function clearSensitiveDomElements() {
  const ids = [
    "reveal-modal-input",
    "created-client-key",
    "rotate-secret-value",
    "new-secret-value",
    "new-secret-name",
  ];
  for (const id of ids) {
    const el = document.getElementById(id);
    if (el) el.value = "";
  }
  const backupList = document.getElementById("backup-codes-list");
  if (backupList) backupList.textContent = "";
  document.querySelectorAll(".totp-pin-box").forEach((el) => { el.value = ""; });
}

export function clearSensitiveDom() {
  clearSensitiveDomElements();
  clearSensitiveState();
}

export function setupSensitiveCleanup() {
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) clearSensitiveDom();
  });
  window.addEventListener("beforeunload", () => clearSensitiveState());
  window.addEventListener("pagehide", () => clearSensitiveDom());
  window.addEventListener("popstate", () => clearSensitiveDom());
}
