import { showToast } from "./notifications.js";

export function checkPublicSettings() {
  fetch("/v1/settings/public")
    .then((r) => r.json())
    .then((data) => {
      if (data.open_registration_enabled) {
        const link = document.getElementById("link-show-register");
        if (link) link.style.display = "inline";
      }
    })
    .catch(() => {});
}
