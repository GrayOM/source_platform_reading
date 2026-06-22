(function () {
  localStorage.setItem("access_token", "e2e-local-storage-token");
  sessionStorage.setItem("session_token", "e2e-session-storage-token");

  const output = document.getElementById("dom-xss-output");
  if (output && location.hash.length > 1) {
    output.innerHTML = decodeURIComponent(location.hash.slice(1));
  }

  window.addEventListener("message", function (event) {
    if (event.data && event.data.type === "preview") {
      document.body.insertAdjacentHTML("beforeend", event.data.html);
    }
  });

  fetch("/api/profile?include=roles")
    .then(function (response) {
      return response.text();
    })
    .catch(function () {});

  fetch("/api/orders/42", {
    headers: { Authorization: "Bearer e2e-hardcoded-test-token" },
  }).catch(function () {});
})();
//# sourceMappingURL=/app.js.map
