/* CipherVault — UI interactions */
(function () {
  "use strict";

  // Mobile sidebar
  const sidebarToggle = document.getElementById("sidebarToggle");
  const sidebarBackdrop = document.getElementById("sidebarBackdrop");
  const closeSidebar = () => document.body.classList.remove("sidebar-open");

  if (sidebarToggle) {
    sidebarToggle.addEventListener("click", () => {
      document.body.classList.toggle("sidebar-open");
    });
  }
  if (sidebarBackdrop) {
    sidebarBackdrop.addEventListener("click", closeSidebar);
  }
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") closeSidebar();
  });

  // Confirm destructive actions: <form data-confirm="message">
  document.querySelectorAll("form[data-confirm]").forEach((form) => {
    form.addEventListener("submit", (event) => {
      if (!window.confirm(form.getAttribute("data-confirm"))) {
        event.preventDefault();
      }
    });
  });

  // Upload drop zone + selected filename
  const dropZone = document.querySelector("[data-file-drop]");
  if (dropZone) {
    const input = dropZone.querySelector('input[type="file"]');
    const label = dropZone.querySelector("[data-selected-file]");

    const describe = (file) => {
      if (!file) {
        if (label) label.textContent = "";
        return;
      }
      const size = file.size < 1024 * 1024
        ? (file.size / 1024).toFixed(1) + " KB"
        : (file.size / (1024 * 1024)).toFixed(2) + " MB";
      if (label) label.textContent = file.name + " · " + size;
    };

    if (input && label) {
      input.addEventListener("change", () => describe(input.files[0]));
      ["dragenter", "dragover"].forEach((name) =>
        dropZone.addEventListener(name, (event) => {
          event.preventDefault();
          dropZone.classList.add("dragover");
        })
      );
      ["dragleave", "drop"].forEach((name) =>
        dropZone.addEventListener(name, (event) => {
          event.preventDefault();
          dropZone.classList.remove("dragover");
        })
      );
      dropZone.addEventListener("drop", (event) => {
        if (event.dataTransfer.files.length) {
          input.files = event.dataTransfer.files;
          describe(input.files[0]);
        }
      });
    }
  }

  // Auto-submit sort selects
  document.querySelectorAll("[data-autosubmit]").forEach((select) => {
    select.addEventListener("change", () => {
      if (select.form) select.form.submit();
    });
  });

  // Dismiss flash alerts after 7 seconds
  window.setTimeout(() => {
    document.querySelectorAll(".app-alert").forEach((alert) => {
      if (window.bootstrap) {
        const instance = window.bootstrap.Alert.getOrCreateInstance(alert);
        instance.close();
      }
    });
  }, 7000);
})();
