// Click-to-copy for the announcement-bar install command.
// Delegated on document so it survives Material's instant navigation.
document.addEventListener("click", function (event) {
  const button = event.target.closest(".db-copy");
  if (!button) return;
  const text = button.getAttribute("data-copy");
  if (!text) return;
  navigator.clipboard.writeText(text).then(function () {
    button.classList.add("db-copy--done");
    setTimeout(function () {
      button.classList.remove("db-copy--done");
    }, 1500);
  });
});
