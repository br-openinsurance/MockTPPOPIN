function directorySso() {
  window.location.replace("/auth/directory");
}

document.addEventListener("DOMContentLoaded", () => {
  const button = document.getElementById("directory-button");
  button.addEventListener("click", directorySso);
});
