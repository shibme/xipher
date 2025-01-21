const themeToggleBtn = document.getElementById("theme-toggle");

function toggleTheme() {
    const currentTheme = document.documentElement.getAttribute("data-theme");
    const newTheme = currentTheme === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", newTheme);
    localStorage.setItem("theme", newTheme);
}

themeToggleBtn.addEventListener("click", toggleTheme);

function loadTheme() {
    const storedTheme = localStorage.getItem("theme");
    const theme = storedTheme || (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
    document.documentElement.setAttribute("data-theme", theme);
}

const dropArea = document.getElementById("drop-area");

dropArea.addEventListener("dragover", (event) => {
    event.preventDefault();
    dropArea.classList.add("dragover");
});

dropArea.addEventListener("dragleave", () => {
    dropArea.classList.remove("dragover");
});

dropArea.addEventListener("drop", (event) => {
    event.preventDefault();
    dropArea.classList.remove("dragover");
    const droppedFiles = event.dataTransfer.files;
    if (droppedFiles.length > 0) {
        fileInput.files = droppedFiles;
        handleFileSelect();
    }
});