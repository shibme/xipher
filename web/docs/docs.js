/* ==========================================================================
   Xipher Docs - interactions
   ========================================================================== */

// ---- Theme (shared behaviour with the app) ----
function loadTheme() {
    const storedTheme = localStorage.getItem("theme");
    const theme = storedTheme || (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
    document.documentElement.setAttribute("data-theme", theme);
}
loadTheme();

const themeToggleBtn = document.getElementById("theme-toggle");
if (themeToggleBtn) {
    themeToggleBtn.addEventListener("click", () => {
        const current = document.documentElement.getAttribute("data-theme");
        const next = current === "dark" ? "light" : "dark";
        document.documentElement.setAttribute("data-theme", next);
        localStorage.setItem("theme", next);
    });
}

// ---- Mobile sidebar ----
const sidebar = document.getElementById("docs-sidebar");
const sidebarToggle = document.getElementById("sidebar-toggle");
const sidebarBackdrop = document.getElementById("sidebar-backdrop");

function openSidebar() {
    sidebar.classList.add("is-open");
    sidebarBackdrop.hidden = false;
}

function closeSidebar() {
    sidebar.classList.remove("is-open");
    sidebarBackdrop.hidden = true;
}

if (sidebarToggle) {
    sidebarToggle.addEventListener("click", () => {
        if (sidebar.classList.contains("is-open")) {
            closeSidebar();
        } else {
            openSidebar();
        }
    });
}

if (sidebarBackdrop) {
    sidebarBackdrop.addEventListener("click", closeSidebar);
}

// Close the sidebar after picking a link on small screens.
const navLinks = Array.from(document.querySelectorAll(".docs-nav-link"));
navLinks.forEach((link) => {
    link.addEventListener("click", () => {
        if (window.matchMedia("(max-width: 880px)").matches) {
            closeSidebar();
        }
    });
});

// ---- Scroll-spy: highlight the active nav link ----
const sections = navLinks
    .map((link) => {
        const id = link.getAttribute("href").slice(1);
        const el = document.getElementById(id);
        return el ? { link, el } : null;
    })
    .filter(Boolean);

if ("IntersectionObserver" in window && sections.length) {
    const visible = new Set();
    const observer = new IntersectionObserver(
        (entries) => {
            entries.forEach((entry) => {
                if (entry.isIntersecting) {
                    visible.add(entry.target.id);
                } else {
                    visible.delete(entry.target.id);
                }
            });
            // Activate the topmost visible section.
            let activeId = null;
            for (const { el } of sections) {
                if (visible.has(el.id)) {
                    activeId = el.id;
                    break;
                }
            }
            let activeLink = null;
            navLinks.forEach((link) => {
                const id = link.getAttribute("href").slice(1);
                const isActive = id === activeId;
                link.classList.toggle("is-active", isActive);
                if (isActive) {
                    activeLink = link;
                }
            });
            keepActiveLinkInView(activeLink);
        },
        { rootMargin: "-72px 0px -65% 0px", threshold: 0 }
    );
    sections.forEach(({ el }) => observer.observe(el));
}

// Scroll the sidebar (only) so the active link stays visible as the page scrolls.
function keepActiveLinkInView(link) {
    if (!sidebar || !link) {
        return;
    }
    const linkRect = link.getBoundingClientRect();
    const barRect = sidebar.getBoundingClientRect();
    const margin = 16;
    if (linkRect.top < barRect.top + margin) {
        sidebar.scrollTop -= barRect.top + margin - linkRect.top;
    } else if (linkRect.bottom > barRect.bottom - margin) {
        sidebar.scrollTop += linkRect.bottom - (barRect.bottom - margin);
    }
}

// ---- Copy buttons on code blocks ----
// How long the "copied" check mark stays before reverting to the copy icon.
const CODE_COPY_FEEDBACK_MS = 1600;

const COPY_ICON_SVG = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="9" y="9" width="11" height="11" rx="2"></rect><path d="M5 15V5a2 2 0 0 1 2-2h8"></path></svg>';
const CHECK_ICON_SVG = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20 6 9 17l-5-5"></path></svg>';

document.querySelectorAll(".code-block").forEach((block) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "code-copy-button";
    button.innerHTML = COPY_ICON_SVG;
    button.title = "Copy";
    button.setAttribute("aria-label", "Copy code");
    button.addEventListener("click", async () => {
        const code = block.querySelector("code");
        const text = code ? code.textContent : "";
        try {
            await navigator.clipboard.writeText(text);
            button.innerHTML = CHECK_ICON_SVG;
            button.classList.add("copied");
            setTimeout(() => {
                button.innerHTML = COPY_ICON_SVG;
                button.classList.remove("copied");
            }, CODE_COPY_FEEDBACK_MS);
        } catch (err) {
            console.error("Copy failed:", err);
        }
    });
    block.appendChild(button);
});
