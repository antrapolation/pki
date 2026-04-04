// Converts all <time data-local> elements from UTC to the browser's local timezone.
// Formats: "datetime" (default) = "2026-04-04 18:31:55", "date" = "2026-04-04", "time" = "18:31:55"

function formatLocalTime(el) {
  const iso = el.getAttribute("datetime")
  if (!iso) return

  const date = new Date(iso.endsWith("Z") ? iso : iso + "Z")
  if (isNaN(date)) return

  const fmt = el.dataset.localFormat || "datetime"

  const pad = (n) => String(n).padStart(2, "0")
  const y = date.getFullYear()
  const mo = pad(date.getMonth() + 1)
  const d = pad(date.getDate())
  const h = pad(date.getHours())
  const mi = pad(date.getMinutes())
  const s = pad(date.getSeconds())

  if (fmt === "date") {
    el.textContent = `${y}-${mo}-${d}`
  } else if (fmt === "time") {
    el.textContent = `${h}:${mi}:${s}`
  } else {
    el.textContent = `${y}-${mo}-${d} ${h}:${mi}:${s}`
  }
}

function convertAll() {
  document.querySelectorAll("time[data-local]").forEach(formatLocalTime)
}

// Run on initial load, LiveView page navigations, and LiveView updates
document.addEventListener("DOMContentLoaded", convertAll)
window.addEventListener("phx:page-loading-stop", convertAll)

// Catch LiveView patches that add new <time> elements
const observer = new MutationObserver((mutations) => {
  for (const m of mutations) {
    for (const node of m.addedNodes) {
      if (node.nodeType !== 1) continue
      if (node.matches && node.matches("time[data-local]")) formatLocalTime(node)
      if (node.querySelectorAll) {
        node.querySelectorAll("time[data-local]").forEach(formatLocalTime)
      }
    }
  }
})
observer.observe(document.body, { childList: true, subtree: true })

export default convertAll
