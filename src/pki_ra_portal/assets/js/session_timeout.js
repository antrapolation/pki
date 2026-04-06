const SessionTimeout = {
  mounted() {
    this.warningMs = parseInt(this.el.dataset.warningMs) || 25 * 60 * 1000
    this.timeoutMs = parseInt(this.el.dataset.timeoutMs) || 30 * 60 * 1000
    this.lastActivity = Date.now()
    this.warningShown = false
    this.countdownInterval = null

    // Track user activity
    const events = ["mousedown", "keydown", "scroll", "touchstart"]
    this.activityHandler = () => {
      this.lastActivity = Date.now()
      if (this.warningShown) {
        this.hideWarning()
      }
    }
    events.forEach(e => document.addEventListener(e, this.activityHandler, { passive: true }))

    // Continue button
    const continueBtn = document.getElementById("session-continue-btn")
    if (continueBtn) {
      continueBtn.addEventListener("click", () => this.continueSession())
    }

    // Check every 30 seconds
    this.checkInterval = setInterval(() => this.checkTimeout(), 30000)
  },

  destroyed() {
    const events = ["mousedown", "keydown", "scroll", "touchstart"]
    events.forEach(e => document.removeEventListener(e, this.activityHandler))
    clearInterval(this.checkInterval)
    clearInterval(this.countdownInterval)
  },

  checkTimeout() {
    const idle = Date.now() - this.lastActivity

    if (idle >= this.timeoutMs) {
      this.submitLogout()
    } else if (idle >= this.warningMs && !this.warningShown) {
      this.showWarning()
    }
  },

  submitLogout() {
    const csrfToken = document.querySelector("meta[name='csrf-token']").getAttribute("content")
    const form = document.createElement("form")
    form.method = "post"
    form.action = "/logout"
    form.innerHTML = `<input type="hidden" name="_method" value="delete"><input type="hidden" name="_csrf_token" value="${csrfToken}">`
    document.body.appendChild(form)
    form.submit()
  },

  showWarning() {
    this.warningShown = true
    const modal = document.getElementById("session-timeout-modal")
    const countdown = document.getElementById("session-timeout-countdown")

    if (modal) {
      modal.classList.remove("hidden")

      this.countdownInterval = setInterval(() => {
        const left = this.timeoutMs - (Date.now() - this.lastActivity)
        if (left <= 0) {
          this.submitLogout()
        } else {
          const mins = Math.floor(left / 60000)
          const secs = Math.floor((left % 60000) / 1000)
          if (countdown) {
            countdown.textContent = `${mins}:${secs.toString().padStart(2, "0")}`
          }
        }
      }, 1000)
    }
  },

  hideWarning() {
    this.warningShown = false
    clearInterval(this.countdownInterval)
    const modal = document.getElementById("session-timeout-modal")
    if (modal) modal.classList.add("hidden")
  },

  continueSession() {
    this.lastActivity = Date.now()
    this.hideWarning()
    this.pushEvent("keep_alive", {})
  }
}

export default SessionTimeout
