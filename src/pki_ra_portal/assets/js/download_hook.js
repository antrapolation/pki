const DownloadHook = {
  mounted() {
    this.handleEvent("download", ({content, filename, content_type}) => {
      const blob = new Blob([content], {type: content_type})
      const url = URL.createObjectURL(blob)
      const a = document.createElement("a")
      a.href = url
      a.download = filename
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
    })
  }
}

export default DownloadHook
