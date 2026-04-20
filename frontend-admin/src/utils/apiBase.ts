export const getApiBaseURL = () => {
  const params = new URLSearchParams(window.location.search)
  const backendPort = params.get('backend_port')
  const envPort = process.env.UMI_APP_BACKEND_PORT || '9092'
  const protocol = window.location.protocol
  const host = window.location.hostname

  if (process.env.NODE_ENV === 'development' && backendPort) {
    return `${protocol}//${host}:${backendPort}`
  }

  if (process.env.NODE_ENV === 'development') {
    return `${protocol}//${host}:${envPort}`
  }

  return `${protocol}//${window.location.host}`
}
