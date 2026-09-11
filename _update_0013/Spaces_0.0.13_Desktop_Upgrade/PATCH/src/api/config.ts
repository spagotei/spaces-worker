export const SPACES_API_URL = (
  import.meta.env.VITE_SPACES_API_URL ||
  'https://scrounge-spaces-api.spagotei.workers.dev'
).replace(/\/+$/, '')
