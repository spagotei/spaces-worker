export type ImagePreset = 'avatar' | 'banner'

const limits = {
  avatar: { width: 384, height: 384, quality: 0.82 },
  banner: { width: 1200, height: 480, quality: 0.8 },
} as const

type CropInput = { zoom?: number; x?: number; y?: number }

function readImageSource(source: string): Promise<HTMLImageElement> {
  return new Promise((resolve, reject) => {
    const image = new Image()
    image.onload = () => resolve(image)
    image.onerror = () => reject(new Error('Could not decode that image.'))
    image.src = source
  })
}

function readImage(file: File): Promise<HTMLImageElement> {
  return new Promise((resolve, reject) => {
    const url = URL.createObjectURL(file)
    const image = new Image()
    image.onload = () => {
      URL.revokeObjectURL(url)
      resolve(image)
    }
    image.onerror = () => {
      URL.revokeObjectURL(url)
      reject(new Error('Could not decode that image.'))
    }
    image.src = url
  })
}

export function imageFileToRawDataUrl(file: File): Promise<string> {
  if (!file.type.startsWith('image/')) return Promise.reject(new Error('Choose an image file.'))
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () => resolve(String(reader.result ?? ''))
    reader.onerror = () => reject(new Error('Could not read that image.'))
    reader.readAsDataURL(file)
  })
}

function renderCrop(image: HTMLImageElement, preset: ImagePreset, crop: CropInput) {
  const target = limits[preset]
  const zoom = Math.max(1, Math.min(2.4, Number(crop.zoom ?? 1)))
  const x = Math.max(0, Math.min(100, Number(crop.x ?? 50))) / 100
  const y = Math.max(0, Math.min(100, Number(crop.y ?? 50))) / 100
  const targetRatio = target.width / target.height
  const imageRatio = image.width / image.height

  let baseW: number
  let baseH: number
  if (imageRatio > targetRatio) {
    baseH = image.height
    baseW = baseH * targetRatio
  } else {
    baseW = image.width
    baseH = baseW / targetRatio
  }

  const sourceW = baseW / zoom
  const sourceH = baseH / zoom
  const maxX = Math.max(0, image.width - sourceW)
  const maxY = Math.max(0, image.height - sourceH)
  const sx = maxX * x
  const sy = maxY * y

  const canvas = document.createElement('canvas')
  canvas.width = target.width
  canvas.height = target.height
  const ctx = canvas.getContext('2d')
  if (!ctx) throw new Error('Image tools are unavailable in this browser.')
  ctx.imageSmoothingEnabled = true
  ctx.imageSmoothingQuality = 'high'
  ctx.drawImage(image, sx, sy, sourceW, sourceH, 0, 0, target.width, target.height)
  return canvas
}

function compressedDataUrl(canvas: HTMLCanvasElement, qualityStart: number) {
  let quality = qualityStart
  let output = canvas.toDataURL('image/webp', quality)
  while (output.length > 280_000 && quality > 0.38) {
    quality -= 0.08
    output = canvas.toDataURL('image/webp', quality)
  }
  if (output.length > 300_000) throw new Error('That image could not be compressed small enough. Try a simpler image.')
  return output
}

export async function cropImageSource(source: string, preset: ImagePreset, crop: CropInput = {}): Promise<string> {
  const image = await readImageSource(source)
  const target = limits[preset]
  return compressedDataUrl(renderCrop(image, preset, crop), target.quality)
}

export async function imageFileToDataUrl(file: File, preset: ImagePreset): Promise<string> {
  if (!file.type.startsWith('image/')) throw new Error('Choose an image file.')
  const image = await readImage(file)
  const target = limits[preset]
  return compressedDataUrl(renderCrop(image, preset, { zoom: 1, x: 50, y: 50 }), target.quality)
}
