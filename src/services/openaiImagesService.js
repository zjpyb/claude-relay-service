const axios = require('axios')
const Busboy = require('busboy')
const FormData = require('form-data')
const config = require('../../config/config')
const ProxyHelper = require('../utils/proxyHelper')
const { filterForOpenAI } = require('../utils/headerFilter')

const DEFAULT_IMAGE_MODEL = 'gpt-image-2'
const CODEX_IMAGE_MAIN_MODEL = 'gpt-5.4-mini'
const CODEX_IMAGE_SCHEDULER_MODEL = 'gpt-5.4'
const CODEX_IMAGES_ENDPOINT = 'https://chatgpt.com/backend-api/codex/responses'
const MAX_IMAGE_FILE_SIZE = 20 * 1024 * 1024
const MAX_MULTIPART_SIZE =
  (Number.parseInt(process.env.REQUEST_MAX_SIZE_MB || '100', 10) || 100) * 1024 * 1024

function normalizeEndpoint(path) {
  return String(path || '').includes('/images/edits')
    ? '/v1/images/edits'
    : '/v1/images/generations'
}

function normalizeResponseFormat(value) {
  return String(value || '').toLowerCase() === 'url' ? 'url' : 'b64_json'
}

function parsePositiveInteger(value, fallback = 1) {
  if (value === undefined || value === null || value === '') {
    return fallback
  }
  const parsed = Number(value)
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw createInvalidRequestError('n must be a positive integer')
  }
  return parsed
}

function createInvalidRequestError(message) {
  const error = new Error(message)
  error.statusCode = 400
  error.type = 'invalid_request_error'
  return error
}

function appendImageReference(images, value) {
  if (typeof value === 'string' && value.trim()) {
    images.push(value.trim())
    return
  }
  if (!value || typeof value !== 'object') {
    return
  }
  const imageUrl = value.image_url?.url || value.image_url || value.url
  if (typeof imageUrl === 'string' && imageUrl.trim()) {
    images.push(imageUrl.trim())
  }
}

function parseJSONImagesRequest(req) {
  const { body } = req
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw createInvalidRequestError('Request body must be a JSON object')
  }

  const images = []
  appendImageReference(images, body.image)
  if (Array.isArray(body.images)) {
    for (const image of body.images) {
      appendImageReference(images, image)
    }
  }

  let maskImage = null
  if (body.mask?.file_id) {
    throw createInvalidRequestError('mask.file_id is not supported; use mask.image_url instead')
  }
  if (body.mask) {
    const masks = []
    appendImageReference(masks, body.mask)
    maskImage = masks[0] || null
  }

  return {
    contentType: 'application/json',
    fields: { ...body },
    files: [],
    images,
    maskImage
  }
}

function parseMultipartImagesRequest(req) {
  return new Promise((resolve, reject) => {
    const fields = {}
    const files = []
    let settled = false
    let totalBytes = 0
    let parser

    const fail = (error) => {
      if (!settled) {
        settled = true
        reject(error)
        if (parser && !parser.destroyed) {
          req.unpipe(parser)
          parser.destroy()
          req.resume()
        }
      }
    }

    try {
      parser = Busboy({
        headers: req.headers,
        limits: {
          fileSize: MAX_IMAGE_FILE_SIZE,
          files: 16,
          fields: 100
        }
      })
    } catch (error) {
      fail(createInvalidRequestError(`Invalid multipart request: ${error.message}`))
      return
    }

    parser.on('field', (name, value) => {
      totalBytes += Buffer.byteLength(value)
      if (totalBytes > MAX_MULTIPART_SIZE) {
        fail(createInvalidRequestError('Multipart request body exceeds configured size limit'))
        return
      }
      if (fields[name] === undefined) {
        fields[name] = value
      } else if (Array.isArray(fields[name])) {
        fields[name].push(value)
      } else {
        fields[name] = [fields[name], value]
      }
    })

    parser.on('file', (fieldName, stream, info) => {
      const chunks = []
      let truncated = false
      stream.on('data', (chunk) => {
        if (settled) {
          return
        }
        totalBytes += chunk.length
        if (totalBytes > MAX_MULTIPART_SIZE) {
          chunks.length = 0
          fail(createInvalidRequestError('Multipart request body exceeds configured size limit'))
          return
        }
        chunks.push(chunk)
      })
      stream.on('limit', () => {
        truncated = true
      })
      stream.on('error', fail)
      stream.on('end', () => {
        if (truncated) {
          fail(
            createInvalidRequestError(`Uploaded file ${info.filename || fieldName} exceeds 20MB`)
          )
          return
        }
        files.push({
          fieldName,
          filename: info.filename || 'image',
          contentType: info.mimeType || 'application/octet-stream',
          data: Buffer.concat(chunks)
        })
      })
    })

    parser.on('filesLimit', () => fail(createInvalidRequestError('Too many uploaded files')))
    parser.on('fieldsLimit', () => fail(createInvalidRequestError('Too many multipart fields')))
    parser.on('error', fail)
    parser.on('finish', () => {
      if (settled) {
        return
      }
      settled = true
      resolve({
        contentType: req.headers['content-type'],
        fields,
        files,
        images: [],
        maskImage: null
      })
    })

    req.pipe(parser)
  })
}

function normalizeParsedRequest(req, parsed) {
  const endpoint = normalizeEndpoint(req.path || req.originalUrl)
  const model = String(parsed.fields.model || DEFAULT_IMAGE_MODEL).trim()
  const prompt = String(parsed.fields.prompt || '').trim()
  const n = parsePositiveInteger(parsed.fields.n, 1)

  for (const field of ['output_compression', 'partial_images']) {
    if (parsed.fields[field] === undefined || parsed.fields[field] === '') {
      continue
    }
    const value = Number(parsed.fields[field])
    if (!Number.isInteger(value) || value < 0) {
      throw createInvalidRequestError(`${field} must be a non-negative integer`)
    }
    parsed.fields[field] = value
  }

  if (!model) {
    throw createInvalidRequestError('model is required')
  }
  if (!model.toLowerCase().startsWith('gpt-image-')) {
    throw createInvalidRequestError(`images endpoint requires a gpt-image model, got ${model}`)
  }
  if (!prompt) {
    throw createInvalidRequestError('prompt is required')
  }

  const imageFiles = parsed.files.filter(
    (file) => file.fieldName === 'image' || file.fieldName.startsWith('image[')
  )
  const maskFile = parsed.files.find((file) => file.fieldName === 'mask') || null
  if (endpoint === '/v1/images/edits' && imageFiles.length === 0 && parsed.images.length === 0) {
    throw createInvalidRequestError('image input is required')
  }

  return {
    endpoint,
    multipart: parsed.contentType.startsWith('multipart/form-data'),
    contentType: parsed.contentType,
    fields: parsed.fields,
    files: parsed.files,
    imageFiles,
    maskFile,
    images: parsed.images,
    maskImage: parsed.maskImage,
    model,
    prompt,
    n,
    stream:
      String(parsed.fields.stream || '').toLowerCase() === 'true' || parsed.fields.stream === true,
    responseFormat: normalizeResponseFormat(parsed.fields.response_format)
  }
}

async function parseImagesRequest(req) {
  const contentType = String(req.headers['content-type'] || '').toLowerCase()
  const parsed = contentType.startsWith('multipart/form-data')
    ? await parseMultipartImagesRequest(req)
    : parseJSONImagesRequest(req)
  return normalizeParsedRequest(req, parsed)
}

function buildDirectTargetUrl(baseApi, endpoint) {
  const normalizedBase = String(baseApi || 'https://api.openai.com').replace(/\/$/, '')
  if (normalizedBase.endsWith('/v1')) {
    return `${normalizedBase}${endpoint.slice(3)}`
  }
  return `${normalizedBase}${endpoint}`
}

function buildDirectMultipartBody(parsed) {
  const form = new FormData()
  for (const [name, rawValue] of Object.entries(parsed.fields)) {
    if (name === 'model') {
      continue
    }
    const values = Array.isArray(rawValue) ? rawValue : [rawValue]
    for (const value of values) {
      if (value !== undefined && value !== null) {
        form.append(name, String(value))
      }
    }
  }
  form.append('model', parsed.model)
  for (const file of parsed.files) {
    form.append(file.fieldName, file.data, {
      filename: file.filename,
      contentType: file.contentType,
      knownLength: file.data.length
    })
  }
  return form
}

function applyProxy(requestOptions, proxy) {
  const proxyAgent = ProxyHelper.createProxyAgent(proxy)
  if (proxyAgent) {
    requestOptions.httpAgent = proxyAgent
    requestOptions.httpsAgent = proxyAgent
    requestOptions.proxy = false
  }
}

async function forwardDirectImages(req, parsed, account, proxy, signal = null) {
  const targetUrl = buildDirectTargetUrl(account.baseApi, parsed.endpoint)
  const data = parsed.multipart
    ? buildDirectMultipartBody(parsed)
    : { ...parsed.fields, model: parsed.model }
  const headers = {
    ...filterForOpenAI(req.headers),
    Authorization: `Bearer ${account.apiKey}`,
    Accept: parsed.stream ? 'text/event-stream' : 'application/json'
  }

  if (parsed.multipart) {
    Object.assign(headers, data.getHeaders())
    delete headers['content-length']
  } else {
    headers['Content-Type'] = 'application/json'
  }
  if (account.userAgent) {
    headers['User-Agent'] = account.userAgent
  }

  const requestOptions = {
    method: 'post',
    url: targetUrl,
    headers,
    data,
    timeout: config.requestTimeout || 600000,
    responseType: parsed.stream ? 'stream' : 'arraybuffer',
    validateStatus: () => true,
    signal
  }
  applyProxy(requestOptions, proxy)
  return axios(requestOptions)
}

function fileToDataURL(file) {
  return `data:${file.contentType || 'application/octet-stream'};base64,${file.data.toString('base64')}`
}

function buildCodexImagesRequest(parsed) {
  const inputContent = [{ type: 'input_text', text: parsed.prompt }]
  for (const image of parsed.images) {
    inputContent.push({ type: 'input_image', image_url: image })
  }
  for (const file of parsed.imageFiles) {
    inputContent.push({ type: 'input_image', image_url: fileToDataURL(file) })
  }

  const tool = {
    type: 'image_generation',
    action: parsed.endpoint.endsWith('/edits') ? 'edit' : 'generate',
    model: parsed.model
  }
  for (const field of [
    'size',
    'quality',
    'background',
    'output_format',
    'input_fidelity',
    'moderation',
    'style',
    'output_compression',
    'partial_images'
  ]) {
    if (parsed.fields[field] !== undefined && parsed.fields[field] !== '') {
      tool[field] = ['output_compression', 'partial_images'].includes(field)
        ? Number(parsed.fields[field])
        : parsed.fields[field]
    }
  }
  if (parsed.n > 1) {
    tool.n = parsed.n
  }

  const maskImage = parsed.maskFile ? fileToDataURL(parsed.maskFile) : parsed.maskImage
  if (maskImage) {
    tool.input_image_mask = { image_url: maskImage }
  }

  return {
    instructions: '',
    stream: true,
    reasoning: { effort: 'medium', summary: 'auto' },
    parallel_tool_calls: true,
    include: ['reasoning.encrypted_content'],
    model: CODEX_IMAGE_MAIN_MODEL,
    store: false,
    tool_choice: { type: 'image_generation' },
    input: [{ type: 'message', role: 'user', content: inputContent }],
    tools: [tool]
  }
}

function appendImageResult(results, seen, item) {
  if (!item || item.type !== 'image_generation_call' || !item.result) {
    return
  }
  const key = `${item.output_format || ''}|${item.result}`
  if (seen.has(key)) {
    return
  }
  seen.add(key)
  results.push({
    result: item.result,
    revisedPrompt: item.revised_prompt || '',
    outputFormat: item.output_format || 'png'
  })
}

function processCodexImageEvent(event, state, onEvent) {
  if (event.type === 'response.image_generation_call.partial_image' && event.partial_image_b64) {
    onEvent?.({
      type: 'partial',
      b64Json: event.partial_image_b64,
      partialImageIndex: event.partial_image_index || 0,
      outputFormat: event.output_format || 'png'
    })
    return
  }

  if (event.type === 'response.output_item.done') {
    appendImageResult(state.results, state.seen, event.item)
    return
  }

  if (event.type === 'response.completed' && event.response) {
    state.created = event.response.created_at || state.created
    state.usage = event.response.tool_usage?.image_gen || event.response.usage || state.usage
    state.actualModel = event.response.model || state.actualModel
    for (const item of event.response.output || []) {
      appendImageResult(state.results, state.seen, item)
    }
    if (!state.completedEmitted) {
      state.completedEmitted = true
      for (const image of state.results) {
        onEvent?.({ type: 'completed', image, usage: state.usage })
      }
    }
  }

  if (event.error || event.type === 'error' || event.type === 'response.failed') {
    const errorData = event.error || event.response?.error || event
    const error = new Error(errorData.message || 'Image generation failed')
    error.statusCode = errorData.status || errorData.status_code || 502
    error.upstream = event
    state.error = error
  }
}

async function collectCodexImageStream(stream, onEvent) {
  const state = {
    results: [],
    seen: new Set(),
    usage: null,
    actualModel: null,
    created: Math.floor(Date.now() / 1000),
    completedEmitted: false,
    error: null
  }
  let buffer = ''

  for await (const chunk of stream) {
    buffer += chunk.toString()
    const frames = buffer.split(/\r?\n\r?\n/)
    buffer = frames.pop() || ''
    for (const frame of frames) {
      for (const line of frame.split(/\r?\n/)) {
        if (!line.startsWith('data:')) {
          continue
        }
        const raw = line.slice(5).trim()
        if (!raw || raw === '[DONE]') {
          continue
        }
        try {
          processCodexImageEvent(JSON.parse(raw), state, onEvent)
        } catch (error) {
          if (error instanceof SyntaxError) {
            continue
          }
          throw error
        }
      }
    }
  }

  if (buffer.trim()) {
    for (const line of buffer.split(/\r?\n/)) {
      if (line.startsWith('data:')) {
        const raw = line.slice(5).trim()
        if (raw && raw !== '[DONE]') {
          processCodexImageEvent(JSON.parse(raw), state, onEvent)
        }
      }
    }
  }

  if (state.error) {
    throw state.error
  }
  if (state.results.length === 0) {
    const error = new Error('Upstream did not return image output')
    error.statusCode = 502
    throw error
  }
  return state
}

async function forwardCodexImages(req, parsed, auth, onEvent, signal = null) {
  const headers = {
    Authorization: `Bearer ${auth.accessToken}`,
    'chatgpt-account-id': auth.account.accountId || auth.account.chatgptUserId || auth.accountId,
    Host: 'chatgpt.com',
    Accept: 'text/event-stream',
    'Content-Type': 'application/json'
  }
  if (req.headers['user-agent']) {
    headers['User-Agent'] = req.headers['user-agent']
  }
  for (const name of ['openai-beta', 'version', 'session_id']) {
    if (req.headers[name] !== undefined) {
      headers[name] = req.headers[name]
    }
  }

  const requestOptions = {
    method: 'post',
    url: CODEX_IMAGES_ENDPOINT,
    headers,
    data: buildCodexImagesRequest(parsed),
    timeout: config.requestTimeout || 600000,
    responseType: 'stream',
    validateStatus: () => true,
    signal
  }
  applyProxy(requestOptions, auth.proxy)
  const response = await axios(requestOptions)
  if (response.status >= 400) {
    const chunks = []
    for await (const chunk of response.data) {
      chunks.push(chunk)
    }
    let data = Buffer.concat(chunks).toString()
    try {
      data = JSON.parse(data)
    } catch (error) {
      // Keep the upstream text when it is not JSON.
    }
    return { response, errorData: data }
  }

  const state = await collectCodexImageStream(response.data, onEvent)
  return { response, state }
}

function buildImagesResponse(state, responseFormat) {
  return {
    created: state.created || Math.floor(Date.now() / 1000),
    data: state.results.map((image) => {
      const item = {}
      if (responseFormat === 'url') {
        const mimeType =
          image.outputFormat === 'jpeg' ? 'image/jpeg' : `image/${image.outputFormat}`
        item.url = `data:${mimeType};base64,${image.result}`
      } else {
        item.b64_json = image.result
      }
      if (image.revisedPrompt) {
        item.revised_prompt = image.revisedPrompt
      }
      return item
    }),
    ...(state.usage ? { usage: state.usage } : {})
  }
}

module.exports = {
  DEFAULT_IMAGE_MODEL,
  CODEX_IMAGE_MAIN_MODEL,
  CODEX_IMAGE_SCHEDULER_MODEL,
  parseImagesRequest,
  buildDirectTargetUrl,
  buildCodexImagesRequest,
  collectCodexImageStream,
  forwardDirectImages,
  forwardCodexImages,
  buildImagesResponse
}
