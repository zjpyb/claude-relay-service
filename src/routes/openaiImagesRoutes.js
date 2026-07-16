const express = require('express')
const crypto = require('crypto')
const { v4: uuidv4 } = require('uuid')
const router = express.Router()
const logger = require('../utils/logger')
const { authenticateApiKey } = require('../middleware/auth')
const apiKeyService = require('../services/apiKeyService')
const openaiResponsesAccountService = require('../services/account/openaiResponsesAccountService')
const unifiedOpenAIScheduler = require('../services/scheduler/unifiedOpenAIScheduler')
const upstreamErrorHelper = require('../utils/upstreamErrorHelper')
const redis = require('../models/redis')
const { getOpenAIAuthToken } = require('../services/openaiAuthService')
const {
  CODEX_IMAGE_SCHEDULER_MODEL,
  parseImagesRequest,
  forwardDirectImages,
  forwardCodexImages,
  buildImagesResponse
} = require('../services/openaiImagesService')
const {
  createRequestDetailMeta,
  extractOpenAICacheReadTokens
} = require('../utils/requestDetailHelper')
const { getSafeMessage } = require('../utils/errorSanitizer')

const FORWARDED_RESPONSE_HEADERS = [
  'content-type',
  'openai-request-id',
  'x-request-id',
  'retry-after',
  'x-ratelimit-limit-requests',
  'x-ratelimit-remaining-requests',
  'x-ratelimit-reset-requests'
]

function sendError(res, status, message, type = 'api_error', code = null) {
  return res.status(status).json({
    error: {
      message,
      type,
      ...(code ? { code } : {})
    }
  })
}

function copyResponseHeaders(res, headers = {}) {
  for (const name of FORWARDED_RESPONSE_HEADERS) {
    const value = headers[name]
    if (value !== undefined) {
      res.setHeader(name, value)
    }
  }
}

function parseResponseBuffer(data, contentType) {
  const buffer = Buffer.isBuffer(data) ? data : Buffer.from(data || '')
  if (String(contentType || '').includes('application/json')) {
    try {
      return JSON.parse(buffer.toString())
    } catch (error) {
      return buffer
    }
  }
  return buffer
}

async function acquireResponsesConcurrency(account) {
  const maxConcurrentTasks = Number(account.maxConcurrentTasks || 0)
  if (maxConcurrentTasks <= 0) {
    return async () => {}
  }

  const requestId = uuidv4()
  const current = Number(
    await redis.incrOpenAIResponsesAccountConcurrency(account.id, requestId, 600)
  )
  if (current > maxConcurrentTasks) {
    await redis.decrOpenAIResponsesAccountConcurrency(account.id, requestId)
    const error = new Error(`Account concurrency limit reached: ${maxConcurrentTasks}`)
    error.statusCode = 429
    error.type = 'account_concurrency_limit'
    error.code = 'account_concurrency_limit'
    throw error
  }

  let released = false
  return async () => {
    if (released) {
      return
    }
    released = true
    await redis.decrOpenAIResponsesAccountConcurrency(account.id, requestId)
  }
}

async function recordImagesUsage(req, apiKeyData, auth, model, usage, statusCode) {
  if (!usage || !apiKeyData?.id) {
    return
  }

  try {
    const totalInputTokens = Number(usage.input_tokens || usage.prompt_tokens || 0)
    const outputTokens = Number(usage.output_tokens || usage.completion_tokens || 0)
    const cacheReadTokens = extractOpenAICacheReadTokens(usage)
    const actualInputTokens = Math.max(0, totalInputTokens - cacheReadTokens)
    const totalTokens = Number(usage.total_tokens || totalInputTokens + outputTokens)

    const usageCosts = await apiKeyService.recordUsage(
      apiKeyData.id,
      actualInputTokens,
      outputTokens,
      0,
      cacheReadTokens,
      model,
      auth.accountId,
      auth.accountType,
      null,
      createRequestDetailMeta(req, {
        requestBody: req.body,
        stream: Boolean(req.body?.stream),
        statusCode
      }),
      usage
    )

    if (auth.accountType === 'openai-responses') {
      await openaiResponsesAccountService.updateAccountUsage(auth.accountId, totalTokens)
      if (Number(auth.account.dailyQuota || 0) > 0 && usageCosts.realCost > 0) {
        await openaiResponsesAccountService.updateUsageQuota(auth.accountId, usageCosts.realCost)
      }
    }
  } catch (error) {
    logger.error('Failed to record OpenAI Images usage:', error)
  }
}

async function updateAccountHealth(auth, status, errorData, sessionHash) {
  if (!auth?.accountId) {
    return
  }

  if (status === 429) {
    await unifiedOpenAIScheduler.markAccountRateLimited(
      auth.accountId,
      auth.accountType,
      sessionHash,
      errorData?.error?.resets_in_seconds || null
    )
  } else if (status === 401 || status === 402) {
    const message =
      errorData?.error?.message || errorData?.message || `OpenAI Images upstream returned ${status}`
    await unifiedOpenAIScheduler.markAccountUnauthorized(
      auth.accountId,
      auth.accountType,
      sessionHash,
      message
    )
  } else if (status >= 500) {
    await upstreamErrorHelper.markTempUnavailable(auth.accountId, auth.accountType, status)
  }
}

function writeImageStreamEvent(res, parsed, event) {
  const eventPrefix = parsed.endpoint.endsWith('/edits') ? 'image_edit' : 'image_generation'
  if (!res.headersSent) {
    res.status(200)
    res.setHeader('Content-Type', 'text/event-stream')
    res.setHeader('Cache-Control', 'no-cache')
    res.setHeader('Connection', 'keep-alive')
    res.setHeader('X-Accel-Buffering', 'no')
  }

  if (event.type === 'partial') {
    res.write(
      `event: ${eventPrefix}.partial_image\ndata: ${JSON.stringify({
        type: `${eventPrefix}.partial_image`,
        partial_image_index: event.partialImageIndex,
        b64_json: event.b64Json,
        output_format: event.outputFormat
      })}\n\n`
    )
    return
  }

  const { image } = event
  const data = {
    type: `${eventPrefix}.completed`,
    ...(parsed.responseFormat === 'url'
      ? { url: `data:image/${image.outputFormat || 'png'};base64,${image.result}` }
      : { b64_json: image.result }),
    output_format: image.outputFormat || 'png'
  }
  if (image.revisedPrompt) {
    data.revised_prompt = image.revisedPrompt
  }
  if (event.usage) {
    data.usage = event.usage
  }
  res.write(`event: ${eventPrefix}.completed\ndata: ${JSON.stringify(data)}\n\n`)
}

function extractUsageFromSSEFrame(frame, state) {
  for (const line of frame.split(/\r?\n/)) {
    if (!line.startsWith('data:')) {
      continue
    }
    const raw = line.slice(5).trim()
    if (!raw || raw === '[DONE]') {
      continue
    }
    try {
      const event = JSON.parse(raw)
      const response = event.response || event
      if (response.usage) {
        state.usage = response.usage
      }
      if (response.model) {
        state.model = response.model
      }
    } catch (error) {
      // Ignore non-JSON SSE payloads while preserving the upstream stream.
    }
  }
}

function pipeDirectImageStream({
  req,
  res,
  upstream,
  parsed,
  apiKeyData,
  auth,
  releaseConcurrency
}) {
  const state = { buffer: '', usage: null, model: parsed.model }
  let finished = false

  const cleanup = async () => {
    if (finished) {
      return
    }
    finished = true
    await releaseConcurrency().catch((error) => {
      logger.error('Failed to release streaming OpenAI Images concurrency:', error)
    })
  }

  upstream.data.on('data', (chunk) => {
    if (!res.destroyed) {
      res.write(chunk)
    }
    state.buffer += chunk.toString()
    const frames = state.buffer.split(/\r?\n\r?\n/)
    state.buffer = frames.pop() || ''
    for (const frame of frames) {
      extractUsageFromSSEFrame(frame, state)
    }
  })

  upstream.data.on('end', async () => {
    if (state.buffer.trim()) {
      extractUsageFromSSEFrame(state.buffer, state)
    }
    await recordImagesUsage(req, apiKeyData, auth, state.model, state.usage, upstream.status)
    if (!res.writableEnded) {
      res.end()
    }
    await cleanup()
  })

  upstream.data.on('error', async (error) => {
    logger.error('OpenAI Images upstream stream failed:', error)
    if (!res.writableEnded) {
      res.end()
    }
    await cleanup()
  })

  res.once('close', () => {
    if (!upstream.data.destroyed) {
      upstream.data.destroy()
    }
    cleanup().catch(() => {})
  })
}

async function handleImages(req, res) {
  let auth = null
  let releaseConcurrency = async () => {}
  let parsed = null
  const apiKeyData = req.apiKey || {}
  const abortController = new AbortController()
  const sessionId = req.headers['session_id'] || req.headers['x-session-id'] || null
  const sessionHash = sessionId ? crypto.createHash('sha256').update(sessionId).digest('hex') : null

  try {
    res.once('close', () => abortController.abort())

    if (!apiKeyService.hasPermission(apiKeyData.permissions, 'openai')) {
      return sendError(
        res,
        403,
        'This API key does not have permission to access OpenAI',
        'permission_denied',
        'permission_denied'
      )
    }

    parsed = await parseImagesRequest(req)
    req.body = parsed.fields
    auth = await getOpenAIAuthToken(apiKeyData, sessionId, CODEX_IMAGE_SCHEDULER_MODEL)

    if (auth.accountType === 'openai-responses') {
      releaseConcurrency = await acquireResponsesConcurrency(auth.account)
      const upstream = await forwardDirectImages(
        req,
        parsed,
        auth.account,
        auth.proxy,
        abortController.signal
      )
      copyResponseHeaders(res, upstream.headers)

      if (parsed.stream) {
        res.status(upstream.status)
        if (upstream.status >= 400) {
          await updateAccountHealth(auth, upstream.status, null, sessionHash)
        }
        pipeDirectImageStream({
          req,
          res,
          upstream,
          parsed,
          apiKeyData,
          auth,
          releaseConcurrency
        })
        return
      }

      const responseData = parseResponseBuffer(upstream.data, upstream.headers['content-type'])
      if (upstream.status >= 400) {
        await updateAccountHealth(auth, upstream.status, responseData, sessionHash)
      } else if (responseData && !Buffer.isBuffer(responseData)) {
        await recordImagesUsage(
          req,
          apiKeyData,
          auth,
          responseData.model || parsed.model,
          responseData.usage,
          upstream.status
        )
      }

      res.status(upstream.status)
      return Buffer.isBuffer(responseData) ? res.send(responseData) : res.json(responseData)
    }

    let streamStarted = false
    const result = await forwardCodexImages(
      req,
      parsed,
      auth,
      (event) => {
        if (!parsed.stream || res.destroyed) {
          return
        }
        streamStarted = true
        writeImageStreamEvent(res, parsed, event)
      },
      abortController.signal
    )

    if (result.errorData !== undefined) {
      await updateAccountHealth(auth, result.response.status, result.errorData, sessionHash)
      return sendError(
        res,
        result.response.status,
        result.errorData?.error?.message || result.errorData?.message || String(result.errorData),
        result.errorData?.error?.type || 'upstream_error',
        result.errorData?.error?.code || null
      )
    }

    await recordImagesUsage(
      req,
      apiKeyData,
      auth,
      parsed.model,
      result.state.usage,
      result.response.status
    )

    if (parsed.stream) {
      if (!streamStarted) {
        for (const image of result.state.results) {
          writeImageStreamEvent(res, parsed, { type: 'completed', image })
        }
      }
      return res.end()
    }

    return res.json(buildImagesResponse(result.state, parsed.responseFormat))
  } catch (error) {
    logger.error('OpenAI Images request failed:', error)
    if (res.destroyed || error.code === 'ERR_CANCELED') {
      return
    }
    const status = error.statusCode || error.response?.status || 500
    const errorData = error.upstream || error.response?.data || null
    await updateAccountHealth(auth, status, errorData, sessionHash).catch(() => {})

    if (res.headersSent) {
      res.write(
        `event: error\ndata: ${JSON.stringify({
          error: {
            message: getSafeMessage(error),
            type: error.type || 'api_error',
            code: error.code || null
          }
        })}\n\n`
      )
      return res.end()
    }

    return sendError(
      res,
      status,
      getSafeMessage(error),
      error.type || 'api_error',
      error.code || null
    )
  } finally {
    if (!parsed?.stream) {
      await releaseConcurrency().catch((error) => {
        logger.error('Failed to release OpenAI Images concurrency:', error)
      })
    }
  }
}

router.post(['/images/generations', '/v1/images/generations'], authenticateApiKey, handleImages)
router.post(['/images/edits', '/v1/images/edits'], authenticateApiKey, handleImages)

module.exports = router
module.exports.handleImages = handleImages
