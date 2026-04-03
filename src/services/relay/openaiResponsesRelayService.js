const axios = require('axios')
const ProxyHelper = require('../../utils/proxyHelper')
const logger = require('../../utils/logger')
const { filterForOpenAI } = require('../../utils/headerFilter')
const openaiResponsesAccountService = require('../account/openaiResponsesAccountService')
const apiKeyService = require('../apiKeyService')
const unifiedOpenAIScheduler = require('../scheduler/unifiedOpenAIScheduler')
const redis = require('../../models/redis')
const config = require('../../../config/config')
const crypto = require('crypto')
const { v4: uuidv4 } = require('uuid')
const LRUCache = require('../../utils/lruCache')
const upstreamErrorHelper = require('../../utils/upstreamErrorHelper')
const { createOpenAITestPayload, extractErrorMessage } = require('../../utils/testPayloadHelper')

// lastUsedAt 更新节流（每账户 60 秒内最多更新一次，使用 LRU 防止内存泄漏）
const lastUsedAtThrottle = new LRUCache(1000) // 最多缓存 1000 个账户
const LAST_USED_AT_THROTTLE_MS = 60000

// 抽取缓存写入 token，兼容多种字段命名
function extractCacheCreationTokens(usageData) {
  if (!usageData || typeof usageData !== 'object') {
    return 0
  }

  const details = usageData.input_tokens_details || usageData.prompt_tokens_details || {}
  const candidates = [
    details.cache_creation_input_tokens,
    details.cache_creation_tokens,
    usageData.cache_creation_input_tokens,
    usageData.cache_creation_tokens
  ]

  for (const value of candidates) {
    if (value !== undefined && value !== null && value !== '') {
      const parsed = Number(value)
      if (!Number.isNaN(parsed)) {
        return parsed
      }
    }
  }

  return 0
}

class OpenAIResponsesRelayService {
  constructor() {
    this.defaultTimeout = config.requestTimeout || 600000
  }

  // 节流更新 lastUsedAt
  async _throttledUpdateLastUsedAt(accountId) {
    const now = Date.now()
    const lastUpdate = lastUsedAtThrottle.get(accountId)

    if (lastUpdate && now - lastUpdate < LAST_USED_AT_THROTTLE_MS) {
      return // 跳过更新
    }

    lastUsedAtThrottle.set(accountId, now, LAST_USED_AT_THROTTLE_MS)
    await openaiResponsesAccountService.updateAccount(accountId, {
      lastUsedAt: new Date().toISOString()
    })
  }

  // 处理请求转发
  async handleRequest(req, res, account, apiKeyData) {
    let abortController = null
    let concurrencyAcquired = false
    let leaseRefreshInterval = null
    let fullAccount = null
    const requestId = uuidv4()
    // 获取会话哈希（如果有的话）
    const sessionId = req.headers['session_id'] || req.body?.session_id
    const sessionHash = sessionId
      ? crypto.createHash('sha256').update(sessionId).digest('hex')
      : null

    try {
      // 获取完整的账户信息（包含解密的 API Key）
      fullAccount = await openaiResponsesAccountService.getAccount(account.id)
      if (!fullAccount) {
        throw new Error('Account not found')
      }

      const releaseConcurrency = async () => {
        if (!concurrencyAcquired) {
          return
        }

        concurrencyAcquired = false
        if (leaseRefreshInterval) {
          clearInterval(leaseRefreshInterval)
          leaseRefreshInterval = null
        }

        try {
          await redis.decrOpenAIResponsesAccountConcurrency(account.id, requestId)
        } catch (error) {
          logger.error(
            `Failed to decrement OpenAI-Responses account concurrency for ${account.id}:`,
            error
          )
        }
      }

      // 创建 AbortController 用于取消请求
      abortController = new AbortController()

      // 设置客户端断开监听器
      const handleClientDisconnect = () => {
        logger.info('🔌 Client disconnected, aborting OpenAI-Responses request')
        if (abortController && !abortController.signal.aborted) {
          abortController.abort()
        }
        releaseConcurrency().catch((error) => {
          logger.error('Failed to cleanup OpenAI-Responses concurrency on disconnect:', error)
        })
      }

      // 监听客户端断开事件
      req.once('close', handleClientDisconnect)
      res.once('close', handleClientDisconnect)
      req.once('aborted', () => {
        releaseConcurrency().catch((error) => {
          logger.error('Failed to cleanup OpenAI-Responses concurrency on abort:', error)
        })
      })
      req.once('error', () => {
        releaseConcurrency().catch((error) => {
          logger.error('Failed to cleanup OpenAI-Responses concurrency on request error:', error)
        })
      })
      res.once('finish', () => {
        releaseConcurrency().catch((error) => {
          logger.error('Failed to cleanup OpenAI-Responses concurrency on finish:', error)
        })
      })
      res.once('error', () => {
        releaseConcurrency().catch((error) => {
          logger.error('Failed to cleanup OpenAI-Responses concurrency on response error:', error)
        })
      })

      const maxConcurrentTasks = Number(fullAccount.maxConcurrentTasks || 0)
      if (maxConcurrentTasks > 0) {
        const newConcurrency = Number(
          await redis.incrOpenAIResponsesAccountConcurrency(account.id, requestId, 600)
        )
        concurrencyAcquired = true

        if (newConcurrency > maxConcurrentTasks) {
          await releaseConcurrency()

          logger.warn(
            `⚠️ OpenAI-Responses account ${account.name} (${account.id}) concurrency limit exceeded: ${newConcurrency}/${maxConcurrentTasks} (request: ${requestId}, rolled back)`
          )

          return res.status(429).json({
            error: {
              message: `Account concurrency limit reached: ${maxConcurrentTasks}`,
              type: 'account_concurrency_limit',
              code: 'account_concurrency_limit'
            },
            accountId: account.id,
            maxConcurrentTasks
          })
        }

        logger.debug(
          `🔓 Acquired OpenAI-Responses concurrency slot for account ${account.name} (${account.id}), current: ${newConcurrency}/${maxConcurrentTasks}, request: ${requestId}`
        )

        if (req.body?.stream) {
          leaseRefreshInterval = setInterval(
            async () => {
              try {
                await redis.refreshOpenAIResponsesAccountConcurrencyLease(
                  account.id,
                  requestId,
                  600
                )
              } catch (error) {
                logger.error(
                  `❌ Failed to refresh OpenAI-Responses concurrency lease for ${account.id}:`,
                  error.message
                )
              }
            },
            5 * 60 * 1000
          )
        }
      }

      // 构建目标 URL（根据 providerEndpoint 配置决定端点路径）
      const providerEndpoint = fullAccount.providerEndpoint || 'responses'
      let targetPath = req.path

      // 根据 providerEndpoint 配置归一化路径
      // 注意：unified.js 已将 /v1/chat/completions 的请求体转换为 Responses 格式，
      // 因此这里只需归一化路径即可；反向 responses→completions 需要同时转换请求体，
      // 目前不支持，所以只保留 responses 和 auto 两种模式
      if (
        providerEndpoint === 'responses' &&
        (targetPath === '/v1/chat/completions' || targetPath === '/chat/completions')
      ) {
        const newPath = targetPath.startsWith('/v1') ? '/v1/responses' : '/responses'
        logger.info(`📝 Normalized path (${req.path}) → ${newPath} (providerEndpoint=responses)`)
        targetPath = newPath
      }
      // providerEndpoint === 'auto' 时保持原始路径不变

      // 防止 baseApi 已含 /v1 时路径重复（如 baseApi=http://host/v1 + targetPath=/v1/responses → /v1/v1/responses）
      const baseApi = fullAccount.baseApi || ''
      if (baseApi.endsWith('/v1') && targetPath.startsWith('/v1/')) {
        targetPath = targetPath.slice(3) // '/v1/responses' → '/responses'
      }
      const targetUrl = `${baseApi}${targetPath}`
      logger.info(`🎯 Forwarding to: ${targetUrl}`)

      // 构建请求头 - 使用统一的 headerFilter 移除 CDN headers
      const headers = {
        ...filterForOpenAI(req.headers),
        Authorization: `Bearer ${fullAccount.apiKey}`,
        'Content-Type': 'application/json'
      }

      // 处理 User-Agent
      if (fullAccount.userAgent) {
        // 使用自定义 User-Agent
        headers['User-Agent'] = fullAccount.userAgent
        logger.debug(`📱 Using custom User-Agent: ${fullAccount.userAgent}`)
      } else if (req.headers['user-agent']) {
        // 透传原始 User-Agent
        headers['User-Agent'] = req.headers['user-agent']
        logger.debug(`📱 Forwarding original User-Agent: ${req.headers['user-agent']}`)
      }

      // 配置请求选项
      const requestOptions = {
        method: req.method,
        url: targetUrl,
        headers,
        data: req.body,
        timeout: this.defaultTimeout,
        responseType: req.body?.stream ? 'stream' : 'json',
        validateStatus: () => true, // 允许处理所有状态码
        signal: abortController.signal
      }

      // 配置代理（如果有）
      if (fullAccount.proxy) {
        const proxyAgent = ProxyHelper.createProxyAgent(fullAccount.proxy)
        if (proxyAgent) {
          requestOptions.httpAgent = proxyAgent
          requestOptions.httpsAgent = proxyAgent
          requestOptions.proxy = false
          logger.info(
            `🌐 Using proxy for OpenAI-Responses: ${ProxyHelper.getProxyDescription(fullAccount.proxy)}`
          )
        }
      }

      // 记录请求信息
      logger.info('📤 OpenAI-Responses relay request', {
        accountId: account.id,
        accountName: account.name,
        targetUrl,
        method: req.method,
        stream: req.body?.stream || false,
        model: req.body?.model || 'unknown',
        userAgent: headers['User-Agent'] || 'not set'
      })

      // 发送请求
      const response = await axios(requestOptions)

      // 处理 429 限流错误
      if (response.status === 429) {
        const { resetsInSeconds, errorData, isQuotaExhausted } = await this._handle429Error(
          account,
          response,
          req.body?.stream,
          sessionHash
        )

        const oaiAutoProtectionDisabled =
          account?.disableAutoProtection === true || account?.disableAutoProtection === 'true'
        const historyContext = {
          model: req.body?.model,
          path: req.originalUrl,
          errorBody: errorData
        }

        if (isQuotaExhausted) {
          await upstreamErrorHelper
            .recordErrorHistory(
              account.id,
              'openai-responses',
              429,
              'quota_exceeded',
              historyContext
            )
            .catch(() => {})
        }

        if (!oaiAutoProtectionDisabled) {
          await upstreamErrorHelper
            .markTempUnavailable(
              account.id,
              'openai-responses',
              429,
              resetsInSeconds || upstreamErrorHelper.parseRetryAfter(response.headers),
              isQuotaExhausted ? { ...historyContext, skipHistory: true } : historyContext
            )
            .catch(() => {})

          if (isQuotaExhausted) {
            this._probeQuotaExhausted429Recovery(fullAccount, req.body?.model).catch(
              (probeError) => {
                logger.warn(
                  `Failed to probe OpenAI-Responses account availability after quota-like 429 for ${account.id}: ${probeError.message}`
                )
              }
            )
          }
        }

        const retryCount = Number(req._openaiResponses429RetryCount || 0)
        if (retryCount < 3) {
          try {
            req._openaiResponses429RetryCount = retryCount + 1
            const retried = await this._retryUnavailableRequest(
              req,
              res,
              account,
              apiKeyData,
              sessionHash,
              handleClientDisconnect,
              releaseConcurrency,
              {
                reasonLabel: '429',
                isQuotaExhausted,
                retryCount: req._openaiResponses429RetryCount
              }
            )
            if (retried) {
              return res
            }
          } catch (retryError) {
            logger.warn(
              `Failed to retry OpenAI-Responses request after 429 for ${account.id}: ${retryError.message}`
            )
          }
        }

        // 返回错误响应（使用处理后的数据，避免循环引用）
        const errorResponse = errorData || {
          error: {
            message: 'Rate limit exceeded',
            type: 'rate_limit_error',
            code: 'rate_limit_exceeded',
            resets_in_seconds: resetsInSeconds
          }
        }
        return res.status(429).json(errorResponse)
      }

      // 处理其他错误状态码
      if (response.status >= 400) {
        // 处理流式错误响应
        let errorData = response.data
        if (response.data && typeof response.data.pipe === 'function') {
          // 流式响应需要先读取内容
          const chunks = []
          await new Promise((resolve) => {
            response.data.on('data', (chunk) => chunks.push(chunk))
            response.data.on('end', resolve)
            response.data.on('error', resolve)
            setTimeout(resolve, 5000) // 超时保护
          })
          const fullResponse = Buffer.concat(chunks).toString()

          // 尝试解析错误响应
          try {
            if (fullResponse.includes('data: ')) {
              // SSE格式
              const lines = fullResponse.split('\n')
              for (const line of lines) {
                if (line.startsWith('data: ')) {
                  const jsonStr = line.slice(6).trim()
                  if (jsonStr && jsonStr !== '[DONE]') {
                    errorData = JSON.parse(jsonStr)
                    break
                  }
                }
              }
            } else {
              // 普通JSON
              errorData = JSON.parse(fullResponse)
            }
          } catch (e) {
            logger.error('Failed to parse error response:', e)
            errorData = { error: { message: fullResponse || 'Unknown error' } }
          }
        }

        logger.error('OpenAI-Responses API error', {
          status: response.status,
          statusText: response.statusText,
          errorData
        })

        const isDailyQuotaExceeded = this._isDailyQuotaExceededError(response.status, errorData)
        const isUpstreamSchedulerRateLimit = this._isUpstreamSchedulerRateLimit(
          response.status,
          errorData
        )

        if (isDailyQuotaExceeded && account?.id) {
          const { resetAt } = this._computeNextDailyQuotaResetAt(account.quotaResetTime || '00:00')
          logger.warn(
            `💸 OpenAI Responses上游明确返回日额度耗尽，按配置重置时间暂停调度 for account ${account.id}, resetAt=${resetAt}`
          )

          try {
            const oaiAutoProtectionDisabled =
              account?.disableAutoProtection === true || account?.disableAutoProtection === 'true'
            await upstreamErrorHelper
              .recordErrorHistory(
                account.id,
                'openai-responses',
                response.status,
                'quota_exceeded',
                {
                  model: req.body?.model,
                  path: req.originalUrl,
                  errorBody: errorData,
                  resetAt
                }
              )
              .catch(() => {})
            if (!oaiAutoProtectionDisabled) {
              await openaiResponsesAccountService.updateAccount(account.id, {
                status: 'quota_exceeded',
                schedulable: 'false',
                quotaStoppedAt: new Date().toISOString(),
                rateLimitedAt: '',
                rateLimitStatus: '',
                rateLimitResetAt: '',
                errorMessage: `Payment Required: 已达到每日费用限制，重置时间 ${resetAt}`
              })
              await upstreamErrorHelper
                .clearTempUnavailable(account.id, 'openai-responses')
                .catch(() => {})
            }
            if (sessionHash) {
              await unifiedOpenAIScheduler._deleteSessionMapping(sessionHash).catch(() => {})
            }
          } catch (markError) {
            logger.warn(
              'Failed to mark OpenAI-Responses account daily quota exceeded after upstream quota error:',
              markError
            )
          }

          const retryCount = Number(req._openaiResponses429RetryCount || 0)
          if (retryCount < 3) {
            try {
              req._openaiResponses429RetryCount = retryCount + 1
              const retried = await this._retryUnavailableRequest(
                req,
                res,
                account,
                apiKeyData,
                sessionHash,
                handleClientDisconnect,
                releaseConcurrency,
                {
                  reasonLabel: `${response.status} 配额型错误`,
                  isQuotaExhausted: true,
                  retryCount: req._openaiResponses429RetryCount
                }
              )
              if (retried) {
                return res
              }
            } catch (retryError) {
              logger.warn(
                `Failed to retry OpenAI-Responses request after quota-like ${response.status} for ${account.id}: ${retryError.message}`
              )
            }
          }

          req.removeListener('close', handleClientDisconnect)
          res.removeListener('close', handleClientDisconnect)

          return res.status(402).json(this._buildDailyQuotaExceededPayload(errorData, resetAt))
        }

        if (isUpstreamSchedulerRateLimit && account?.id) {
          logger.warn(
            `🚫 OpenAI Responses上游返回模型当前不可路由，已按限流处理 for account ${account.id}`
          )

          try {
            const oaiAutoProtectionDisabled =
              account?.disableAutoProtection === true || account?.disableAutoProtection === 'true'
            const historyContext = {
              model: req.body?.model,
              path: req.originalUrl,
              errorBody: errorData,
              pauseStatus: 429
            }
            await upstreamErrorHelper
              .recordErrorHistory(
                account.id,
                'openai-responses',
                response.status,
                'unroutable_model',
                historyContext
              )
              .catch(() => {})
            if (!oaiAutoProtectionDisabled) {
              await unifiedOpenAIScheduler.markAccountRateLimited(
                account.id,
                'openai-responses',
                sessionHash
              )
              await upstreamErrorHelper
                .markTempUnavailable(account.id, 'openai-responses', 429, null, {
                  ...historyContext,
                  skipHistory: true
                })
                .catch(() => {})
            }
            if (sessionHash) {
              await unifiedOpenAIScheduler._deleteSessionMapping(sessionHash).catch(() => {})
            }
          } catch (markError) {
            logger.warn(
              'Failed to mark OpenAI-Responses account rate limited after upstream unroutable-model error:',
              markError
            )
          }
        }

        if (response.status === 401) {
          logger.warn(`🚫 OpenAI Responses账号认证失败（401错误）for account ${account?.id}`)

          try {
            // 仅临时暂停，不永久禁用
            const oaiAutoProtectionDisabled =
              account?.disableAutoProtection === true || account?.disableAutoProtection === 'true'
            if (!oaiAutoProtectionDisabled) {
              await upstreamErrorHelper
                .markTempUnavailable(account.id, 'openai-responses', 401)
                .catch(() => {})
            }
            if (sessionHash) {
              await unifiedOpenAIScheduler._deleteSessionMapping(sessionHash).catch(() => {})
            }
          } catch (markError) {
            logger.error(
              '❌ Failed to mark OpenAI-Responses account temporarily unavailable after 401:',
              markError
            )
          }

          let unauthorizedResponse = errorData
          if (
            !unauthorizedResponse ||
            typeof unauthorizedResponse !== 'object' ||
            unauthorizedResponse.pipe ||
            Buffer.isBuffer(unauthorizedResponse)
          ) {
            const fallbackMessage =
              typeof errorData === 'string' && errorData.trim() ? errorData.trim() : 'Unauthorized'
            unauthorizedResponse = {
              error: {
                message: fallbackMessage,
                type: 'unauthorized',
                code: 'unauthorized'
              }
            }
          }

          // 清理监听器
          req.removeListener('close', handleClientDisconnect)
          res.removeListener('close', handleClientDisconnect)

          return res.status(401).json(unauthorizedResponse)
        }

        if (response.status === 403 && account?.id) {
          logger.warn(`🚫 OpenAI Responses账号触发403临时暂停 for account ${account.id}`)

          try {
            const oaiAutoProtectionDisabled =
              account?.disableAutoProtection === true || account?.disableAutoProtection === 'true'
            if (!oaiAutoProtectionDisabled) {
              await upstreamErrorHelper
                .markTempUnavailable(account.id, 'openai-responses', 403)
                .catch(() => {})
            }
            if (sessionHash) {
              await unifiedOpenAIScheduler._deleteSessionMapping(sessionHash).catch(() => {})
            }
          } catch (markError) {
            logger.warn(
              'Failed to mark OpenAI-Responses account temporarily unavailable after 403:',
              markError
            )
          }
        }

        // 处理 5xx 上游错误
        if (response.status >= 500 && account?.id && !isUpstreamSchedulerRateLimit) {
          try {
            const oaiAutoProtectionDisabled =
              account?.disableAutoProtection === true || account?.disableAutoProtection === 'true'
            if (!oaiAutoProtectionDisabled) {
              await upstreamErrorHelper.markTempUnavailable(
                account.id,
                'openai-responses',
                response.status
              )
            }
            if (sessionHash) {
              await unifiedOpenAIScheduler._deleteSessionMapping(sessionHash).catch(() => {})
            }
          } catch (markError) {
            logger.warn(
              'Failed to mark OpenAI-Responses account temporarily unavailable:',
              markError
            )
          }

          const retryCount = Number(req._openaiResponses429RetryCount || 0)
          if (retryCount < 3) {
            try {
              req._openaiResponses429RetryCount = retryCount + 1
              const retried = await this._retryUnavailableRequest(
                req,
                res,
                account,
                apiKeyData,
                sessionHash,
                handleClientDisconnect,
                releaseConcurrency,
                {
                  reasonLabel: `${response.status} 上游错误`,
                  retryCount: req._openaiResponses429RetryCount
                }
              )
              if (retried) {
                return res
              }
            } catch (retryError) {
              logger.warn(
                `Failed to retry OpenAI-Responses request after upstream ${response.status} for ${account.id}: ${retryError.message}`
              )
            }
          }
        }

        // 清理监听器
        req.removeListener('close', handleClientDisconnect)
        res.removeListener('close', handleClientDisconnect)

        return res
          .status(response.status)
          .json(upstreamErrorHelper.sanitizeErrorForClient(errorData))
      }

      // 更新最后使用时间（节流）
      await this._throttledUpdateLastUsedAt(account.id)

      // 处理流式响应
      if (req.body?.stream && response.data && typeof response.data.pipe === 'function') {
        return this._handleStreamResponse(
          response,
          res,
          account,
          apiKeyData,
          req.body?.model,
          handleClientDisconnect,
          req
        )
      }

      // 处理非流式响应
      return this._handleNormalResponse(response, res, account, apiKeyData, req.body?.model, req)
    } catch (error) {
      // 清理 AbortController
      if (abortController && !abortController.signal.aborted) {
        abortController.abort()
      }

      // 安全地记录错误，避免循环引用
      const errorInfo = {
        message: error.message,
        code: error.code,
        status: error.response?.status,
        statusText: error.response?.statusText
      }
      logger.error('OpenAI-Responses relay error:', errorInfo)

      // 检查是否是网络错误
      if (error.code === 'ECONNREFUSED' || error.code === 'ETIMEDOUT') {
        if (account?.id) {
          const oaiAutoProtectionDisabled =
            account?.disableAutoProtection === true || account?.disableAutoProtection === 'true'
          if (!oaiAutoProtectionDisabled) {
            await upstreamErrorHelper
              .markTempUnavailable(account.id, 'openai-responses', 503)
              .catch(() => {})
          }
        }
      }

      // 如果已经发送了响应头，直接结束
      if (res.headersSent) {
        return res.end()
      }

      // 检查是否是axios错误并包含响应
      if (error.response) {
        // 处理axios错误响应
        const status = error.response.status || 500
        let errorData = {
          error: {
            message: error.response.statusText || 'Request failed',
            type: 'api_error',
            code: error.code || 'unknown'
          }
        }

        // 如果响应包含数据，尝试使用它
        if (error.response.data) {
          // 检查是否是流
          if (typeof error.response.data === 'object' && !error.response.data.pipe) {
            errorData = error.response.data
          } else if (typeof error.response.data === 'string') {
            try {
              errorData = JSON.parse(error.response.data)
            } catch (e) {
              errorData.error.message = error.response.data
            }
          }
        }

        if (status === 401) {
          logger.warn(
            `🚫 OpenAI Responses账号认证失败（401错误）for account ${account?.id} (catch handler)`
          )

          try {
            // 仅临时暂停，不永久禁用
            const oaiAutoProtectionDisabled =
              account?.disableAutoProtection === true || account?.disableAutoProtection === 'true'
            if (!oaiAutoProtectionDisabled) {
              await upstreamErrorHelper
                .markTempUnavailable(account.id, 'openai-responses', 401)
                .catch(() => {})
            }
            if (sessionHash) {
              await unifiedOpenAIScheduler._deleteSessionMapping(sessionHash).catch(() => {})
            }
          } catch (markError) {
            logger.error(
              '❌ Failed to mark OpenAI-Responses account temporarily unavailable in catch handler:',
              markError
            )
          }

          let unauthorizedResponse = errorData
          if (
            !unauthorizedResponse ||
            typeof unauthorizedResponse !== 'object' ||
            unauthorizedResponse.pipe ||
            Buffer.isBuffer(unauthorizedResponse)
          ) {
            const fallbackMessage =
              typeof errorData === 'string' && errorData.trim() ? errorData.trim() : 'Unauthorized'
            unauthorizedResponse = {
              error: {
                message: fallbackMessage,
                type: 'unauthorized',
                code: 'unauthorized'
              }
            }
          }

          return res.status(401).json(unauthorizedResponse)
        }

        const isDailyQuotaExceeded = this._isDailyQuotaExceededError(status, errorData)
        const isUpstreamSchedulerRateLimit = this._isUpstreamSchedulerRateLimit(status, errorData)

        if (isDailyQuotaExceeded && account?.id) {
          const { resetAt } = this._computeNextDailyQuotaResetAt(account.quotaResetTime || '00:00')
          logger.warn(
            `💸 OpenAI Responses上游明确返回日额度耗尽，按配置重置时间暂停调度 for account ${account.id} (catch handler), resetAt=${resetAt}`
          )

          try {
            const oaiAutoProtectionDisabled =
              account?.disableAutoProtection === true || account?.disableAutoProtection === 'true'
            await upstreamErrorHelper
              .recordErrorHistory(account.id, 'openai-responses', status, 'quota_exceeded', {
                model: req.body?.model,
                path: req.originalUrl,
                errorBody: errorData,
                resetAt
              })
              .catch(() => {})
            if (!oaiAutoProtectionDisabled) {
              await openaiResponsesAccountService.updateAccount(account.id, {
                status: 'quota_exceeded',
                schedulable: 'false',
                quotaStoppedAt: new Date().toISOString(),
                rateLimitedAt: '',
                rateLimitStatus: '',
                rateLimitResetAt: '',
                errorMessage: `Payment Required: 已达到每日费用限制，重置时间 ${resetAt}`
              })
              await upstreamErrorHelper
                .clearTempUnavailable(account.id, 'openai-responses')
                .catch(() => {})
            }
            if (sessionHash) {
              await unifiedOpenAIScheduler._deleteSessionMapping(sessionHash).catch(() => {})
            }
          } catch (markError) {
            logger.warn(
              'Failed to mark OpenAI-Responses account daily quota exceeded after upstream quota error in catch handler:',
              markError
            )
          }

          const retryCount = Number(req._openaiResponses429RetryCount || 0)
          if (retryCount < 3) {
            try {
              req._openaiResponses429RetryCount = retryCount + 1
              const retried = await this._retryUnavailableRequest(
                req,
                res,
                account,
                apiKeyData,
                sessionHash,
                handleClientDisconnect,
                releaseConcurrency,
                {
                  reasonLabel: `${status} 配额型错误`,
                  isQuotaExhausted: true,
                  retryCount: req._openaiResponses429RetryCount
                }
              )
              if (retried) {
                return res
              }
            } catch (retryError) {
              logger.warn(
                `Failed to retry OpenAI-Responses request after quota-like ${status} in catch handler for ${account.id}: ${retryError.message}`
              )
            }
          }

          return res.status(402).json(this._buildDailyQuotaExceededPayload(errorData, resetAt))
        }

        if (isUpstreamSchedulerRateLimit && account?.id) {
          logger.warn(
            `🚫 OpenAI Responses上游返回模型当前不可路由，已按限流处理 for account ${account.id} (catch handler)`
          )

          try {
            const oaiAutoProtectionDisabled =
              account?.disableAutoProtection === true || account?.disableAutoProtection === 'true'
            const historyContext = {
              model: req.body?.model,
              path: req.originalUrl,
              errorBody: errorData,
              pauseStatus: 429
            }
            await upstreamErrorHelper
              .recordErrorHistory(
                account.id,
                'openai-responses',
                status,
                'unroutable_model',
                historyContext
              )
              .catch(() => {})
            if (!oaiAutoProtectionDisabled) {
              await unifiedOpenAIScheduler.markAccountRateLimited(
                account.id,
                'openai-responses',
                sessionHash
              )
              await upstreamErrorHelper
                .markTempUnavailable(account.id, 'openai-responses', 429, null, {
                  ...historyContext,
                  skipHistory: true
                })
                .catch(() => {})
            }
            if (sessionHash) {
              await unifiedOpenAIScheduler._deleteSessionMapping(sessionHash).catch(() => {})
            }
          } catch (markError) {
            logger.warn(
              'Failed to mark OpenAI-Responses account rate limited after upstream unroutable-model error in catch handler:',
              markError
            )
          }
        }

        if (status === 403 && account?.id) {
          logger.warn(
            `🚫 OpenAI Responses账号触发403临时暂停 for account ${account.id} (catch handler)`
          )

          try {
            const oaiAutoProtectionDisabled =
              account?.disableAutoProtection === true || account?.disableAutoProtection === 'true'
            if (!oaiAutoProtectionDisabled) {
              await upstreamErrorHelper
                .markTempUnavailable(account.id, 'openai-responses', 403)
                .catch(() => {})
            }
            if (sessionHash) {
              await unifiedOpenAIScheduler._deleteSessionMapping(sessionHash).catch(() => {})
            }
          } catch (markError) {
            logger.warn(
              'Failed to mark OpenAI-Responses account temporarily unavailable after 403 in catch handler:',
              markError
            )
          }
        }

        if (status >= 500 && account?.id && !isUpstreamSchedulerRateLimit) {
          try {
            const oaiAutoProtectionDisabled =
              account?.disableAutoProtection === true || account?.disableAutoProtection === 'true'
            if (!oaiAutoProtectionDisabled) {
              await upstreamErrorHelper
                .markTempUnavailable(account.id, 'openai-responses', status)
                .catch(() => {})
            }
            if (sessionHash) {
              await unifiedOpenAIScheduler._deleteSessionMapping(sessionHash).catch(() => {})
            }
          } catch (markError) {
            logger.warn(
              `Failed to mark OpenAI-Responses account temporarily unavailable after ${status} in catch handler:`,
              markError
            )
          }

          const retryCount = Number(req._openaiResponses429RetryCount || 0)
          if (retryCount < 3) {
            try {
              req._openaiResponses429RetryCount = retryCount + 1
              const retried = await this._retryUnavailableRequest(
                req,
                res,
                account,
                apiKeyData,
                sessionHash,
                handleClientDisconnect,
                releaseConcurrency,
                {
                  reasonLabel: `${status} 上游错误`,
                  retryCount: req._openaiResponses429RetryCount
                }
              )
              if (retried) {
                return res
              }
            } catch (retryError) {
              logger.warn(
                `Failed to retry OpenAI-Responses request after upstream ${status} in catch handler for ${account.id}: ${retryError.message}`
              )
            }
          }
        }

        return res.status(status).json(upstreamErrorHelper.sanitizeErrorForClient(errorData))
      }

      // 其他错误
      return res.status(500).json({
        error: {
          message: 'Internal server error',
          type: 'internal_error',
          details: error.message
        }
      })
    }
  }

  // 处理流式响应
  async _handleStreamResponse(
    response,
    res,
    account,
    apiKeyData,
    requestedModel,
    handleClientDisconnect,
    req
  ) {
    // 设置 SSE 响应头
    res.setHeader('Content-Type', 'text/event-stream')
    res.setHeader('Cache-Control', 'no-cache')
    res.setHeader('Connection', 'keep-alive')
    res.setHeader('X-Accel-Buffering', 'no')

    let usageData = null
    let actualModel = null
    let buffer = ''
    let rateLimitDetected = false
    let rateLimitResetsInSeconds = null
    let rateLimitErrorData = null
    let rateLimitIsQuotaExhausted = false
    let streamEnded = false

    // 解析 SSE 事件以捕获 usage 数据和 model
    const parseSSEForUsage = (data) => {
      const lines = data.split('\n')

      for (const line of lines) {
        if (line.startsWith('data:')) {
          try {
            const jsonStr = line.slice(5).trim()
            if (jsonStr === '[DONE]') {
              continue
            }

            const eventData = JSON.parse(jsonStr)

            // 检查是否是 response.completed 事件（OpenAI-Responses 格式）
            if (eventData.type === 'response.completed' && eventData.response) {
              // 从响应中获取真实的 model
              if (eventData.response.model) {
                actualModel = eventData.response.model
                logger.debug(`📊 Captured actual model from response.completed: ${actualModel}`)
              }

              // 获取 usage 数据 - OpenAI-Responses 格式在 response.usage 下
              if (eventData.response.usage) {
                usageData = eventData.response.usage
                logger.info('📊 Successfully captured usage data from OpenAI-Responses:', {
                  input_tokens: usageData.input_tokens,
                  output_tokens: usageData.output_tokens,
                  total_tokens: usageData.total_tokens
                })
              }
            }

            // 检查是否有限流错误
            if (eventData.error) {
              // 检查多种可能的限流错误类型
              if (
                eventData.error.type === 'rate_limit_error' ||
                eventData.error.type === 'usage_limit_reached' ||
                eventData.error.type === 'rate_limit_exceeded'
              ) {
                rateLimitDetected = true
                rateLimitErrorData = eventData
                rateLimitIsQuotaExhausted = this._isQuotaExhausted429Error(eventData)
                if (eventData.error.resets_in_seconds) {
                  rateLimitResetsInSeconds = eventData.error.resets_in_seconds
                  logger.warn(
                    `🚫 Rate limit detected in stream, resets in ${rateLimitResetsInSeconds} seconds (${Math.ceil(rateLimitResetsInSeconds / 60)} minutes)`
                  )
                }
              }
            }
          } catch (e) {
            // 忽略解析错误
          }
        }
      }
    }

    // 监听数据流
    response.data.on('data', (chunk) => {
      try {
        const chunkStr = chunk.toString()

        // 转发数据给客户端
        if (!res.destroyed && !streamEnded) {
          res.write(chunk)
        }

        // 同时解析数据以捕获 usage 信息
        buffer += chunkStr

        // 处理完整的 SSE 事件
        if (buffer.includes('\n\n')) {
          const events = buffer.split('\n\n')
          buffer = events.pop() || ''

          for (const event of events) {
            if (event.trim()) {
              parseSSEForUsage(event)
            }
          }
        }
      } catch (error) {
        logger.error('Error processing stream chunk:', error)
      }
    })

    response.data.on('end', async () => {
      streamEnded = true

      // 处理剩余的 buffer
      if (buffer.trim()) {
        parseSSEForUsage(buffer)
      }

      // 记录使用统计
      if (usageData) {
        try {
          // OpenAI-Responses 使用 input_tokens/output_tokens，标准 OpenAI 使用 prompt_tokens/completion_tokens
          const totalInputTokens = usageData.input_tokens || usageData.prompt_tokens || 0
          const outputTokens = usageData.output_tokens || usageData.completion_tokens || 0

          // 提取缓存相关的 tokens（如果存在）
          const cacheReadTokens = usageData.input_tokens_details?.cached_tokens || 0
          const cacheCreateTokens = extractCacheCreationTokens(usageData)
          // 计算实际输入token（总输入减去缓存部分）
          const actualInputTokens = Math.max(0, totalInputTokens - cacheReadTokens)

          const totalTokens =
            usageData.total_tokens || totalInputTokens + outputTokens + cacheCreateTokens
          const modelToRecord = actualModel || requestedModel || 'gpt-4'

          const serviceTier = req._serviceTier || null
          await apiKeyService.recordUsage(
            apiKeyData.id,
            actualInputTokens, // 传递实际输入（不含缓存）
            outputTokens,
            cacheCreateTokens,
            cacheReadTokens,
            modelToRecord,
            account.id,
            'openai-responses',
            serviceTier
          )

          logger.info(
            `📊 Recorded usage - Input: ${totalInputTokens}(actual:${actualInputTokens}+cached:${cacheReadTokens}), CacheCreate: ${cacheCreateTokens}, Output: ${outputTokens}, Total: ${totalTokens}, Model: ${modelToRecord}`
          )

          // 更新账户的 token 使用统计
          await openaiResponsesAccountService.updateAccountUsage(account.id, totalTokens)

          // 更新账户使用额度（如果设置了额度限制）
          if (parseFloat(account.dailyQuota) > 0) {
            // 使用CostCalculator正确计算费用（考虑缓存token的不同价格）
            const CostCalculator = require('../../utils/costCalculator')
            const costInfo = CostCalculator.calculateCost(
              {
                input_tokens: actualInputTokens, // 实际输入（不含缓存）
                output_tokens: outputTokens,
                cache_creation_input_tokens: cacheCreateTokens,
                cache_read_input_tokens: cacheReadTokens
              },
              modelToRecord,
              serviceTier
            )
            await openaiResponsesAccountService.updateUsageQuota(account.id, costInfo.costs.total)
          }
        } catch (error) {
          logger.error('Failed to record usage:', error)
        }
      }

      // 如果在流式响应中检测到限流
      if (rateLimitDetected) {
        const sessionId = req.headers['session_id'] || req.body?.session_id
        const sessionHash = sessionId
          ? crypto.createHash('sha256').update(sessionId).digest('hex')
          : null

        if (rateLimitIsQuotaExhausted) {
          const resolvedCooldown = this._resolve429ResetSeconds(rateLimitErrorData, null)
          const cooldownSeconds = rateLimitResetsInSeconds || resolvedCooldown.resetsInSeconds
          const historyContext = {
            model: req.body?.model,
            path: req.originalUrl,
            errorBody: rateLimitErrorData
          }

          await upstreamErrorHelper
            .recordErrorHistory(
              account.id,
              'openai-responses',
              429,
              'quota_exceeded',
              historyContext
            )
            .catch(() => {})

          await upstreamErrorHelper
            .markTempUnavailable(account.id, 'openai-responses', 429, cooldownSeconds, {
              ...historyContext,
              skipHistory: true
            })
            .catch(() => {})

          this._probeQuotaExhausted429Recovery(account, req.body?.model).catch((probeError) => {
            logger.warn(
              `Failed to probe OpenAI-Responses stream account availability after quota-like 429 for ${account.id}: ${probeError.message}`
            )
          })

          logger.warn(
            `🚫 Processing quota-like 429 for OpenAI-Responses account ${account.id} from stream with temp pause only`
          )
        } else {
          // 使用统一调度器处理普通限流（与非流式响应保持一致）
          await unifiedOpenAIScheduler.markAccountRateLimited(
            account.id,
            'openai-responses',
            sessionHash,
            rateLimitResetsInSeconds
          )

          logger.warn(
            `🚫 Processing rate limit for OpenAI-Responses account ${account.id} from stream`
          )
        }
      }

      // 清理监听器
      req.removeListener('close', handleClientDisconnect)
      res.removeListener('close', handleClientDisconnect)

      if (!res.destroyed) {
        res.end()
      }

      logger.info('Stream response completed', {
        accountId: account.id,
        hasUsage: !!usageData,
        actualModel: actualModel || 'unknown'
      })
    })

    response.data.on('error', (error) => {
      streamEnded = true
      logger.error('Stream error:', error)

      // 清理监听器
      req.removeListener('close', handleClientDisconnect)
      res.removeListener('close', handleClientDisconnect)

      if (!res.headersSent) {
        res.status(502).json({ error: { message: 'Upstream stream error' } })
      } else if (!res.destroyed) {
        res.end()
      }
    })

    // 处理客户端断开连接
    const cleanup = () => {
      streamEnded = true
      try {
        response.data?.unpipe?.(res)
        response.data?.destroy?.()
      } catch (_) {
        // 忽略清理错误
      }
    }

    req.on('close', cleanup)
    req.on('aborted', cleanup)
  }

  // 处理非流式响应
  async _handleNormalResponse(response, res, account, apiKeyData, requestedModel, req) {
    const responseData = response.data

    // 提取 usage 数据和实际 model
    // 支持两种格式：直接的 usage 或嵌套在 response 中的 usage
    const usageData = responseData?.usage || responseData?.response?.usage
    const actualModel =
      responseData?.model || responseData?.response?.model || requestedModel || 'gpt-4'

    // 记录使用统计
    if (usageData) {
      try {
        // OpenAI-Responses 使用 input_tokens/output_tokens，标准 OpenAI 使用 prompt_tokens/completion_tokens
        const totalInputTokens = usageData.input_tokens || usageData.prompt_tokens || 0
        const outputTokens = usageData.output_tokens || usageData.completion_tokens || 0

        // 提取缓存相关的 tokens（如果存在）
        const cacheReadTokens = usageData.input_tokens_details?.cached_tokens || 0
        const cacheCreateTokens = extractCacheCreationTokens(usageData)
        // 计算实际输入token（总输入减去缓存部分）
        const actualInputTokens = Math.max(0, totalInputTokens - cacheReadTokens)

        const totalTokens =
          usageData.total_tokens || totalInputTokens + outputTokens + cacheCreateTokens

        const serviceTier = req._serviceTier || null
        await apiKeyService.recordUsage(
          apiKeyData.id,
          actualInputTokens, // 传递实际输入（不含缓存）
          outputTokens,
          cacheCreateTokens,
          cacheReadTokens,
          actualModel,
          account.id,
          'openai-responses',
          serviceTier
        )

        logger.info(
          `📊 Recorded non-stream usage - Input: ${totalInputTokens}(actual:${actualInputTokens}+cached:${cacheReadTokens}), CacheCreate: ${cacheCreateTokens}, Output: ${outputTokens}, Total: ${totalTokens}, Model: ${actualModel}`
        )

        // 更新账户的 token 使用统计
        await openaiResponsesAccountService.updateAccountUsage(account.id, totalTokens)

        // 更新账户使用额度（如果设置了额度限制）
        if (parseFloat(account.dailyQuota) > 0) {
          // 使用CostCalculator正确计算费用（考虑缓存token的不同价格）
          const CostCalculator = require('../../utils/costCalculator')
          const costInfo = CostCalculator.calculateCost(
            {
              input_tokens: actualInputTokens, // 实际输入（不含缓存）
              output_tokens: outputTokens,
              cache_creation_input_tokens: cacheCreateTokens,
              cache_read_input_tokens: cacheReadTokens
            },
            actualModel,
            serviceTier
          )
          await openaiResponsesAccountService.updateUsageQuota(account.id, costInfo.costs.total)
        }
      } catch (error) {
        logger.error('Failed to record usage:', error)
      }
    }

    // 返回响应
    res.status(response.status).json(responseData)

    logger.info('Normal response completed', {
      accountId: account.id,
      status: response.status,
      hasUsage: !!usageData,
      model: actualModel
    })
  }

  _get429ErrorText(errorData) {
    const candidates = [
      errorData?.error?.message,
      errorData?.error?.code,
      errorData?.error?.type,
      errorData?.message,
      errorData?.code,
      errorData?.reason
    ]

    return candidates
      .filter((value) => typeof value === 'string' && value.trim())
      .join(' | ')
      .toLowerCase()
  }

  _isDailyQuotaExceededError(statusCode, errorData) {
    if (statusCode !== 402 && statusCode !== 403) {
      return false
    }

    const errorText = this._get429ErrorText(errorData)
    const explicitCode = String(errorData?.error?.code || '').toLowerCase()
    const hasDailyAndLimit = errorText.includes('daily') && errorText.includes('limit')

    return (
      /用户额度不足|剩余额度/.test(errorText) ||
      explicitCode === 'daily_cost_limit_exceeded' ||
      explicitCode === 'daily_limit_exceeded' ||
      hasDailyAndLimit
    )
  }

  _isUpstreamSchedulerRateLimit(statusCode, errorData) {
    if (statusCode !== 400 && statusCode !== 503) {
      return false
    }

    const errorText = this._get429ErrorText(errorData)
    return (
      errorText.includes('no available openai accounts support the requested model') ||
      errorText.includes('no available channel for model')
    )
  }

  _computeNextDailyQuotaResetAt(resetTime = '00:00') {
    const now = new Date()
    const tzNow = redis.getDateInTimezone(now)
    const offsetMs = tzNow.getTime() - now.getTime()

    const [h, m] = String(resetTime || '00:00')
      .split(':')
      .map((n) => parseInt(n, 10))

    const resetHour = Number.isFinite(h) ? h : 0
    const resetMinute = Number.isFinite(m) ? m : 0

    const year = tzNow.getUTCFullYear()
    const month = tzNow.getUTCMonth()
    const day = tzNow.getUTCDate()

    let resetAtMs = Date.UTC(year, month, day, resetHour, resetMinute, 0, 0) - offsetMs
    if (resetAtMs <= now.getTime()) {
      resetAtMs += 24 * 60 * 60 * 1000
    }

    const resetAt = new Date(resetAtMs)
    return {
      resetAt: resetAt.toISOString(),
      resetsInSeconds: Math.max(1, Math.ceil((resetAtMs - now.getTime()) / 1000))
    }
  }

  _buildDailyQuotaExceededPayload(errorData, resetAt) {
    const upstreamMessage =
      typeof errorData?.error?.message === 'string' && errorData.error.message.trim()
        ? errorData.error.message.trim()
        : '已达到每日费用限制'

    return {
      error: {
        type: 'insufficient_quota',
        message: '已达到每日费用限制',
        code: 'daily_cost_limit_exceeded',
        upstreamMessage
      },
      resetAt
    }
  }

  _isQuotaExhausted429Error(errorData) {
    const errorText = this._get429ErrorText(errorData)
    return /daily_limit_exceeded|usage_limit_exceeded|daily usage limit exceeded|the usage limit has been reached|当前订阅余额已用尽|余额已用尽|subscription.*余额|subscription balance|insufficient.*quota|额度不足|剩余额度/.test(
      errorText
    )
  }

  _buildProbeTargetUrl(account) {
    const baseUrl = account?.baseApi || ''
    const providerEndpoint = account?.providerEndpoint || 'responses'
    let endpointPath = '/responses'

    if (providerEndpoint === 'auto') {
      endpointPath = '/responses'
    }

    if (!baseUrl.endsWith('/v1')) {
      endpointPath = `/v1${endpointPath}`
    }

    return `${baseUrl}${endpointPath}`
  }

  _shouldResetAfterTestSuccess(account) {
    if (!account) {
      return false
    }

    return (
      account.status === 'unauthorized' ||
      account.status === 'rateLimited' ||
      account.status === 'temp_error' ||
      account.schedulable === 'false' ||
      Boolean(account.errorMessage) ||
      Boolean(account.quotaStoppedAt) ||
      Boolean(account.unauthorizedAt) ||
      Boolean(account.unauthorizedCount) ||
      Boolean(account.rateLimitedAt) ||
      Boolean(account.rateLimitStatus) ||
      Boolean(account.rateLimitResetAt)
    )
  }

  async _readProbeFailureMessage(response) {
    if (!response?.data?.on) {
      return `API Error: ${response?.status || 'unknown'}`
    }

    return await new Promise((resolve) => {
      const chunks = []
      let settled = false

      const finalize = (message) => {
        if (settled) {
          return
        }
        settled = true
        response.data.destroy?.()
        resolve(message)
      }

      response.data.on('data', (chunk) => {
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)))
        const currentSize = chunks.reduce((sum, item) => sum + item.length, 0)
        if (currentSize >= 16 * 1024) {
          finalize(this._formatProbeFailureMessage(response.status, Buffer.concat(chunks).toString()))
        }
      })

      response.data.on('end', () => {
        finalize(this._formatProbeFailureMessage(response.status, Buffer.concat(chunks).toString()))
      })

      response.data.on('error', (error) => {
        finalize(error.message || `API Error: ${response.status || 'unknown'}`)
      })
    })
  }

  _formatProbeFailureMessage(status, rawBody) {
    const fallback = `API Error: ${status || 'unknown'}`
    if (!rawBody || typeof rawBody !== 'string') {
      return fallback
    }

    const body = rawBody.trim()
    if (!body) {
      return fallback
    }

    try {
      return extractErrorMessage(JSON.parse(body), fallback)
    } catch {
      return body.length <= 300 ? body : body.slice(0, 300)
    }
  }

  async _awaitProbeStreamReady(stream) {
    if (!stream?.on) {
      return
    }

    return await new Promise((resolve, reject) => {
      let settled = false

      const finalize = (handler, error) => {
        if (settled) {
          return
        }
        settled = true
        stream.off?.('data', onData)
        stream.off?.('end', onEnd)
        stream.off?.('error', onError)
        if (handler === 'reject') {
          reject(error)
          return
        }
        resolve()
      }

      const onData = () => {
        stream.destroy?.()
        finalize('resolve')
      }
      const onEnd = () => finalize('resolve')
      const onError = (error) => finalize('reject', error)

      stream.once('data', onData)
      stream.once('end', onEnd)
      stream.once('error', onError)
    })
  }

  async testAccountConnectionSync(accountId, model = 'gpt-5.4') {
    const startTime = Date.now()
    let response = null

    try {
      const account = await openaiResponsesAccountService.getAccount(accountId)
      if (!account) {
        throw new Error('Account not found')
      }

      if (!account.apiKey) {
        throw new Error('API Key not found or decryption failed')
      }

      const apiUrl = this._buildProbeTargetUrl(account)
      const payload = createOpenAITestPayload(model, {
        prompt: 'ping',
        maxTokens: 16,
        stream: true
      })

      const requestConfig = {
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${account.apiKey}`
        },
        timeout: 15000,
        responseType: 'stream',
        validateStatus: () => true
      }

      if (account.proxy) {
        const proxyAgent = ProxyHelper.createProxyAgent(account.proxy)
        if (proxyAgent) {
          requestConfig.httpsAgent = proxyAgent
          requestConfig.httpAgent = proxyAgent
        }
      }

      logger.info(`🧪 Testing OpenAI-Responses account connection (sync): ${account.name} (${accountId})`)

      response = await axios.post(apiUrl, payload, requestConfig)
      if (response.status < 200 || response.status >= 400) {
        const errorMessage = await this._readProbeFailureMessage(response)
        return {
          success: false,
          error: errorMessage,
          statusCode: response.status,
          latencyMs: Date.now() - startTime,
          timestamp: new Date().toISOString()
        }
      }

      await this._awaitProbeStreamReady(response.data)

      if (this._shouldResetAfterTestSuccess(account)) {
        await openaiResponsesAccountService.resetAccountStatus(accountId, {
          sendWebhook: false,
          reason: 'Account recovered after scheduled connection test'
        })
        logger.warn(`✅ OpenAI-Responses账户 ${accountId} 定时测试成功，已自动重置异常状态`)
      }

      return {
        success: true,
        latencyMs: Date.now() - startTime,
        model,
        timestamp: new Date().toISOString()
      }
    } catch (error) {
      logger.error(`❌ Test OpenAI-Responses account connection failed:`, error.message)
      return {
        success: false,
        error: error.message,
        statusCode: error.response?.status,
        latencyMs: Date.now() - startTime,
        timestamp: new Date().toISOString()
      }
    } finally {
      response?.data?.destroy?.()
    }
  }

  async applyTestFailureProtection(account, status, errorData, options = {}) {
    if (!account?.id || !status) {
      return
    }

    const { model = null, path = null, headers = null } = options
    const oaiAutoProtectionDisabled =
      account?.disableAutoProtection === true || account?.disableAutoProtection === 'true'
    const historyContext = {
      model,
      path,
      errorBody: errorData
    }

    const isDailyQuotaExceeded = this._isDailyQuotaExceededError(status, errorData)
    if (isDailyQuotaExceeded) {
      const { resetAt } = this._computeNextDailyQuotaResetAt(account.quotaResetTime || '00:00')
      logger.warn(
        `💸 OpenAI Responses测试触发明确日额度耗尽，按配置重置时间暂停调度 for account ${account.id}, resetAt=${resetAt}`
      )

      await upstreamErrorHelper
        .recordErrorHistory(account.id, 'openai-responses', status, 'quota_exceeded', {
          ...historyContext,
          resetAt
        })
        .catch(() => {})

      if (!oaiAutoProtectionDisabled) {
        await openaiResponsesAccountService.updateAccount(account.id, {
          status: 'quota_exceeded',
          schedulable: 'false',
          quotaStoppedAt: new Date().toISOString(),
          rateLimitedAt: '',
          rateLimitStatus: '',
          rateLimitResetAt: '',
          errorMessage: `Payment Required: 已达到每日费用限制，重置时间 ${resetAt}`
        })
        await upstreamErrorHelper.clearTempUnavailable(account.id, 'openai-responses').catch(() => {})
      }
      return
    }

    const isUpstreamSchedulerRateLimit = this._isUpstreamSchedulerRateLimit(status, errorData)
    if (isUpstreamSchedulerRateLimit) {
      logger.warn(`🚫 OpenAI Responses测试触发模型不可路由，已按限流处理 for account ${account.id}`)

      await upstreamErrorHelper
        .recordErrorHistory(account.id, 'openai-responses', status, 'unroutable_model', {
          ...historyContext,
          pauseStatus: 429
        })
        .catch(() => {})

      if (!oaiAutoProtectionDisabled) {
        await unifiedOpenAIScheduler.markAccountRateLimited(account.id, 'openai-responses')
        await upstreamErrorHelper
          .markTempUnavailable(account.id, 'openai-responses', 429, null, {
            ...historyContext,
            pauseStatus: 429,
            skipHistory: true
          })
          .catch(() => {})
      }
      return
    }

    if (status === 429) {
      const responseLike = {
        status,
        data: errorData,
        headers: headers || {}
      }
      const {
        resetsInSeconds,
        errorData: normalizedErrorData,
        isQuotaExhausted
      } = await this._handle429Error(account, responseLike, false, null)

      const finalErrorData = normalizedErrorData || errorData
      const quotaHistoryContext = {
        model,
        path,
        errorBody: finalErrorData
      }

      if (isQuotaExhausted) {
        await upstreamErrorHelper
          .recordErrorHistory(account.id, 'openai-responses', 429, 'quota_exceeded', quotaHistoryContext)
          .catch(() => {})
      }

      if (!oaiAutoProtectionDisabled) {
        await upstreamErrorHelper
          .markTempUnavailable(
            account.id,
            'openai-responses',
            429,
            resetsInSeconds || upstreamErrorHelper.parseRetryAfter(headers),
            isQuotaExhausted
              ? { ...quotaHistoryContext, skipHistory: true }
              : quotaHistoryContext
          )
          .catch(() => {})

        if (isQuotaExhausted) {
          this._probeQuotaExhausted429Recovery(account, model).catch((probeError) => {
            logger.warn(
              `Failed to probe OpenAI-Responses account availability after test 429 for ${account.id}: ${probeError.message}`
            )
          })
        }
      }
      return
    }

    if (status === 401 && !oaiAutoProtectionDisabled) {
      logger.warn(`🚫 OpenAI Responses测试触发401临时暂停 for account ${account.id}`)
      await upstreamErrorHelper.markTempUnavailable(account.id, 'openai-responses', 401).catch(() => {})
      return
    }

    if (status === 403 && !oaiAutoProtectionDisabled) {
      logger.warn(`🚫 OpenAI Responses测试触发403临时暂停 for account ${account.id}`)
      await upstreamErrorHelper.markTempUnavailable(account.id, 'openai-responses', 403).catch(() => {})
      return
    }

    if (status >= 500 && !oaiAutoProtectionDisabled) {
      logger.warn(`🚫 OpenAI Responses测试触发${status}临时暂停 for account ${account.id}`)
      await upstreamErrorHelper.markTempUnavailable(account.id, 'openai-responses', status).catch(() => {})
    }
  }

  async _retryUnavailableRequest(
    req,
    res,
    currentAccount,
    apiKeyData,
    sessionHash,
    handleClientDisconnect,
    releaseConcurrency,
    options = {}
  ) {
    const { reasonLabel = '429', isQuotaExhausted = false, retryCount = 1 } = options
    const requestedModel = req.body?.model || null
    const result = await unifiedOpenAIScheduler.selectAccountForApiKey(
      apiKeyData,
      sessionHash,
      requestedModel,
      [currentAccount.id]
    )

    if (!result?.accountId || result.accountType !== 'openai-responses') {
      logger.info(
        `🧪 ${reasonLabel} 后未找到可立即重试的 OpenAI-Responses 账户，保留原始响应 for account ${currentAccount.id}`
      )
      return null
    }

    const retryAccount = await openaiResponsesAccountService.getAccount(result.accountId)
    if (!retryAccount?.apiKey) {
      logger.warn(
        `🧪 ${reasonLabel} 后选中的重试账户 ${result.accountId} 缺少可用 apiKey，跳过立即重试`
      )
      return null
    }

    logger.warn(
      `🔁 OpenAI-Responses账户 ${currentAccount.id} 命中${reasonLabel}，第 ${retryCount} 次立即重试到账户 ${retryAccount.id}`
    )

    req.removeListener('close', handleClientDisconnect)
    res.removeListener('close', handleClientDisconnect)
    await releaseConcurrency().catch(() => {})

    await this.handleRequest(req, res, retryAccount, apiKeyData)
    logger.info(
      `✅ OpenAI-Responses账户 ${currentAccount.id} 命中的${reasonLabel}已由重试账户 ${retryAccount.id} 接管响应`
    )
    return true
  }

  async _probeQuotaExhausted429Recovery(account, requestedModel) {
    if (!account?.id || !account?.apiKey || !account?.baseApi) {
      return false
    }

    if (!requestedModel || typeof requestedModel !== 'string') {
      logger.info(
        `🧪 OpenAI-Responses账户 ${account.id} 配额耗尽类429后缺少原始请求模型，跳过后台可用性探测`
      )
      return false
    }

    const apiUrl = this._buildProbeTargetUrl(account)
    const model = requestedModel
    const payload = createOpenAITestPayload(model, {
      prompt: 'ping',
      maxTokens: 16,
      stream: true
    })

    const requestConfig = {
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${account.apiKey}`
      },
      timeout: 15000,
      responseType: 'stream',
      validateStatus: () => true
    }

    if (account.proxy) {
      const proxyAgent = ProxyHelper.createProxyAgent(account.proxy)
      if (proxyAgent) {
        requestConfig.httpsAgent = proxyAgent
        requestConfig.httpAgent = proxyAgent
      }
    }

    let response = null
    try {
      response = await axios.post(apiUrl, payload, requestConfig)
      response.data?.destroy?.()

      if (response.status >= 200 && response.status < 400) {
        await openaiResponsesAccountService.updateAccount(account.id, {
          status: account.apiKey ? 'active' : 'created',
          schedulable: 'true',
          errorMessage: '',
          rateLimitedAt: '',
          rateLimitStatus: '',
          rateLimitResetAt: ''
        })
        await upstreamErrorHelper
          .clearTempUnavailable(account.id, 'openai-responses')
          .catch(() => {})

        logger.warn(
          `✅ OpenAI-Responses账户 ${account.id} 在配额耗尽类429后探测可用，已自动恢复调度状态`
        )
        return true
      }

      logger.info(
        `🧪 OpenAI-Responses账户 ${account.id} 配额耗尽类429后探测仍不可用: status=${response.status}`
      )
      return false
    } catch (error) {
      const message = extractErrorMessage(error.response?.data, error.message)
      logger.info(
        `🧪 OpenAI-Responses账户 ${account.id} 配额耗尽类429后探测失败，保留暂停状态: ${message}`
      )
      return false
    } finally {
      response?.data?.destroy?.()
    }
  }

  _resolve429ResetSeconds(errorData, headers) {
    let resetsInSeconds = null
    let cooldownReason = 'default'

    if (errorData?.error?.resets_in_seconds) {
      resetsInSeconds = Number(errorData.error.resets_in_seconds)
      cooldownReason = 'response_error_resets_in_seconds'
    } else if (errorData?.error?.resets_in) {
      resetsInSeconds = Number(errorData.error.resets_in)
      cooldownReason = 'response_error_resets_in'
    } else if (errorData?.resets_in_seconds) {
      resetsInSeconds = Number(errorData.resets_in_seconds)
      cooldownReason = 'response_resets_in_seconds'
    }

    if (!Number.isFinite(resetsInSeconds) || resetsInSeconds <= 0) {
      resetsInSeconds = upstreamErrorHelper.parseRetryAfter(headers)
      if (resetsInSeconds) {
        cooldownReason = 'retry_after_header'
      }
    }

    if (!Number.isFinite(resetsInSeconds) || resetsInSeconds <= 0) {
      const errorText = this._get429ErrorText(errorData)
      const transientLimitPattern = /too many pending requests|达到请求数限制|最多请求/

      // 配额耗尽类 429 已有立即重试和后台探测，这里只做短暂冷却，避免长期双重阻塞。
      if (this._isQuotaExhausted429Error(errorData)) {
        resetsInSeconds = 5 * 60
        cooldownReason = 'quota_exhausted_probe_fallback'
      } else if (transientLimitPattern.test(errorText)) {
        resetsInSeconds = 5 * 60
        cooldownReason = 'transient_rate_limit_fallback'
      }
    }

    return {
      resetsInSeconds:
        Number.isFinite(resetsInSeconds) && resetsInSeconds > 0 ? Math.ceil(resetsInSeconds) : null,
      cooldownReason
    }
  }

  // 处理 429 限流错误
  async _handle429Error(account, response, isStream = false, sessionHash = null) {
    let resetsInSeconds = null
    let errorData = null
    let cooldownReason = 'default'

    try {
      // 对于429错误，响应可能是JSON或SSE格式
      if (isStream && response.data && typeof response.data.pipe === 'function') {
        // 流式响应需要先收集数据
        const chunks = []
        await new Promise((resolve, reject) => {
          response.data.on('data', (chunk) => chunks.push(chunk))
          response.data.on('end', resolve)
          response.data.on('error', reject)
          // 设置超时防止无限等待
          setTimeout(resolve, 5000)
        })

        const fullResponse = Buffer.concat(chunks).toString()

        // 尝试解析SSE格式的错误响应
        if (fullResponse.includes('data: ')) {
          const lines = fullResponse.split('\n')
          for (const line of lines) {
            if (line.startsWith('data: ')) {
              try {
                const jsonStr = line.slice(6).trim()
                if (jsonStr && jsonStr !== '[DONE]') {
                  errorData = JSON.parse(jsonStr)
                  break
                }
              } catch (e) {
                // 继续尝试下一行
              }
            }
          }
        }

        // 如果SSE解析失败，尝试直接解析为JSON
        if (!errorData) {
          try {
            errorData = JSON.parse(fullResponse)
          } catch (e) {
            logger.error('Failed to parse 429 error response:', e)
            logger.debug('Raw response:', fullResponse)
          }
        }
      } else if (response.data && typeof response.data !== 'object') {
        // 如果response.data是字符串，尝试解析为JSON
        try {
          errorData = JSON.parse(response.data)
        } catch (e) {
          logger.error('Failed to parse 429 error response as JSON:', e)
          errorData = { error: { message: response.data } }
        }
      } else if (response.data && typeof response.data === 'object' && !response.data.pipe) {
        // 非流式响应，且是对象，直接使用
        errorData = response.data
      }

      const resolvedCooldown = this._resolve429ResetSeconds(errorData, response.headers)
      resetsInSeconds = resolvedCooldown.resetsInSeconds
      cooldownReason = resolvedCooldown.cooldownReason

      if (resetsInSeconds) {
        logger.info(
          `🕐 Rate limit will reset in ${resetsInSeconds} seconds (${Math.ceil(resetsInSeconds / 60)} minutes / ${Math.ceil(resetsInSeconds / 3600)} hours), reason=${cooldownReason}`
        )
      } else {
        logger.warn('⚠️ Could not extract reset time from 429 response, using default 60 minutes')
      }
    } catch (e) {
      logger.error('⚠️ Failed to parse rate limit error:', e)
    }

    const isQuotaExhausted = this._isQuotaExhausted429Error(errorData)

    if (!isQuotaExhausted) {
      // 使用统一调度器标记普通 429 限流状态（与普通OpenAI账号保持一致）
      await unifiedOpenAIScheduler.markAccountRateLimited(
        account.id,
        'openai-responses',
        sessionHash,
        resetsInSeconds
      )
    } else {
      logger.warn(
        `⏸️ OpenAI-Responses account ${account.id} hit quota-like 429, skip rateLimited status and use temp pause only`
      )
    }

    logger.warn('OpenAI-Responses account rate limited', {
      accountId: account.id,
      accountName: account.name,
      isQuotaExhausted,
      resetsInSeconds: resetsInSeconds || 'unknown',
      cooldownReason,
      resetInMinutes: resetsInSeconds ? Math.ceil(resetsInSeconds / 60) : 60,
      resetInHours: resetsInSeconds ? Math.ceil(resetsInSeconds / 3600) : 1
    })

    // 返回处理后的数据，避免循环引用
    return {
      resetsInSeconds,
      errorData,
      isQuotaExhausted
    }
  }

  // 过滤请求头 - 已迁移到 headerFilter 工具类
  // 此方法保留用于向后兼容，实际使用 filterForOpenAI()
  _filterRequestHeaders(headers) {
    return filterForOpenAI(headers)
  }

  // 估算费用（简化版本，实际应该根据不同的定价模型）
  _estimateCost(model, inputTokens, outputTokens) {
    // 这是一个简化的费用估算，实际应该根据不同的 API 提供商和模型定价
    const rates = {
      'gpt-4': { input: 0.03, output: 0.06 }, // per 1K tokens
      'gpt-4-turbo': { input: 0.01, output: 0.03 },
      'gpt-3.5-turbo': { input: 0.0005, output: 0.0015 },
      'claude-3-opus': { input: 0.015, output: 0.075 },
      'claude-3-sonnet': { input: 0.003, output: 0.015 },
      'claude-3-haiku': { input: 0.00025, output: 0.00125 }
    }

    // 查找匹配的模型定价
    let rate = rates['gpt-3.5-turbo'] // 默认使用 GPT-3.5 的价格
    for (const [modelKey, modelRate] of Object.entries(rates)) {
      if (model.toLowerCase().includes(modelKey.toLowerCase())) {
        rate = modelRate
        break
      }
    }

    const inputCost = (inputTokens / 1000) * rate.input
    const outputCost = (outputTokens / 1000) * rate.output
    return inputCost + outputCost
  }
}

module.exports = new OpenAIResponsesRelayService()
