const axios = require('axios')
const openaiAccountService = require('../account/openaiAccountService')
const ProxyHelper = require('../../utils/proxyHelper')
const logger = require('../../utils/logger')
const { createOpenAITestPayload, extractErrorMessage } = require('../../utils/testPayloadHelper')

const DEFAULT_OPENAI_TEST_USER_AGENT =
  'codex-tui/0.118.0 (Mac OS 12.6.9; x86_64) Apple_Terminal (codex-tui; 0.118.0)'
const CODEX_TEST_ENDPOINT = 'https://chatgpt.com/backend-api/codex/responses'

class OpenAIAccountTestService {
  async testAccountConnectionSync(accountId, model = 'gpt-5.4') {
    const startTime = Date.now()

    try {
      const account = await openaiAccountService.getAccount(accountId)
      if (!account) {
        throw new Error('Account not found')
      }

      if (!account.accessToken) {
        throw new Error('Access token not found')
      }

      if (openaiAccountService.isTokenExpired(account)) {
        if (!account.refreshToken) {
          throw new Error('Access token expired and no refresh token available')
        }
        await openaiAccountService.refreshAccountToken(accountId)
      }

      const refreshedAccount = await openaiAccountService.getAccount(accountId)
      if (!refreshedAccount?.accessToken) {
        throw new Error('Access token not found after refresh')
      }

      const accessToken = openaiAccountService.decrypt(refreshedAccount.accessToken)
      if (!accessToken) {
        throw new Error('Failed to decrypt OpenAI access token')
      }

      const payload = createOpenAITestPayload(model, {
        prompt: 'ping',
        maxTokens: 16,
        stream: false
      })
      payload.store = false

      const headers = {
        authorization: `Bearer ${accessToken}`,
        'chatgpt-account-id':
          refreshedAccount.accountId || refreshedAccount.chatgptUserId || refreshedAccount.id,
        host: 'chatgpt.com',
        accept: 'application/json',
        'content-type': 'application/json',
        'user-agent': refreshedAccount.userAgent || DEFAULT_OPENAI_TEST_USER_AGENT
      }

      const requestConfig = {
        headers,
        timeout: 30000,
        validateStatus: () => true
      }

      if (refreshedAccount.proxy) {
        const proxyAgent = ProxyHelper.createProxyAgent(refreshedAccount.proxy)
        if (proxyAgent) {
          requestConfig.httpsAgent = proxyAgent
          requestConfig.httpAgent = proxyAgent
          requestConfig.proxy = false
        }
      }

      logger.info(`🧪 Testing OpenAI account connection (sync): ${refreshedAccount.name} (${accountId})`)

      const response = await axios.post(CODEX_TEST_ENDPOINT, payload, requestConfig)
      const latencyMs = Date.now() - startTime

      if (response.status < 200 || response.status >= 400) {
        const errorMessage = extractErrorMessage(
          response.data,
          `Request failed with status code ${response.status}`
        )
        return {
          success: false,
          error: errorMessage,
          statusCode: response.status,
          latencyMs,
          model,
          timestamp: new Date().toISOString()
        }
      }

      if (this._shouldResetAfterTestSuccess(refreshedAccount)) {
        await openaiAccountService.resetAccountStatus(accountId)
        logger.warn(`✅ OpenAI账户 ${accountId} 定时测试成功，已自动重置异常状态`)
      }

      return {
        success: true,
        latencyMs,
        model,
        responseText: this._extractResponseText(response.data),
        timestamp: new Date().toISOString()
      }
    } catch (error) {
      logger.error(`❌ Test OpenAI account connection failed:`, error.message)
      return {
        success: false,
        error: extractErrorMessage(error.response?.data, error.message),
        statusCode: error.response?.status,
        latencyMs: Date.now() - startTime,
        model,
        timestamp: new Date().toISOString()
      }
    }
  }

  _shouldResetAfterTestSuccess(account) {
    if (!account) {
      return false
    }

    return (
      account.status !== 'active' ||
      account.schedulable === 'false' ||
      account.rateLimitStatus === 'limited' ||
      Boolean(account.rateLimitedAt) ||
      Boolean(account.rateLimitResetAt) ||
      Boolean(account.errorMessage)
    )
  }

  _extractResponseText(data) {
    if (!data) {
      return ''
    }

    if (typeof data.output_text === 'string' && data.output_text.trim()) {
      return data.output_text.trim()
    }

    if (Array.isArray(data.output)) {
      const texts = []
      for (const item of data.output) {
        const contents = Array.isArray(item?.content) ? item.content : []
        for (const content of contents) {
          if (typeof content?.text === 'string' && content.text.trim()) {
            texts.push(content.text.trim())
          }
        }
      }
      if (texts.length > 0) {
        return texts.join('\n').slice(0, 500)
      }
    }

    return ''
  }
}

module.exports = new OpenAIAccountTestService()
