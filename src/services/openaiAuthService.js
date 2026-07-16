const crypto = require('crypto')
const logger = require('../utils/logger')
const unifiedOpenAIScheduler = require('./scheduler/unifiedOpenAIScheduler')
const openaiAccountService = require('./account/openaiAccountService')
const openaiResponsesAccountService = require('./account/openaiResponsesAccountService')

function parseProxy(proxy) {
  if (!proxy) {
    return null
  }

  try {
    return typeof proxy === 'string' ? JSON.parse(proxy) : proxy
  } catch (error) {
    logger.warn('Failed to parse proxy configuration:', error)
    return null
  }
}

async function getOpenAIAuthToken(
  apiKeyData,
  sessionId = null,
  requestedModel = null,
  excludedAccountIds = []
) {
  const sessionHash = sessionId ? crypto.createHash('sha256').update(sessionId).digest('hex') : null
  const result = excludedAccountIds.length
    ? await unifiedOpenAIScheduler.selectAccountForApiKey(
        apiKeyData,
        sessionHash,
        requestedModel,
        excludedAccountIds
      )
    : await unifiedOpenAIScheduler.selectAccountForApiKey(apiKeyData, sessionHash, requestedModel)

  if (!result?.accountId) {
    const error = new Error('No available OpenAI account found')
    error.statusCode = 402
    throw error
  }

  if (result.accountType === 'openai-responses') {
    const account = await openaiResponsesAccountService.getAccount(result.accountId)
    if (!account?.apiKey) {
      const error = new Error(`OpenAI-Responses account ${result.accountId} has no valid apiKey`)
      error.statusCode = 403
      throw error
    }

    logger.info(`Selected OpenAI-Responses account: ${account.name} (${result.accountId})`)
    return {
      accessToken: null,
      accountId: result.accountId,
      accountName: account.name,
      accountType: result.accountType,
      proxy: parseProxy(account.proxy),
      account
    }
  }

  let account = await openaiAccountService.getAccount(result.accountId)
  if (!account?.accessToken) {
    const error = new Error(`OpenAI account ${result.accountId} has no valid accessToken`)
    error.statusCode = 403
    throw error
  }

  if (openaiAccountService.isTokenExpired(account)) {
    if (!account.refreshToken) {
      const error = new Error(
        `Token expired and no refresh token available for account ${account.name}`
      )
      error.statusCode = 403
      throw error
    }

    logger.info(`🔄 Token expired, auto-refreshing for account ${account.name} (fallback)`)
    try {
      await openaiAccountService.refreshAccountToken(result.accountId)
      account = await openaiAccountService.getAccount(result.accountId)
      logger.info('✅ Token refreshed successfully in route handler')
    } catch (refreshError) {
      logger.error(`Failed to refresh token for ${account.name}:`, refreshError)
      const error = new Error(`Token expired and refresh failed: ${refreshError.message}`)
      error.statusCode = 403
      throw error
    }
  }

  const accessToken = openaiAccountService.decrypt(account.accessToken)
  if (!accessToken) {
    const error = new Error('Failed to decrypt OpenAI accessToken')
    error.statusCode = 403
    throw error
  }

  logger.info(`Selected OpenAI account: ${account.name} (${result.accountId})`)
  return {
    accessToken,
    accountId: result.accountId,
    accountName: account.name,
    accountType: result.accountType,
    proxy: parseProxy(account.proxy),
    account
  }
}

module.exports = {
  getOpenAIAuthToken
}
