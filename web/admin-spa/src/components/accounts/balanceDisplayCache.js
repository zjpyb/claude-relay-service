const responseCache = new Map()
const pendingRequestCache = new Map()

export const getBalanceCacheKey = ({ accountId, platform, queryMode = 'local' }) =>
  [accountId || '', platform || '', queryMode || 'local'].join('::')

export const getCachedBalance = (cacheKey) => responseCache.get(cacheKey) || null

export const setCachedBalance = (cacheKey, balanceData) => {
  if (!cacheKey) {
    return
  }

  if (balanceData) {
    responseCache.set(cacheKey, balanceData)
    return
  }

  responseCache.delete(cacheKey)
}

export const getPendingBalanceRequest = (cacheKey) => pendingRequestCache.get(cacheKey) || null

export const setPendingBalanceRequest = (cacheKey, requestPromise) => {
  if (!cacheKey) {
    return
  }

  if (requestPromise) {
    pendingRequestCache.set(cacheKey, requestPromise)
    return
  }

  pendingRequestCache.delete(cacheKey)
}

export const clearPendingBalanceRequest = (cacheKey) => {
  if (!cacheKey) {
    return
  }

  pendingRequestCache.delete(cacheKey)
}
