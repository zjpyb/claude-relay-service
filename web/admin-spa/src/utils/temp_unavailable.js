export const toPositiveInteger = (value) => {
  const parsed = Number(value)
  return Number.isFinite(parsed) && parsed > 0 ? Math.floor(parsed) : 0
}

export const formatTempUnavailableTime = (seconds) => {
  if (!seconds || seconds <= 0) return ''
  seconds = Math.floor(seconds)
  const mins = Math.floor(seconds / 60)
  const secs = seconds % 60
  if (mins > 0) return `${mins}m${secs > 0 ? secs + 's' : ''}`
  return `${secs}s`
}

export const getTempUnavailableCooldownSeconds = (tempUnavailable) => {
  if (!tempUnavailable) return 0
  return toPositiveInteger(tempUnavailable.cooldownSeconds)
}

export const getTempUnavailableRecoveryAt = (tempUnavailable) => {
  if (!tempUnavailable) return ''

  if (tempUnavailable.expiresAt) {
    const expiresAt = new Date(tempUnavailable.expiresAt)
    if (!Number.isNaN(expiresAt.getTime())) {
      return tempUnavailable.expiresAt
    }
  }

  if (tempUnavailable.markedAt) {
    const markedAt = new Date(tempUnavailable.markedAt)
    const cooldownSeconds = getTempUnavailableCooldownSeconds(tempUnavailable)
    if (!Number.isNaN(markedAt.getTime()) && cooldownSeconds > 0) {
      return new Date(markedAt.getTime() + cooldownSeconds * 1000).toISOString()
    }
  }

  return ''
}

export const getTempUnavailableRemainingSeconds = (tempUnavailable, nowTs = Date.now()) => {
  if (!tempUnavailable) return 0
  const serverRemainingSeconds = toPositiveInteger(
    tempUnavailable.remainingSeconds || tempUnavailable.ttl
  )

  const recoveryAt = getTempUnavailableRecoveryAt(tempUnavailable)
  if (!recoveryAt) {
    return serverRemainingSeconds
  }

  const recoveryAtTimestamp = new Date(recoveryAt).getTime()
  if (Number.isNaN(recoveryAtTimestamp)) {
    return serverRemainingSeconds
  }

  const liveRemainingSeconds = Math.max(0, Math.ceil((recoveryAtTimestamp - nowTs) / 1000))
  if (serverRemainingSeconds <= 0) {
    return liveRemainingSeconds
  }
  return Math.min(serverRemainingSeconds, liveRemainingSeconds)
}

export const formatTempUnavailableRecoveryAt = (tempUnavailable) => {
  const recoveryAt = getTempUnavailableRecoveryAt(tempUnavailable)
  if (!recoveryAt) return ''

  const recoveryDate = new Date(recoveryAt)
  if (Number.isNaN(recoveryDate.getTime())) return ''

  const month = `${recoveryDate.getMonth() + 1}`.padStart(2, '0')
  const day = `${recoveryDate.getDate()}`.padStart(2, '0')
  const hours = `${recoveryDate.getHours()}`.padStart(2, '0')
  const minutes = `${recoveryDate.getMinutes()}`.padStart(2, '0')
  const seconds = `${recoveryDate.getSeconds()}`.padStart(2, '0')
  return `${month}-${day} ${hours}:${minutes}:${seconds}`
}

export const getTempUnavailableTooltipContent = (tempUnavailable, nowTs = Date.now()) => {
  if (!tempUnavailable) return ''

  const details = []
  const statusCodeText = tempUnavailable.statusCode ? `HTTP ${tempUnavailable.statusCode}` : ''
  const errorTypeText = tempUnavailable.errorType || 'upstream_error'
  details.push(`${errorTypeText}${statusCodeText ? ` (${statusCodeText})` : ''}`)

  const cooldownSeconds = getTempUnavailableCooldownSeconds(tempUnavailable)
  if (cooldownSeconds > 0) {
    details.push(`内部冷却 ${formatTempUnavailableTime(cooldownSeconds)}`)
  }

  const remainingSeconds = getTempUnavailableRemainingSeconds(tempUnavailable, nowTs)
  if (remainingSeconds > 0) {
    details.push(`剩余 ${formatTempUnavailableTime(remainingSeconds)}`)
  }

  const recoveryAtText = formatTempUnavailableRecoveryAt(tempUnavailable)
  if (recoveryAtText) {
    details.push(`预计恢复 ${recoveryAtText}`)
  }

  if (tempUnavailable.reason) {
    details.push(tempUnavailable.reason)
  }

  return details.join('，')
}
