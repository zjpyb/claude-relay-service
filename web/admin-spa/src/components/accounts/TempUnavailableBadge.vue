<template>
  <span
    class="inline-flex items-center rounded-full bg-amber-100 px-3 py-1 text-xs font-semibold text-amber-800 dark:bg-amber-900/30 dark:text-amber-300"
  >
    <i class="fas fa-clock mr-1" />
    临时暂停
    <span v-if="remainingSeconds > 0">
      ({{ formatTempUnavailableTime(remainingSeconds) }}
      <span v-if="cooldownSeconds > 0">/{{ formatTempUnavailableTime(cooldownSeconds) }}</span
      >)
    </span>
    <el-tooltip :content="tooltipContent" effect="dark" placement="top">
      <i class="fas fa-info-circle ml-1 cursor-help" />
    </el-tooltip>
  </span>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import {
  formatTempUnavailableTime,
  getTempUnavailableCooldownSeconds,
  getTempUnavailableRemainingSeconds,
  getTempUnavailableTooltipContent
} from '@/utils/temp_unavailable'

const props = defineProps({
  tempUnavailable: {
    type: Object,
    required: true
  }
})

const remainingSeconds = ref(0)
let countdownTimer = null

const cooldownSeconds = computed(() => getTempUnavailableCooldownSeconds(props.tempUnavailable))

const tooltipContent = computed(() => {
  const nowTs = Date.now()
  return getTempUnavailableTooltipContent(
    {
      ...props.tempUnavailable,
      remainingSeconds: remainingSeconds.value
    },
    nowTs
  )
})

const updateRemainingSeconds = () => {
  remainingSeconds.value = getTempUnavailableRemainingSeconds(props.tempUnavailable, Date.now())

  if (remainingSeconds.value <= 0 && countdownTimer) {
    clearInterval(countdownTimer)
    countdownTimer = null
  }
}

const restartCountdown = () => {
  if (countdownTimer) {
    clearInterval(countdownTimer)
    countdownTimer = null
  }

  updateRemainingSeconds()

  if (remainingSeconds.value > 0) {
    countdownTimer = setInterval(updateRemainingSeconds, 1000)
  }
}

watch(
  () => props.tempUnavailable,
  () => {
    restartCountdown()
  },
  { deep: true }
)

onMounted(() => {
  restartCountdown()
})

onUnmounted(() => {
  if (countdownTimer) {
    clearInterval(countdownTimer)
    countdownTimer = null
  }
})
</script>
