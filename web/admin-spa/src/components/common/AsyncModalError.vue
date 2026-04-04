<template>
  <div class="fixed inset-0 z-[1200] flex items-center justify-center bg-black/45 px-4">
    <div
      class="w-full max-w-sm rounded-2xl border border-red-200 bg-white/95 px-6 py-5 text-center shadow-2xl dark:border-red-900/60 dark:bg-gray-800/95"
    >
      <div
        class="mx-auto mb-3 flex h-12 w-12 items-center justify-center rounded-full bg-red-100 text-red-500 dark:bg-red-900/30 dark:text-red-300"
      >
        <i class="fas fa-exclamation-triangle text-lg" />
      </div>
      <p class="text-sm font-medium text-gray-800 dark:text-gray-100">弹窗加载失败</p>
      <p class="mt-1 text-xs text-gray-500 dark:text-gray-400">
        {{ errorMessage || '请检查网络后重试' }}
      </p>
      <div class="mt-4 flex gap-3">
        <button
          class="flex-1 rounded-lg bg-gray-100 px-4 py-2 text-sm font-medium text-gray-700 transition-colors hover:bg-gray-200 dark:bg-gray-700 dark:text-gray-200 dark:hover:bg-gray-600"
          @click="$emit('close')"
        >
          关闭
        </button>
        <button
          class="flex-1 rounded-lg bg-blue-500 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-blue-600"
          @click="$emit('retry')"
        >
          重试
        </button>
      </div>
    </div>
  </div>
</template>

<script setup>
defineProps({
  errorMessage: {
    type: String,
    default: ''
  }
})

defineEmits(['close', 'retry'])
</script>
