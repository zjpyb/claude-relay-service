<template>
  <div class="card p-4 transition-shadow hover:shadow-lg">
    <!-- 卡片头部 -->
    <div class="mb-3 flex items-start justify-between">
      <div class="flex items-center gap-3">
        <input
          v-if="showCheckboxes"
          :checked="selected"
          class="mt-1 h-4 w-4 rounded border-gray-300 text-blue-600 focus:ring-blue-500"
          type="checkbox"
          @change="handleSelectionChange"
        />
        <div
          :class="[
            'flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-lg',
            account.platform === 'claude'
              ? 'bg-gradient-to-br from-purple-500 to-purple-600'
              : account.platform === 'bedrock'
                ? 'bg-gradient-to-br from-orange-500 to-red-600'
                : account.platform === 'azure_openai'
                  ? 'bg-gradient-to-br from-blue-500 to-cyan-600'
                  : account.platform === 'openai'
                    ? 'bg-gradient-to-br from-gray-600 to-gray-700'
                    : account.platform === 'ccr'
                      ? 'bg-gradient-to-br from-teal-500 to-emerald-600'
                      : account.platform === 'droid'
                        ? 'bg-gradient-to-br from-cyan-500 to-sky-600'
                        : 'bg-gradient-to-br from-blue-500 to-blue-600'
          ]"
        >
          <i
            :class="[
              'text-sm text-white',
              account.platform === 'claude'
                ? 'fas fa-brain'
                : account.platform === 'bedrock'
                  ? 'fab fa-aws'
                  : account.platform === 'azure_openai'
                    ? 'fab fa-microsoft'
                    : account.platform === 'openai'
                      ? 'fas fa-openai'
                      : account.platform === 'ccr'
                        ? 'fas fa-code-branch'
                        : account.platform === 'droid'
                          ? 'fas fa-robot'
                          : 'fas fa-robot'
            ]"
          />
        </div>
        <div>
          <h4
            class="cursor-pointer text-sm font-semibold text-gray-900 hover:text-blue-600 dark:hover:text-blue-400"
            title="点击复制"
            @click.stop="copyText(account.name || account.email)"
          >
            {{ account.name || account.email }}
          </h4>
          <div class="mt-0.5 flex items-center gap-2">
            <span class="text-xs text-gray-500 dark:text-gray-400">{{ account.platform }}</span>
            <span class="text-xs text-gray-400">|</span>
            <span class="text-xs text-gray-500 dark:text-gray-400">{{ account.type }}</span>
          </div>
        </div>
      </div>
      <span
        :class="[
          'inline-flex items-center rounded-full px-2 py-1 text-xs font-semibold',
          getAccountStatusClass(account)
        ]"
      >
        <div :class="['mr-1.5 h-1.5 w-1.5 rounded-full', getAccountStatusDotClass(account)]" />
        {{ getAccountStatusText(account) }}
      </span>
    </div>

    <!-- 使用统计 -->
    <div class="mb-3 grid grid-cols-2 gap-3">
      <div>
        <p class="text-xs text-gray-500 dark:text-gray-400">今日使用</p>
        <div class="space-y-1">
          <div class="flex items-center gap-1.5">
            <div class="h-1.5 w-1.5 rounded-full bg-blue-500" />
            <p class="text-sm font-semibold text-gray-900 dark:text-gray-100">
              {{ account.usage?.daily?.requests || 0 }} 次
            </p>
          </div>
          <div class="flex items-center gap-1.5">
            <div class="h-1.5 w-1.5 rounded-full bg-purple-500" />
            <p class="text-xs text-gray-600 dark:text-gray-400">
              {{ formatNumber(account.usage?.daily?.allTokens || 0) }}
            </p>
          </div>
          <div class="flex items-center gap-1.5">
            <div class="h-1.5 w-1.5 rounded-full bg-green-500" />
            <p class="text-xs text-gray-600 dark:text-gray-400">
              ${{ calculateDailyCost(account) }}
            </p>
          </div>
        </div>
      </div>
      <div>
        <p class="text-xs text-gray-500 dark:text-gray-400">会话窗口</p>
        <div v-if="account.usage && account.usage.sessionWindow" class="space-y-1">
          <div class="flex items-center gap-1.5">
            <div class="h-1.5 w-1.5 rounded-full bg-purple-500" />
            <p class="text-sm font-semibold text-gray-900 dark:text-gray-100">
              {{ formatNumber(account.usage.sessionWindow.totalTokens) }}
            </p>
          </div>
          <div class="flex items-center gap-1.5">
            <div class="h-1.5 w-1.5 rounded-full bg-green-500" />
            <p class="text-xs text-gray-600 dark:text-gray-400">
              ${{ formatCost(account.usage.sessionWindow.totalCost) }}
            </p>
          </div>
        </div>
        <div v-else class="text-sm font-semibold text-gray-400">-</div>
      </div>
    </div>

    <!-- 余额/配额 -->
    <div class="mb-3">
      <p class="mb-1 text-xs text-gray-500 dark:text-gray-400">余额/配额</p>
      <BalanceDisplay
        :account-id="account.id"
        :initial-balance="account.balanceInfo"
        :platform="account.platform"
        :query-mode="
          account.platform === 'gemini' && account.oauthProvider === 'antigravity'
            ? 'auto'
            : 'local'
        "
        @error="handleBalanceErrorEvent"
        @refreshed="handleBalanceRefreshedEvent"
      />
      <div class="mt-1 text-xs">
        <button
          v-if="!(account.platform === 'gemini' && account.oauthProvider === 'antigravity')"
          class="text-blue-500 hover:underline dark:text-blue-300"
          @click="openBalanceScriptModal(account)"
        >
          配置余额脚本
        </button>
      </div>
    </div>

    <!-- 状态信息 -->
    <div class="mb-3 space-y-2">
      <!-- 会话窗口 -->
      <div v-if="account.platform === 'claude'" class="space-y-2">
        <!-- OAuth 账户：显示三窗口 OAuth usage -->
        <div v-if="isClaudeOAuth(account) && account.claudeUsage" class="space-y-2">
          <!-- 5小时窗口 -->
          <div class="rounded-lg bg-gray-50 p-2 dark:bg-gray-700/70">
            <div class="flex items-center gap-2">
              <span
                class="inline-flex min-w-[32px] justify-center rounded-full bg-indigo-100 px-2 py-0.5 text-[11px] font-medium text-indigo-600 dark:bg-indigo-500/20 dark:text-indigo-300"
              >
                5h
              </span>
              <div class="flex-1">
                <div class="flex items-center gap-2">
                  <div class="h-2 flex-1 rounded-full bg-gray-200 dark:bg-gray-600">
                    <div
                      :class="[
                        'h-2 rounded-full transition-all duration-300',
                        getClaudeUsageBarClass(account.claudeUsage.fiveHour)
                      ]"
                      :style="{
                        width: getClaudeUsageWidth(account.claudeUsage.fiveHour)
                      }"
                    />
                  </div>
                  <span
                    class="w-12 text-right text-xs font-semibold text-gray-800 dark:text-gray-100"
                  >
                    {{ formatClaudeUsagePercent(account.claudeUsage.fiveHour) }}
                  </span>
                </div>
              </div>
            </div>
            <div class="mt-1 text-[11px] text-gray-500 dark:text-gray-400">
              重置剩余 {{ formatClaudeRemaining(account.claudeUsage.fiveHour) }}
            </div>
          </div>
          <!-- 7天窗口 -->
          <div class="rounded-lg bg-gray-50 p-2 dark:bg-gray-700/70">
            <div class="flex items-center gap-2">
              <span
                class="inline-flex min-w-[32px] justify-center rounded-full bg-emerald-100 px-2 py-0.5 text-[11px] font-medium text-emerald-600 dark:bg-emerald-500/20 dark:text-emerald-300"
              >
                7d
              </span>
              <div class="flex-1">
                <div class="flex items-center gap-2">
                  <div class="h-2 flex-1 rounded-full bg-gray-200 dark:bg-gray-600">
                    <div
                      :class="[
                        'h-2 rounded-full transition-all duration-300',
                        getClaudeUsageBarClass(account.claudeUsage.sevenDay)
                      ]"
                      :style="{
                        width: getClaudeUsageWidth(account.claudeUsage.sevenDay)
                      }"
                    />
                  </div>
                  <span
                    class="w-12 text-right text-xs font-semibold text-gray-800 dark:text-gray-100"
                  >
                    {{ formatClaudeUsagePercent(account.claudeUsage.sevenDay) }}
                  </span>
                </div>
              </div>
            </div>
            <div class="mt-1 text-[11px] text-gray-500 dark:text-gray-400">
              重置剩余 {{ formatClaudeRemaining(account.claudeUsage.sevenDay) }}
            </div>
          </div>
          <!-- 7天Opus窗口 -->
          <div class="rounded-lg bg-gray-50 p-2 dark:bg-gray-700/70">
            <div class="flex items-center gap-2">
              <span
                class="inline-flex min-w-[32px] justify-center rounded-full bg-purple-100 px-2 py-0.5 text-[11px] font-medium text-purple-600 dark:bg-purple-500/20 dark:text-purple-300"
              >
                Opus
              </span>
              <div class="flex-1">
                <div class="flex items-center gap-2">
                  <div class="h-2 flex-1 rounded-full bg-gray-200 dark:bg-gray-600">
                    <div
                      :class="[
                        'h-2 rounded-full transition-all duration-300',
                        getClaudeUsageBarClass(account.claudeUsage.sevenDayOpus)
                      ]"
                      :style="{
                        width: getClaudeUsageWidth(account.claudeUsage.sevenDayOpus)
                      }"
                    />
                  </div>
                  <span
                    class="w-12 text-right text-xs font-semibold text-gray-800 dark:text-gray-100"
                  >
                    {{ formatClaudeUsagePercent(account.claudeUsage.sevenDayOpus) }}
                  </span>
                </div>
              </div>
            </div>
            <div class="mt-1 text-[11px] text-gray-500 dark:text-gray-400">
              重置剩余 {{ formatClaudeRemaining(account.claudeUsage.sevenDayOpus) }}
            </div>
          </div>
        </div>
        <!-- Setup Token 账户：显示原有的会话窗口时间进度 -->
        <div
          v-else-if="
            !isClaudeOAuth(account) &&
            account.sessionWindow &&
            account.sessionWindow.hasActiveWindow
          "
          class="space-y-1.5 rounded-lg bg-gray-50 p-2 dark:bg-gray-700"
        >
          <div class="flex items-center justify-between text-xs">
            <div class="flex items-center gap-1">
              <span class="font-medium text-gray-600 dark:text-gray-300">会话窗口</span>
              <el-tooltip
                content="会话窗口进度不代表使用量，仅表示距离下一个5小时窗口的剩余时间"
                placement="top"
              >
                <i
                  class="fas fa-question-circle cursor-help text-xs text-gray-400 hover:text-gray-600"
                />
              </el-tooltip>
            </div>
            <span class="font-medium text-gray-700 dark:text-gray-200">
              {{ account.sessionWindow.progress }}%
            </span>
          </div>
          <div class="h-2 w-full overflow-hidden rounded-full bg-gray-200 dark:bg-gray-600">
            <div
              :class="[
                'h-full transition-all duration-300',
                getSessionProgressBarClass(account.sessionWindow.sessionWindowStatus, account)
              ]"
              :style="{ width: account.sessionWindow.progress + '%' }"
            />
          </div>
          <div class="flex items-center justify-between text-xs">
            <span class="text-gray-500 dark:text-gray-400">
              {{
                formatSessionWindow(
                  account.sessionWindow.windowStart,
                  account.sessionWindow.windowEnd
                )
              }}
            </span>
            <span
              v-if="account.sessionWindow.remainingTime > 0"
              class="font-medium text-indigo-600"
            >
              剩余 {{ formatRemainingTime(account.sessionWindow.remainingTime) }}
            </span>
            <span v-else class="text-gray-500"> 已结束 </span>
          </div>
        </div>
        <div v-else class="text-xs text-gray-400">暂无统计</div>
      </div>
      <div v-else-if="account.platform === 'openai'" class="space-y-2">
        <div v-if="account.codexUsage" class="space-y-2">
          <div class="rounded-lg bg-gray-50 p-2 dark:bg-gray-700">
            <div class="flex items-center gap-2">
              <span
                class="inline-flex min-w-[32px] justify-center rounded-full bg-indigo-100 px-2 py-0.5 text-[11px] font-medium text-indigo-600 dark:bg-indigo-500/20 dark:text-indigo-300"
              >
                {{ getCodexWindowLabel('primary') }}
              </span>
              <div class="flex-1">
                <div class="flex items-center gap-2">
                  <div class="h-2 flex-1 rounded-full bg-gray-200 dark:bg-gray-600">
                    <div
                      :class="[
                        'h-2 rounded-full transition-all duration-300',
                        getCodexUsageBarClass(account.codexUsage.primary)
                      ]"
                      :style="{
                        width: getCodexUsageWidth(account.codexUsage.primary)
                      }"
                    />
                  </div>
                  <span
                    class="w-12 text-right text-xs font-semibold text-gray-800 dark:text-gray-100"
                  >
                    {{ formatCodexUsagePercent(account.codexUsage.primary) }}
                  </span>
                </div>
              </div>
            </div>
            <div class="mt-1 text-[11px] text-gray-500 dark:text-gray-400">
              重置剩余 {{ formatCodexRemaining(account.codexUsage.primary) }}
            </div>
          </div>
          <div class="rounded-lg bg-gray-50 p-2 dark:bg-gray-700">
            <div class="flex items-center gap-2">
              <span
                class="inline-flex min-w-[32px] justify-center rounded-full bg-blue-100 px-2 py-0.5 text-[11px] font-medium text-blue-600 dark:bg-blue-500/20 dark:text-blue-300"
              >
                {{ getCodexWindowLabel('secondary') }}
              </span>
              <div class="flex-1">
                <div class="flex items-center gap-2">
                  <div class="h-2 flex-1 rounded-full bg-gray-200 dark:bg-gray-600">
                    <div
                      :class="[
                        'h-2 rounded-full transition-all duration-300',
                        getCodexUsageBarClass(account.codexUsage.secondary)
                      ]"
                      :style="{
                        width: getCodexUsageWidth(account.codexUsage.secondary)
                      }"
                    />
                  </div>
                  <span
                    class="w-12 text-right text-xs font-semibold text-gray-800 dark:text-gray-100"
                  >
                    {{ formatCodexUsagePercent(account.codexUsage.secondary) }}
                  </span>
                </div>
              </div>
            </div>
            <div class="mt-1 text-[11px] text-gray-500 dark:text-gray-400">
              重置剩余 {{ formatCodexRemaining(account.codexUsage.secondary) }}
            </div>
          </div>
        </div>
        <div v-if="!account.codexUsage" class="text-xs text-gray-400">暂无统计</div>
      </div>

      <!-- 最后使用时间 -->
      <div class="flex items-center justify-between text-xs">
        <span class="text-gray-500 dark:text-gray-400">最后使用</span>
        <span class="text-gray-700 dark:text-gray-200">
          {{ account.lastUsedAt ? formatRelativeTime(account.lastUsedAt) : '从未使用' }}
        </span>
      </div>

      <!-- 代理配置 -->
      <div
        v-if="account.proxyConfig && account.proxyConfig.type !== 'none'"
        class="flex items-center justify-between text-xs"
      >
        <span class="text-gray-500 dark:text-gray-400">代理</span>
        <span class="text-gray-700 dark:text-gray-200">
          {{ account.proxyConfig.type.toUpperCase() }}
        </span>
      </div>

      <!-- 调度优先级 -->
      <div class="flex items-center justify-between text-xs">
        <span class="text-gray-500 dark:text-gray-400">优先级</span>
        <span class="font-medium text-gray-700 dark:text-gray-200">
          {{ account.priority || 50 }}
        </span>
      </div>
    </div>

    <div
      v-if="isAccountRoutingBlocked(account)"
      class="mb-3 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-700 dark:border-red-800/70 dark:bg-red-900/30 dark:text-red-300"
    >
      <div class="font-semibold">不可路由原因</div>
      <div class="mt-1 break-all">{{ getRoutingBlockReasonSummary(account) }}</div>
    </div>

    <!-- 操作按钮 -->
    <div class="mt-3 flex gap-2 border-t border-gray-100 pt-3">
      <button
        v-if="showResetButton(account)"
        class="flex flex-1 items-center justify-center gap-1 rounded-lg bg-amber-50 px-3 py-2 text-xs text-amber-700 transition-colors hover:bg-amber-100 disabled:cursor-not-allowed disabled:opacity-60 dark:bg-amber-900/40 dark:text-amber-300 dark:hover:bg-amber-800/50"
        :disabled="account.isResetting"
        @click="resetAccountStatus(account)"
      >
        <i :class="['fas fa-redo', account.isResetting ? 'animate-spin' : '']" />
        重置
      </button>
      <button
        class="flex flex-1 items-center justify-center gap-1 rounded-lg px-3 py-2 text-xs transition-colors"
        :class="
          account.schedulable
            ? 'bg-gray-50 text-gray-600 hover:bg-gray-100'
            : 'bg-green-50 text-green-600 hover:bg-green-100'
        "
        :disabled="account.isTogglingSchedulable"
        @click="toggleSchedulable(account)"
      >
        <i :class="['fas', account.schedulable ? 'fa-pause' : 'fa-play']" />
        {{ account.schedulable ? '暂停' : '启用' }}
      </button>

      <button
        v-if="canViewUsage(account)"
        class="flex flex-1 items-center justify-center gap-1 rounded-lg bg-indigo-50 px-3 py-2 text-xs text-indigo-600 transition-colors hover:bg-indigo-100"
        @click="openAccountUsageModal(account)"
      >
        <i class="fas fa-chart-line" />
        详情
      </button>
      <button
        class="flex flex-1 items-center justify-center gap-1 rounded-lg bg-red-50 px-3 py-2 text-xs text-red-600 transition-colors hover:bg-red-100 dark:bg-red-900/40 dark:text-red-300 dark:hover:bg-red-800/50"
        @click="openErrorHistory(account)"
      >
        <i class="fas fa-exclamation-triangle" />
        错误
      </button>
      <button
        v-if="canTestAccount(account)"
        class="flex flex-1 items-center justify-center gap-1 rounded-lg bg-cyan-50 px-3 py-2 text-xs text-cyan-600 transition-colors hover:bg-cyan-100 dark:bg-cyan-900/40 dark:text-cyan-300 dark:hover:bg-cyan-800/50"
        @click="openAccountTestModal(account)"
      >
        <i class="fas fa-vial" />
        测试
      </button>

      <button
        v-if="canScheduleTestAccount(account)"
        class="flex flex-1 items-center justify-center gap-1 rounded-lg bg-amber-50 px-3 py-2 text-xs text-amber-600 transition-colors hover:bg-amber-100 dark:bg-amber-900/40 dark:text-amber-300 dark:hover:bg-amber-800/50"
        @click="openScheduledTestModal(account)"
      >
        <i class="fas fa-clock" />
        定时
      </button>

      <button
        class="flex-1 rounded-lg bg-gray-50 px-3 py-2 text-xs text-gray-600 transition-colors hover:bg-gray-100"
        @click="editAccount(account)"
      >
        <i class="fas fa-edit mr-1" />
        编辑
      </button>

      <button
        class="rounded-lg bg-red-50 px-3 py-2 text-xs text-red-600 transition-colors hover:bg-red-100"
        @click="deleteAccount(account)"
      >
        <i class="fas fa-trash" />
      </button>
    </div>
  </div>
</template>

<script setup>
import { toRefs, useAttrs } from 'vue'

import BalanceDisplay from '@/components/accounts/BalanceDisplay.vue'

defineOptions({ inheritAttrs: false })

const props = defineProps({
  account: {
    type: Object,
    required: true
  },
  selected: {
    type: Boolean,
    default: false
  },
  showCheckboxes: {
    type: Boolean,
    default: false
  }
})

const emit = defineEmits(['toggle-select'])
const attrs = useAttrs()
const { account, selected, showCheckboxes } = toRefs(props)

const {
  copyText,
  formatNumber,
  formatCost,
  formatRelativeTime,
  calculateDailyCost,
  getClaudeUsageBarClass,
  getClaudeUsageWidth,
  formatClaudeUsagePercent,
  formatClaudeRemaining,
  getCodexWindowLabel,
  getCodexUsageBarClass,
  getCodexUsageWidth,
  formatCodexUsagePercent,
  formatCodexRemaining,
  formatSessionWindow,
  getSessionProgressBarClass,
  formatRemainingTime,
  canViewUsage,
  canTestAccount,
  canScheduleTestAccount,
  getAccountStatusClass,
  getAccountStatusDotClass,
  getAccountStatusText,
  getRoutingBlockReasonSummary,
  isAccountRoutingBlocked,
  isClaudeOAuth,
  showResetButton,
  handleBalanceError,
  handleBalanceRefreshed,
  openBalanceScriptModal,
  resetAccountStatus,
  toggleSchedulable,
  openAccountUsageModal,
  openErrorHistory,
  openAccountTestModal,
  openScheduledTestModal,
  editAccount,
  deleteAccount
} = attrs

const handleSelectionChange = (event) => {
  emit('toggle-select', account.value.id, event.target.checked)
}

const handleBalanceErrorEvent = (error) => {
  handleBalanceError(account.value.id, error)
}

const handleBalanceRefreshedEvent = (data) => {
  handleBalanceRefreshed(account.value.id, data)
}
</script>
