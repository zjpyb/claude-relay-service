<template>
  <tr class="table-row">
    <td v-if="showCheckboxes" class="checkbox-column sticky left-0 z-10 px-3 py-3">
      <div class="flex items-center">
        <input
          :checked="selected"
          class="h-4 w-4 rounded border-gray-300 text-blue-600 focus:ring-blue-500"
          type="checkbox"
          @change="handleSelectionChange"
        />
      </div>
    </td>
    <td
      class="name-column sticky z-10 px-3 py-4"
      :class="showCheckboxes ? 'left-[50px]' : 'left-0'"
    >
      <div class="flex items-center">
        <div
          class="mr-2 flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-lg bg-gradient-to-br from-green-500 to-green-600"
        >
          <i class="fas fa-user-circle text-xs text-white" />
        </div>
        <div class="min-w-0">
          <div class="flex items-center gap-2">
            <div
              class="cursor-pointer truncate text-sm font-semibold text-gray-900 hover:text-blue-600 dark:text-gray-100 dark:hover:text-blue-400"
              title="点击复制"
              @click.stop="copyText(account.name)"
            >
              {{ account.name }}
            </div>
            <span
              v-if="account.accountType === 'dedicated'"
              class="inline-flex items-center rounded-full bg-purple-100 px-2 py-0.5 text-xs font-medium text-purple-800"
            >
              <i class="fas fa-lock mr-1" />专属
            </span>
            <span
              v-else-if="account.accountType === 'group'"
              class="inline-flex items-center rounded-full bg-blue-100 px-2 py-0.5 text-xs font-medium text-blue-800"
            >
              <i class="fas fa-layer-group mr-1" />分组调度
            </span>
            <span
              v-else
              class="inline-flex items-center rounded-full bg-green-100 px-2 py-0.5 text-xs font-medium text-green-800"
            >
              <i class="fas fa-share-alt mr-1" />共享
            </span>
          </div>
          <!-- 显示所有分组 - 换行显示 -->
          <div
            v-if="account.groupInfos && account.groupInfos.length > 0"
            class="my-2 flex flex-wrap items-center gap-2"
          >
            <span
              v-for="group in account.groupInfos"
              :key="group.id"
              class="inline-flex items-center rounded-full bg-gray-100 px-2 py-0.5 text-xs font-medium text-gray-600 dark:bg-gray-700 dark:text-gray-400"
              :title="`所属分组: ${group.name}`"
            >
              <i class="fas fa-folder mr-1" />{{ group.name }}
            </span>
          </div>
          <div class="truncate text-xs text-gray-500 dark:text-gray-400" :title="account.id">
            {{ account.id }}
          </div>
        </div>
      </div>
    </td>
    <td class="px-3 py-4">
      <div class="flex items-center gap-1">
        <!-- 平台图标和名称 -->
        <div
          v-if="account.platform === 'gemini'"
          class="flex items-center gap-1.5 rounded-lg border border-yellow-200 bg-gradient-to-r from-yellow-100 to-amber-100 px-2.5 py-1"
        >
          <i class="fas fa-robot text-xs text-yellow-700" />
          <span class="text-xs font-semibold text-yellow-800">Gemini</span>
          <span class="mx-1 h-4 w-px bg-yellow-300" />
          <span class="text-xs font-medium text-yellow-700">
            {{ getGeminiAuthType() }}
          </span>
        </div>
        <div
          v-else-if="account.platform === 'claude-console'"
          class="flex items-center gap-1.5 rounded-lg border border-purple-200 bg-gradient-to-r from-purple-100 to-pink-100 px-2.5 py-1"
        >
          <i class="fas fa-terminal text-xs text-purple-700" />
          <span class="text-xs font-semibold text-purple-800">Console</span>
          <span class="mx-1 h-4 w-px bg-purple-300" />
          <span class="text-xs font-medium text-purple-700">API Key</span>
        </div>
        <div
          v-else-if="account.platform === 'bedrock'"
          class="flex items-center gap-1.5 rounded-lg border border-orange-200 bg-gradient-to-r from-orange-100 to-red-100 px-2.5 py-1"
        >
          <i class="fab fa-aws text-xs text-orange-700" />
          <span class="text-xs font-semibold text-orange-800">Bedrock</span>
          <span class="mx-1 h-4 w-px bg-orange-300" />
          <span class="text-xs font-medium text-orange-700">AWS</span>
        </div>
        <div
          v-else-if="account.platform === 'openai'"
          class="flex items-center gap-1.5 rounded-lg border border-gray-700 bg-gray-100 bg-gradient-to-r from-gray-100 to-gray-100 px-2.5 py-1"
        >
          <div class="fa-openai" />
          <span class="text-xs font-semibold text-gray-950">OpenAi</span>
          <span class="mx-1 h-4 w-px bg-gray-400" />
          <span class="text-xs font-medium text-gray-950">{{ getOpenAIAuthType() }}</span>
        </div>
        <div
          v-else-if="account.platform === 'azure_openai'"
          class="flex items-center gap-1.5 rounded-lg border border-blue-200 bg-gradient-to-r from-blue-100 to-cyan-100 px-2.5 py-1 dark:border-blue-700 dark:from-blue-900/20 dark:to-cyan-900/20"
        >
          <i class="fab fa-microsoft text-xs text-blue-700 dark:text-blue-400" />
          <span class="text-xs font-semibold text-blue-800 dark:text-blue-300">Azure OpenAI</span>
          <span class="mx-1 h-4 w-px bg-blue-300 dark:bg-blue-600" />
          <span class="text-xs font-medium text-blue-700 dark:text-blue-400">API Key</span>
        </div>
        <div
          v-else-if="account.platform === 'openai-responses'"
          class="flex items-center gap-1.5 rounded-lg border border-teal-200 bg-gradient-to-r from-teal-100 to-green-100 px-2.5 py-1 dark:border-teal-700 dark:from-teal-900/20 dark:to-green-900/20"
        >
          <i class="fas fa-server text-xs text-teal-700 dark:text-teal-400" />
          <span class="text-xs font-semibold text-teal-800 dark:text-teal-300">OpenAI-Api</span>
          <span class="mx-1 h-4 w-px bg-teal-300 dark:bg-teal-600" />
          <span class="text-xs font-medium text-teal-700 dark:text-teal-400">API Key</span>
        </div>
        <div
          v-else-if="account.platform === 'claude' || account.platform === 'claude-oauth'"
          class="flex items-center gap-1.5 rounded-lg border border-indigo-200 bg-gradient-to-r from-indigo-100 to-blue-100 px-2.5 py-1"
        >
          <i class="fas fa-brain text-xs text-indigo-700" />
          <span class="text-xs font-semibold text-indigo-800">{{
            getClaudeAccountType(account)
          }}</span>
          <span class="mx-1 h-4 w-px bg-indigo-300" />
          <span class="text-xs font-medium text-indigo-700">
            {{ getClaudeAuthType(account) }}
          </span>
        </div>
        <div
          v-else-if="account.platform === 'ccr'"
          class="flex items-center gap-1.5 rounded-lg border border-teal-200 bg-gradient-to-r from-teal-100 to-emerald-100 px-2.5 py-1 dark:border-teal-700 dark:from-teal-900/20 dark:to-emerald-900/20"
        >
          <i class="fas fa-code-branch text-xs text-teal-700 dark:text-teal-400" />
          <span class="text-xs font-semibold text-teal-800 dark:text-teal-300">CCR</span>
          <span class="mx-1 h-4 w-px bg-teal-300 dark:bg-teal-600" />
          <span class="text-xs font-medium text-teal-700 dark:text-teal-300">Relay</span>
        </div>
        <div
          v-else-if="account.platform === 'droid'"
          class="flex items-center gap-1.5 rounded-lg border border-cyan-200 bg-gradient-to-r from-cyan-100 to-sky-100 px-2.5 py-1 dark:border-cyan-700 dark:from-cyan-900/20 dark:to-sky-900/20"
        >
          <i class="fas fa-robot text-xs text-cyan-700 dark:text-cyan-400" />
          <span class="text-xs font-semibold text-cyan-800 dark:text-cyan-300">Droid</span>
          <span class="mx-1 h-4 w-px bg-cyan-300 dark:bg-cyan-600" />
          <span class="text-xs font-medium text-cyan-700 dark:text-cyan-300">
            {{ getDroidAuthType(account) }}
          </span>
          <span v-if="isDroidApiKeyMode(account)" :class="getDroidApiKeyBadgeClasses(account)">
            <i class="fas fa-key text-[9px]" />
            <span>x{{ getDroidApiKeyCount(account) }}</span>
          </span>
        </div>
        <div
          v-else-if="account.platform === 'gemini-api'"
          class="flex items-center gap-1.5 rounded-lg border border-amber-200 bg-gradient-to-r from-amber-100 to-yellow-100 px-2.5 py-1 dark:border-amber-700 dark:from-amber-900/20 dark:to-yellow-900/20"
        >
          <i class="fas fa-robot text-xs text-amber-700 dark:text-amber-400" />
          <span class="text-xs font-semibold text-amber-800 dark:text-amber-300">Gemini-API</span>
          <span class="mx-1 h-4 w-px bg-amber-300 dark:bg-amber-600" />
          <span class="text-xs font-medium text-amber-700 dark:text-amber-400">API Key</span>
        </div>
        <div
          v-else
          class="flex items-center gap-1.5 rounded-lg border border-gray-200 bg-gradient-to-r from-gray-100 to-gray-200 px-2.5 py-1"
        >
          <i class="fas fa-question text-xs text-gray-700" />
          <span class="text-xs font-semibold text-gray-800">未知</span>
        </div>
      </div>
    </td>
    <td class="w-[100px] min-w-[100px] max-w-[100px] whitespace-nowrap px-3 py-4">
      <div class="flex flex-col gap-1">
        <span
          :class="[
            'inline-flex items-center rounded-full px-3 py-1 text-xs font-semibold',
            account.status === 'blocked'
              ? 'bg-orange-100 text-orange-800'
              : account.status === 'unauthorized'
                ? 'bg-red-100 text-red-800'
                : account.status === 'temp_error'
                  ? 'bg-orange-100 text-orange-800'
                  : account.isActive
                    ? 'bg-green-100 text-green-800'
                    : 'bg-red-100 text-red-800'
          ]"
        >
          <div
            :class="[
              'mr-2 h-2 w-2 rounded-full',
              account.status === 'blocked'
                ? 'bg-orange-500'
                : account.status === 'unauthorized'
                  ? 'bg-red-500'
                  : account.status === 'temp_error'
                    ? 'bg-orange-500'
                    : account.isActive
                      ? 'bg-green-500'
                      : 'bg-red-500'
            ]"
          />
          {{
            account.status === 'blocked'
              ? '已封锁'
              : account.status === 'unauthorized'
                ? '异常'
                : account.status === 'temp_error'
                  ? '临时异常'
                  : account.isActive
                    ? '正常'
                    : '异常'
          }}
        </span>
        <span
          v-if="
            account.status === 'rateLimited' ||
            (account.rateLimitStatus && account.rateLimitStatus.isRateLimited) ||
            account.rateLimitStatus === 'limited'
          "
          class="inline-flex items-center rounded-full bg-yellow-100 px-3 py-1 text-xs font-semibold text-yellow-800"
        >
          <i class="fas fa-exclamation-triangle mr-1" />
          限流中
          <span
            v-if="
              account.rateLimitStatus &&
              typeof account.rateLimitStatus === 'object' &&
              account.rateLimitStatus.minutesRemaining > 0
            "
            >({{ formatRateLimitTime(account.rateLimitStatus.minutesRemaining) }})</span
          >
        </span>
        <TempUnavailableBadge
          v-if="account.tempUnavailable"
          :temp-unavailable="account.tempUnavailable"
        />
        <span
          v-if="account.schedulable === false"
          class="inline-flex items-center rounded-full bg-gray-100 px-3 py-1 text-xs font-semibold text-gray-700"
        >
          <i class="fas fa-pause-circle mr-1" />
          不可调度
          <el-tooltip
            v-if="getSchedulableReason(account)"
            :content="getSchedulableReason(account)"
            effect="dark"
            placement="top"
          >
            <i class="fas fa-question-circle ml-1 cursor-help text-gray-500" />
          </el-tooltip>
        </span>
        <span
          v-if="account.opusRateLimitStatus && account.opusRateLimitStatus.isRateLimited"
          class="inline-flex items-center rounded-full bg-purple-100 px-3 py-1 text-xs font-semibold text-purple-800"
        >
          <i class="fas fa-hourglass-half mr-1" />
          Opus限流
          <span
            v-if="
              Number.isFinite(account.opusRateLimitStatus.minutesRemaining) &&
              account.opusRateLimitStatus.minutesRemaining > 0
            "
          >
            ({{ formatRateLimitTime(account.opusRateLimitStatus.minutesRemaining) }})
          </span>
        </span>
        <span
          v-if="account.status === 'blocked' && account.errorMessage"
          class="mt-1 max-w-xs truncate text-xs text-gray-500 dark:text-gray-400"
          :title="account.errorMessage"
        >
          {{ account.errorMessage }}
        </span>
        <span
          v-if="isAccountRoutingBlocked(account)"
          class="mt-1 block max-w-xl truncate text-xs font-medium text-red-600 dark:text-red-300"
          :title="`不可路由：${getRoutingBlockReasonSummary(account)}`"
        >
          不可路由：{{ getRoutingBlockReasonSummary(account) }}
        </span>
        <span
          v-if="account.accountType === 'dedicated'"
          class="text-xs text-gray-500 dark:text-gray-400"
        >
          绑定: {{ account.boundApiKeysCount || 0 }} 个API Key
        </span>
      </div>
    </td>
    <td class="whitespace-nowrap px-3 py-4 text-sm">
      <div v-if="account.usage && account.usage.daily" class="space-y-1">
        <div class="flex items-center gap-2">
          <div class="h-2 w-2 rounded-full bg-blue-500" />
          <span class="text-sm font-medium text-gray-900 dark:text-gray-100"
            >{{ account.usage.daily.requests || 0 }} 次</span
          >
        </div>
        <div class="flex items-center gap-2">
          <div class="h-2 w-2 rounded-full bg-purple-500" />
          <span class="text-xs text-gray-600 dark:text-gray-300">{{
            formatNumber(account.usage.daily.allTokens || 0)
          }}</span>
        </div>
        <div class="flex items-center gap-2">
          <div class="h-2 w-2 rounded-full bg-green-500" />
          <span class="text-xs text-gray-600 dark:text-gray-300"
            >${{ calculateDailyCost(account) }}</span
          >
        </div>
        <div
          v-if="account.usage.averages && account.usage.averages.rpm > 0"
          class="text-xs text-gray-500 dark:text-gray-400"
        >
          平均 {{ account.usage.averages.rpm.toFixed(2) }} RPM
        </div>
      </div>
      <div v-else class="text-xs text-gray-400">暂无数据</div>
    </td>
    <td class="whitespace-nowrap px-3 py-4">
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
    </td>
    <td class="whitespace-nowrap px-3 py-4">
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
                sonnet
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
          class="space-y-2"
        >
          <!-- 使用统计在顶部 -->
          <div
            v-if="account.usage && account.usage.sessionWindow"
            class="flex items-center gap-3 text-xs"
          >
            <div class="flex items-center gap-1">
              <div class="h-1.5 w-1.5 rounded-full bg-purple-500" />
              <span class="font-medium text-gray-900 dark:text-gray-100">
                {{ formatNumber(account.usage.sessionWindow.totalTokens) }}
              </span>
            </div>
            <div class="flex items-center gap-1">
              <div class="h-1.5 w-1.5 rounded-full bg-green-500" />
              <span class="font-medium text-gray-900 dark:text-gray-100">
                ${{ formatCost(account.usage.sessionWindow.totalCost) }}
              </span>
            </div>
          </div>

          <!-- 进度条 -->
          <div class="flex items-center gap-2">
            <div class="h-2 w-24 rounded-full bg-gray-200 dark:bg-gray-700">
              <div
                :class="[
                  'h-2 rounded-full transition-all duration-300',
                  getSessionProgressBarClass(account.sessionWindow.sessionWindowStatus, account)
                ]"
                :style="{ width: account.sessionWindow.progress + '%' }"
              />
            </div>
            <span class="min-w-[32px] text-xs font-medium text-gray-700 dark:text-gray-200">
              {{ account.sessionWindow.progress }}%
            </span>
          </div>

          <!-- 时间信息 -->
          <div class="text-xs text-gray-600 dark:text-gray-400">
            <div>
              {{
                formatSessionWindow(
                  account.sessionWindow.windowStart,
                  account.sessionWindow.windowEnd
                )
              }}
            </div>
            <div
              v-if="account.sessionWindow.remainingTime > 0"
              class="font-medium text-indigo-600 dark:text-indigo-400"
            >
              剩余 {{ formatRemainingTime(account.sessionWindow.remainingTime) }}
            </div>
          </div>
        </div>
        <div v-else class="text-xs text-gray-400">暂无统计</div>
      </div>
      <!-- Claude Console / OpenAI-Responses: 显示每日额度和并发状态 -->
      <div
        v-else-if="account.platform === 'claude-console' || account.platform === 'openai-responses'"
        class="space-y-3"
      >
        <div>
          <template v-if="Number(account.dailyQuota) > 0">
            <div class="flex items-center justify-between text-xs">
              <span class="text-gray-600 dark:text-gray-300">额度进度</span>
              <span class="font-medium text-gray-700 dark:text-gray-200">
                {{ getQuotaUsagePercent(account).toFixed(1) }}%
              </span>
            </div>
            <div class="flex items-center gap-2">
              <div class="h-2 w-24 rounded-full bg-gray-200 dark:bg-gray-700">
                <div
                  :class="[
                    'h-2 rounded-full transition-all duration-300',
                    getQuotaBarClass(getQuotaUsagePercent(account))
                  ]"
                  :style="{ width: Math.min(100, getQuotaUsagePercent(account)) + '%' }"
                />
              </div>
              <span class="min-w-[32px] text-xs font-medium text-gray-700 dark:text-gray-200">
                ${{ formatCost(account.usage?.daily?.cost || 0) }} / ${{
                  Number(account.dailyQuota).toFixed(2)
                }}
              </span>
            </div>
            <div class="text-xs text-gray-600 dark:text-gray-400">
              剩余 ${{ formatRemainingQuota(account) }}
              <span class="ml-2 text-gray-400">重置 {{ account.quotaResetTime || '00:00' }}</span>
            </div>
          </template>
          <template v-else>
            <div class="text-sm text-gray-400">
              <i class="fas fa-minus" />
            </div>
          </template>
        </div>

        <div class="space-y-1">
          <div class="flex items-center justify-between text-xs">
            <span class="text-gray-600 dark:text-gray-300">并发状态</span>
            <span
              v-if="Number(account.maxConcurrentTasks || 0) > 0"
              class="font-medium text-gray-700 dark:text-gray-200"
            >
              {{ getConsoleConcurrencyPercent(account).toFixed(0) }}%
            </span>
          </div>
          <div v-if="Number(account.maxConcurrentTasks || 0) > 0" class="flex items-center gap-2">
            <div class="h-2 w-24 rounded-full bg-gray-200 dark:bg-gray-700">
              <div
                :class="[
                  'h-2 rounded-full transition-all duration-300',
                  getConcurrencyBarClass(getConsoleConcurrencyPercent(account))
                ]"
                :style="{
                  width: Math.min(100, getConsoleConcurrencyPercent(account)) + '%'
                }"
              />
            </div>
            <span :class="['min-w-[48px] text-xs font-medium', getConcurrencyLabelClass(account)]">
              {{ Number(account.activeTaskCount || 0) }} /
              {{ Number(account.maxConcurrentTasks || 0) }}
            </span>
          </div>
          <div
            v-else
            class="inline-flex items-center rounded-full bg-gray-100 px-2 py-0.5 text-xs font-medium text-gray-500 dark:bg-gray-700 dark:text-gray-300"
          >
            <i class="fas fa-infinity mr-1" />并发无限制
          </div>
        </div>
      </div>
      <div v-else-if="account.platform === 'openai'" class="space-y-2">
        <div v-if="account.codexUsage" class="space-y-2">
          <div class="rounded-lg bg-gray-50 p-2 dark:bg-gray-700/70">
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
          <div class="rounded-lg bg-gray-50 p-2 dark:bg-gray-700/70">
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
        <div v-else class="text-sm text-gray-400">
          <span class="text-xs">N/A</span>
        </div>
      </div>
      <div v-else class="text-sm text-gray-400">
        <span class="text-xs">N/A</span>
      </div>
    </td>
    <td class="whitespace-nowrap px-3 py-4 text-sm text-gray-600 dark:text-gray-300">
      {{ formatLastUsed(account.lastUsedAt) }}
    </td>
    <td class="whitespace-nowrap px-3 py-4">
      <div
        v-if="
          account.platform === 'claude' ||
          account.platform === 'claude-console' ||
          account.platform === 'bedrock' ||
          account.platform === 'gemini' ||
          account.platform === 'openai' ||
          account.platform === 'openai-responses' ||
          account.platform === 'azure_openai' ||
          account.platform === 'ccr' ||
          account.platform === 'droid' ||
          account.platform === 'gemini-api'
        "
        class="flex items-center gap-2"
      >
        <div class="h-2 w-16 rounded-full bg-gray-200">
          <div
            class="h-2 rounded-full bg-gradient-to-r from-green-500 to-blue-600 transition-all duration-300"
            :style="{ width: 101 - (account.priority || 50) + '%' }"
          />
        </div>
        <span class="min-w-[20px] text-xs font-medium text-gray-700 dark:text-gray-200">
          {{ account.priority || 50 }}
        </span>
      </div>
      <div v-else class="text-sm text-gray-400">
        <span class="text-xs">N/A</span>
      </div>
    </td>
    <td class="px-3 py-4 text-sm text-gray-600">
      <div
        v-if="formatProxyDisplay(account.proxy)"
        class="break-all rounded bg-blue-50 px-2 py-1 font-mono text-xs"
        :title="formatProxyDisplay(account.proxy)"
      >
        {{ formatProxyDisplay(account.proxy) }}
      </div>
      <div v-else class="text-gray-400">无代理</div>
    </td>
    <td class="whitespace-nowrap px-3 py-4">
      <div class="flex flex-col gap-1">
        <!-- 已设置过期时间 -->
        <span v-if="account.expiresAt">
          <span
            v-if="isExpired(account.expiresAt)"
            class="inline-flex cursor-pointer items-center text-red-600 hover:underline"
            style="font-size: 13px"
            @click.stop="startEditAccountExpiry(account)"
          >
            <i class="fas fa-exclamation-circle mr-1 text-xs" />
            已过期
          </span>
          <span
            v-else-if="isExpiringSoon(account.expiresAt)"
            class="inline-flex cursor-pointer items-center text-orange-600 hover:underline"
            style="font-size: 13px"
            @click.stop="startEditAccountExpiry(account)"
          >
            <i class="fas fa-clock mr-1 text-xs" />
            {{ formatExpireDate(account.expiresAt) }}
          </span>
          <span
            v-else
            class="cursor-pointer text-gray-600 hover:underline dark:text-gray-400"
            style="font-size: 13px"
            @click.stop="startEditAccountExpiry(account)"
          >
            {{ formatExpireDate(account.expiresAt) }}
          </span>
        </span>
        <!-- 永不过期 -->
        <span
          v-else
          class="inline-flex cursor-pointer items-center text-gray-400 hover:underline dark:text-gray-500"
          style="font-size: 13px"
          @click.stop="startEditAccountExpiry(account)"
        >
          <i class="fas fa-infinity mr-1 text-xs" />
          永不过期
        </span>
      </div>
    </td>
    <td
      class="operations-column sticky right-0 z-10 whitespace-nowrap px-3 py-4 text-sm font-medium"
    >
      <!-- 宽度足够时显示所有按钮 -->
      <div v-if="!needsHorizontalScroll" class="flex items-center gap-1">
        <button
          v-if="showResetButton(account)"
          :class="[
            'rounded px-2.5 py-1 text-xs font-medium transition-colors',
            account.isResetting
              ? 'cursor-not-allowed bg-gray-100 text-gray-400'
              : 'bg-yellow-100 text-yellow-700 hover:bg-yellow-200'
          ]"
          :disabled="account.isResetting"
          :title="account.isResetting ? '重置中...' : '重置所有异常状态'"
          @click="resetAccountStatus(account)"
        >
          <i :class="['fas fa-redo', account.isResetting ? 'animate-spin' : '']" />
          <span class="ml-1">重置状态</span>
        </button>
        <button
          :class="[
            'rounded px-2.5 py-1 text-xs font-medium transition-colors',
            account.isTogglingSchedulable
              ? 'cursor-not-allowed bg-gray-100 text-gray-400'
              : account.schedulable
                ? 'bg-green-100 text-green-700 hover:bg-green-200'
                : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
          ]"
          :disabled="account.isTogglingSchedulable"
          :title="account.schedulable ? '点击禁用调度' : '点击启用调度'"
          @click="toggleSchedulable(account)"
        >
          <i :class="['fas', account.schedulable ? 'fa-toggle-on' : 'fa-toggle-off']" />
          <span class="ml-1">{{ account.schedulable ? '调度' : '停用' }}</span>
        </button>
        <button
          v-if="canViewUsage(account)"
          class="rounded bg-indigo-100 px-2.5 py-1 text-xs font-medium text-indigo-700 transition-colors hover:bg-indigo-200"
          title="查看使用详情"
          @click="openAccountUsageModal(account)"
        >
          <i class="fas fa-chart-line" />
          <span class="ml-1">详情</span>
        </button>
        <button
          class="rounded bg-red-100 px-2.5 py-1 text-xs font-medium text-red-700 transition-colors hover:bg-red-200 dark:bg-red-900/40 dark:text-red-300 dark:hover:bg-red-800/50"
          title="查看错误历史"
          @click="openErrorHistory(account)"
        >
          <i class="fas fa-exclamation-triangle" />
          <span class="ml-1">错误</span>
        </button>
        <button
          v-if="canTestAccount(account)"
          class="rounded bg-cyan-100 px-2.5 py-1 text-xs font-medium text-cyan-700 transition-colors hover:bg-cyan-200 dark:bg-cyan-900/40 dark:text-cyan-300 dark:hover:bg-cyan-800/50"
          title="测试账户连通性"
          @click="openAccountTestModal(account)"
        >
          <i class="fas fa-vial" />
          <span class="ml-1">测试</span>
        </button>
        <button
          v-if="canScheduleTestAccount(account)"
          class="rounded bg-amber-100 px-2.5 py-1 text-xs font-medium text-amber-700 transition-colors hover:bg-amber-200 dark:bg-amber-900/40 dark:text-amber-300 dark:hover:bg-amber-800/50"
          title="定时测试配置"
          @click="openScheduledTestModal(account)"
        >
          <i class="fas fa-clock" />
          <span class="ml-1">定时</span>
        </button>
        <button
          class="rounded bg-blue-100 px-2.5 py-1 text-xs font-medium text-blue-700 transition-colors hover:bg-blue-200"
          title="编辑账户"
          @click="editAccount(account)"
        >
          <i class="fas fa-edit" />
          <span class="ml-1">编辑</span>
        </button>
        <button
          class="rounded bg-red-100 px-2.5 py-1 text-xs font-medium text-red-700 transition-colors hover:bg-red-200"
          title="删除账户"
          @click="deleteAccount(account)"
        >
          <i class="fas fa-trash" />
          <span class="ml-1">删除</span>
        </button>
      </div>
      <!-- 需要横向滚动时使用缩减形式：2个快捷按钮 + 下拉菜单 -->
      <div v-else class="flex items-center gap-1">
        <button
          :class="[
            'rounded px-2.5 py-1 text-xs font-medium transition-colors',
            account.isTogglingSchedulable
              ? 'cursor-not-allowed bg-gray-100 text-gray-400'
              : account.schedulable
                ? 'bg-green-100 text-green-700 hover:bg-green-200'
                : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
          ]"
          :disabled="account.isTogglingSchedulable"
          :title="account.schedulable ? '点击禁用调度' : '点击启用调度'"
          @click="toggleSchedulable(account)"
        >
          <i :class="['fas', account.schedulable ? 'fa-toggle-on' : 'fa-toggle-off']" />
          <span class="ml-1">{{ account.schedulable ? '调度' : '停用' }}</span>
        </button>
        <button
          class="rounded bg-blue-100 px-2.5 py-1 text-xs font-medium text-blue-700 transition-colors hover:bg-blue-200"
          title="编辑账户"
          @click="editAccount(account)"
        >
          <i class="fas fa-edit" />
          <span class="ml-1">编辑</span>
        </button>
        <ActionDropdown :actions="getAccountActions(account)" />
      </div>
    </td>
  </tr>
</template>

<script setup>
import { toRefs, useAttrs } from 'vue'

import ActionDropdown from '@/components/common/ActionDropdown.vue'
import BalanceDisplay from '@/components/accounts/BalanceDisplay.vue'
import TempUnavailableBadge from '@/components/accounts/TempUnavailableBadge.vue'

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
  },
  needsHorizontalScroll: {
    type: Boolean,
    default: false
  }
})

const emit = defineEmits(['toggle-select'])
const attrs = useAttrs()
const { account, selected, showCheckboxes, needsHorizontalScroll } = toRefs(props)

const {
  copyText,
  formatNumber,
  formatCost,
  formatRateLimitTime,
  calculateDailyCost,
  getGeminiAuthType,
  getOpenAIAuthType,
  getClaudeAccountType,
  getClaudeAuthType,
  getDroidAuthType,
  isDroidApiKeyMode,
  getDroidApiKeyBadgeClasses,
  getDroidApiKeyCount,
  getSchedulableReason,
  isAccountRoutingBlocked,
  getRoutingBlockReasonSummary,
  isClaudeOAuth,
  getClaudeUsageBarClass,
  getClaudeUsageWidth,
  formatClaudeUsagePercent,
  formatClaudeRemaining,
  formatSessionWindow,
  getSessionProgressBarClass,
  formatRemainingTime,
  getQuotaUsagePercent,
  getQuotaBarClass,
  formatRemainingQuota,
  getConsoleConcurrencyPercent,
  getConcurrencyBarClass,
  getConcurrencyLabelClass,
  getCodexWindowLabel,
  getCodexUsageBarClass,
  getCodexUsageWidth,
  formatCodexUsagePercent,
  formatCodexRemaining,
  formatLastUsed,
  formatProxyDisplay,
  isExpired,
  isExpiringSoon,
  formatExpireDate,
  showResetButton,
  canViewUsage,
  canTestAccount,
  canScheduleTestAccount,
  getAccountActions,
  handleBalanceError,
  handleBalanceRefreshed,
  openBalanceScriptModal,
  startEditAccountExpiry,
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
