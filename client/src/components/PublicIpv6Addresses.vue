<script setup lang="ts">
import { onUnmounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { Check, Copy } from 'lucide-vue-next'
import { useToast } from '@/stores/toast'
import { useThemeStore } from '@/stores/theme'

defineProps<{ addresses: string[]; status?: string; showEmpty?: boolean; appearance?: 'network' }>()
const { t } = useI18n()
const toast = useToast()
const themeStore = useThemeStore()
const copied = ref('')
let timer: ReturnType<typeof setTimeout> | undefined
async function copy(address: string) {
  try {
    await navigator.clipboard.writeText(address)
    copied.value = address
    clearTimeout(timer)
    timer = setTimeout(() => { copied.value = '' }, 2000)
  } catch { toast.error(t('common.copyFailed')) }
}
onUnmounted(() => clearTimeout(timer))
</script>

<template>
  <div class="min-w-0 space-y-2">
    <ul v-if="addresses.length" class="space-y-1.5" :aria-label="t('ipv6Delivery.title')">
      <li v-for="(address, index) in addresses" :key="address" class="flex gap-2" :class="appearance === 'network' ? 'items-center justify-end' : 'items-start'">
        <div class="min-w-0" :class="appearance === 'network' ? '' : 'py-1'">
          <code
            class="text-sm font-mono break-all"
            :class="appearance === 'network'
              ? ['network-address-value block px-2 py-0.5 rounded', themeStore.isDark ? 'text-gray-300 bg-gray-800' : 'text-gray-700 bg-gray-100']
              : 'text-themed'"
          >{{ address }}</code>
          <span v-if="addresses.length > 1 && index === 0" class="ml-2 text-xs text-themed-muted">{{ t('ipv6Delivery.primary') }}</span>
        </div>
        <button type="button" class="shrink-0" :class="appearance === 'network' ? 'network-address-copy text-gray-500 hover:text-gray-400' : 'btn-secondary p-2'" :aria-label="t('ipv6Delivery.copyAddress', { address })" :title="t('common.copy')" @click="copy(address)">
          <template v-if="appearance === 'network'">
            <svg v-if="copied !== address" class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
            </svg>
            <svg v-else class="w-4 h-4 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
            </svg>
          </template>
          <template v-else>
            <Check v-if="copied === address" :size="16" class="text-green-600 dark:text-green-400" aria-hidden="true" />
            <Copy v-else :size="16" aria-hidden="true" />
          </template>
        </button>
      </li>
    </ul>
    <p v-else-if="showEmpty && status !== 'pending' && status !== 'failed'" class="text-sm text-themed-muted">{{ t('ipv6Delivery.empty') }}</p>
    <p v-if="status === 'pending' || status === 'failed'" role="status" class="text-sm text-amber-700 dark:text-amber-300">{{ t(status === 'failed' ? 'ipv6Delivery.customerFailed' : 'ipv6Delivery.customerPending') }}</p>
    <span class="sr-only" aria-live="polite">{{ copied ? t('common.copied') : '' }}</span>
  </div>
</template>
