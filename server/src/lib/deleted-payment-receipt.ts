import { createHash } from 'node:crypto'
import type { Prisma } from '@prisma/client'
export const paymentTradeHash = (trade: string) => createHash('sha256').update(trade.trim()).digest('hex')
export async function assertPaymentNotDeleted(tx: Prisma.TransactionClient, providerId: number, trade: string) {
  if (await tx.deletedPaymentReceipt.findUnique({ where: { providerId_tradeHash: { providerId, tradeHash: paymentTradeHash(trade) } } })) throw Error('PAYMENT_TRADE_ALREADY_CREDITED')
}
