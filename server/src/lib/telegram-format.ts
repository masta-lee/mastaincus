/** Bound the encoded payload too, so escaping cannot produce an invalid or
 * overlong Telegram message. Iterate code points to keep surrogate pairs. */
function clippedEscape(value: string, budget: number, escape: (value: string) => string): string {
  let result = ''
  for (const character of value) {
    const encoded = escape(character)
    if (result.length + encoded.length > budget) return result + '…'
    result += encoded
  }
  return result
}
export const telegramMarkdownEscape = (value: string): string => value.replace(/([\\_*\[\]()~`>#+\-=|{}.!])/g, '\\$1')
export function telegramMarkdownText(title: string, message: string, link?: {label:string;url:string}): string {
  const heading = clippedEscape(title.replace(/[\r\n]+/g,' '), 300, telegramMarkdownEscape)
  let suffix = ''
  if (link) {
    const url = new URL(link.url)
    if (!['https:','http:'].includes(url.protocol) || url.username || url.password) throw Error('Invalid notification link')
    const target = url.href.replace(/[\\)]/g, '\\$&')
    if (target.length > 1000) throw Error('Notification link is too long')
    suffix = `\n[${clippedEscape(link.label, 200, telegramMarkdownEscape)}](${target})`
  }
  const prefix = `*${heading}*\n\n`
  return prefix + clippedEscape(message, 3990-prefix.length-suffix.length, telegramMarkdownEscape) + suffix
}
export function telegramHtmlText(title: string, message: string): string {
  const escape = (value:string) => value.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
  const prefix = `<b>${clippedEscape(title.replace(/[\r\n]+/g,' '), 300, escape)}</b>\n\n`
  return prefix + clippedEscape(message, 3990-prefix.length, escape)
}
