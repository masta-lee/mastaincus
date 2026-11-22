/**
 * WebDAV 存储适配器
 */

import { createClient, WebDAVClient } from 'webdav'
import { Readable } from 'stream'
import '../webdav-transport.js'
import { limitReadable, readBoundedResponse } from '../../lib/bounded-response.js'
import type { IStorageProvider, StorageConfigData } from '../types.js'
import { assertSafeStorageTarget } from '../../lib/outbound-security.js'
import { joinStorageRemoteDirectory, joinStorageRemotePath, normalizeStorageBasePath } from '../path.js'
import { storageHttpAgent, storageHttpsAgent, rejectStorageControlCharacters } from '../transport.js'

export class WebDavProvider implements IStorageProvider {
    private client: WebDAVClient
    private basePath: string
    private rawHost: string

    constructor(config: StorageConfigData) {
        rejectStorageControlCharacters(config.host)
        // 构建 WebDAV URL
        const port = config.port ? `:${config.port}` : ''
        const baseUrl = config.host.includes('://')
            ? `${config.host}${port}`
            : `https://${config.host}${port}`

        this.rawHost = config.host

        this.basePath = normalizeStorageBasePath(config.basePath)

        this.client = createClient(baseUrl, {
            httpAgent: storageHttpAgent,
            httpsAgent: storageHttpsAgent,
            username: config.username || undefined,
            password: config.password || undefined
        })
    }

    async uploadStream(fileStream: Readable, filename: string): Promise<void> {
        await assertSafeStorageTarget('WEBDAV', this.rawHost)
        const remotePath = joinStorageRemotePath(this.basePath, filename)

        // 确保目录存在
        try {
            const dirExists = await this.client.exists(this.basePath)
            if (!dirExists) {
                await this.client.createDirectory(this.basePath, { recursive: true })
            }
        } catch {
            // 忽略目录创建错误，可能已存在
        }

        // Await the remote HTTP success, not just a local writable finish.
        const response = await this.client.customRequest(remotePath, { method: 'PUT', data: limitReadable(fileStream) })
        await readBoundedResponse((response as unknown as { body: Readable }).body, 2 * 1024 ** 2)
    }

    async downloadStream(filename: string): Promise<Readable> {
        await assertSafeStorageTarget('WEBDAV', this.rawHost)
        const remotePath = joinStorageRemotePath(this.basePath, filename)
        const response = await this.client.customRequest(remotePath, { method: 'GET' })
        return (response as unknown as { body: Readable }).body
    }

    async testConnection(): Promise<void> {
        try {
            await assertSafeStorageTarget('WEBDAV', this.rawHost)
            // 尝试获取根目录内容来测试连接
            await this.client.getDirectoryContents('/', { signal: AbortSignal.timeout(15000) })
        } catch (err) {
            const message = err instanceof Error ? err.message : String(err)
            throw new Error(`WebDAV 连接测试失败: ${message}`)
        }
    }

    async deleteFile(filename: string): Promise<void> {
        await assertSafeStorageTarget('WEBDAV', this.rawHost)
        const remotePath = joinStorageRemotePath(this.basePath, filename)
        try {
            await this.client.deleteFile(remotePath)
        } catch (err) {
            const message = err instanceof Error ? err.message : String(err)
            throw new Error(`删除文件失败: ${message}`)
        }
    }

    async listFiles(path?: string): Promise<string[]> {
        await assertSafeStorageTarget('WEBDAV', this.rawHost)
        const targetPath = joinStorageRemoteDirectory(this.basePath, path)
        try {
            const contents = await this.client.getDirectoryContents(targetPath)
            if (Array.isArray(contents)) {
                return contents.map(item => item.basename)
            }
            return []
        } catch {
            return []
        }
    }
}
