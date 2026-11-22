/**
 * SFTP 存储适配器
 */

import SftpClient from 'ssh2-sftp-client'
import { Readable, PassThrough } from 'stream'
import { limitReadable } from '../../lib/bounded-response.js'
import type { IStorageProvider, StorageConfigData } from '../types.js'
import { assertSafeStorageTarget, resolvePublicHostname } from '../../lib/outbound-security.js'
import { rejectStorageControlCharacters } from '../transport.js'
import { createHash } from 'node:crypto'
import { joinStorageRemoteDirectory, joinStorageRemotePath, normalizeStorageBasePath } from '../path.js'

// SFTP 超时配置（6小时，适合大型备份）
const SFTP_TIMEOUT = 15000

export class SftpProvider implements IStorageProvider {
    private config: StorageConfigData
    private basePath: string

    constructor(config: StorageConfigData) {
        for (const value of [config.host,config.username,config.password,config.basePath]) rejectStorageControlCharacters(value)
        this.config = config
        this.basePath = normalizeStorageBasePath(config.basePath)
    }

    private async getClient(timeout = SFTP_TIMEOUT): Promise<SftpClient> {
        await assertSafeStorageTarget('SFTP', this.config.host)
        const client = new SftpClient()
        const hostname = this.config.host.replace(/^sftp:\/\//, '')
        const [address] = await resolvePublicHostname(hostname)
        const fingerprint = this.config.extra?.hostFingerprint
        if (typeof fingerprint !== 'string' || !/^SHA256:[A-Za-z0-9+/]{43}$/.test(fingerprint)) throw new Error('SFTP_HOST_FINGERPRINT_REQUIRED')

        try { await client.connect({
            host: address.address,
            hostVerifier: (key: Buffer) => `SHA256:${createHash('sha256').update(key).digest('base64').replace(/=+$/,'')}` === fingerprint,
            port: this.config.port || 22,
            username: this.config.username || '',
            password: this.config.password || '',
            // 大文件上传需要更长的超时时间
            readyTimeout: timeout,
            retries: 0,
            retry_minTimeout: 2000
        }) } catch (error) { await client.end().catch(() => {}); throw error }

        return client
    }

    async uploadStream(fileStream: Readable, filename: string): Promise<void> {
        const client = await this.getClient()

        try {
            // 确保目录存在
            if (this.basePath && this.basePath !== '/') {
                try {
                    await client.mkdir(this.basePath, true)
                } catch {
                    // 目录可能已存在
                }
            }

            // 上传文件
            const remotePath = joinStorageRemotePath(this.basePath, filename)
            await client.put(limitReadable(fileStream), remotePath)
        } finally {
            await client.end()
        }
    }

    async downloadStream(filename: string): Promise<Readable> {
        const client = await this.getClient()
        const remotePath = joinStorageRemotePath(this.basePath, filename)
        try {
            const stream = new PassThrough()
            stream.once('close',()=>{ void client.end() })
            void client.get(remotePath, stream).then(()=>stream.end(),error=>stream.destroy(error)).finally(()=>client.end())
            return limitReadable(stream)
        } catch (error) {
            await client.end()
            throw error
        }
    }

    async testConnection(): Promise<void> {
        const client = await this.getClient(10000)
        const timeout=setTimeout(()=>{void client.end()},5000)

        try {
            // 尝试列出根目录来测试连接
            await client.list('/')
        } catch (err) {
            const message = err instanceof Error ? err.message : String(err)
            throw new Error(`SFTP 连接测试失败: ${message}`)
        } finally {
            clearTimeout(timeout)
            await client.end()
        }
    }

    async deleteFile(filename: string): Promise<void> {
        const client = await this.getClient()

        try {
            const remotePath = joinStorageRemotePath(this.basePath, filename)
            await client.delete(remotePath)
        } catch (err) {
            const message = err instanceof Error ? err.message : String(err)
            throw new Error(`删除文件失败: ${message}`)
        } finally {
            await client.end()
        }
    }

    async listFiles(path?: string): Promise<string[]> {
        const client = await this.getClient()

        try {
            const targetPath = joinStorageRemoteDirectory(this.basePath, path)
            const list = await client.list(targetPath)
            return list.map(item => item.name)
        } catch {
            return []
        } finally {
            await client.end()
        }
    }
}
