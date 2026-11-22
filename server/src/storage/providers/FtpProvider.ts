/**
 * FTP 存储适配器
 */

import * as ftp from 'basic-ftp'
import { PassThrough, Readable } from 'stream'
import { limitReadable } from '../../lib/bounded-response.js'
import type { IStorageProvider, StorageConfigData } from '../types.js'
import { assertSafeStorageTarget, resolvePublicHostname } from '../../lib/outbound-security.js'
import { rejectStorageControlCharacters } from '../transport.js'
import { joinStorageRemoteDirectory, joinStorageRemotePath, normalizeStorageBasePath } from '../path.js'

// FTP 超时配置（6小时，适合大型备份）
const FTP_TIMEOUT = 60 * 1000

export class FtpProvider implements IStorageProvider {
    private config: StorageConfigData
    private basePath: string

    constructor(config: StorageConfigData) {
        for (const value of [config.host,config.username,config.password,config.basePath]) rejectStorageControlCharacters(value)
        this.config = config
        this.basePath = normalizeStorageBasePath(config.basePath)
    }

    private async getClient(timeout = FTP_TIMEOUT): Promise<ftp.Client> {
        await assertSafeStorageTarget('FTP', this.config.host)
        const client = new ftp.Client(timeout)
        client.ftp.verbose = false

        const hostname = this.config.host.replace(/^ftps?:\/\//, '')
        const [address] = await resolvePublicHostname(hostname)
        try { await client.access({
            host: address.address,
            port: this.config.port || 21,
            user: this.config.username || 'anonymous',
            password: this.config.password || '',
            secure: true,
            secureOptions: { servername: hostname, rejectUnauthorized: true }
        }) } catch (error) { client.close(); throw error }

        return client
    }

    async uploadStream(fileStream: Readable, filename: string): Promise<void> {
        const client = await this.getClient()

        try {
            // 确保目录存在
            if (this.basePath && this.basePath !== '/') {
                await client.ensureDir(this.basePath)
            }

            // 上传文件
            const remotePath = joinStorageRemotePath(this.basePath, filename)
            await client.uploadFrom(limitReadable(fileStream), remotePath)
        } finally {
            client.close()
        }
    }

    async downloadStream(filename: string): Promise<Readable> {
        const client = await this.getClient()
        const stream = new PassThrough()
        stream.once('close', () => client.close())

        void client.downloadTo(stream, joinStorageRemotePath(this.basePath, filename))
            .catch(error => stream.destroy(error))
            .finally(() => client.close())

        return limitReadable(stream)
    }

    async testConnection(): Promise<void> {
        const client = await this.getClient(10000)
        const timeout=setTimeout(()=>client.close(),5000)

        try {
            // 尝试列出目录来测试连接
            await client.list('/')
        } catch (err) {
            const message = err instanceof Error ? err.message : String(err)
            throw new Error(`FTP 连接测试失败: ${message}`)
        } finally {
            clearTimeout(timeout)
            client.close()
        }
    }

    async deleteFile(filename: string): Promise<void> {
        const client = await this.getClient()

        try {
            const remotePath = joinStorageRemotePath(this.basePath, filename)
            await client.remove(remotePath)
        } catch (err) {
            const message = err instanceof Error ? err.message : String(err)
            throw new Error(`删除文件失败: ${message}`)
        } finally {
            client.close()
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
            client.close()
        }
    }
}
