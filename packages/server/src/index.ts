import express, { Request, Response } from 'express'
import path from 'path'
import cors from 'cors'
import http from 'http'
import cookieParser from 'cookie-parser'
import { DataSource } from 'typeorm' // Removed IsNull
import { MODE } from './Interface' // Removed Platform
import { getNodeModulesPackagePath, getEncryptionKey } from './utils'
import logger, { expressRequestLogger } from './utils/logger'
import { getDataSource } from './DataSource'
import { NodesPool } from './NodesPool'
import { ChatFlow } from './database/entities/ChatFlow'
import { CachePool } from './CachePool'
import { AbortControllerPool } from './AbortControllerPool'
import { RateLimiterManager } from './utils/rateLimit'
import { getAllowedIframeOrigins, getCorsOptions, sanitizeMiddleware } from './utils/XSS'
import { Telemetry } from './utils/telemetry'
import flowiseApiV1Router from './routes'
import errorHandlerMiddleware from './middlewares/errors'
import { WHITELIST_URLS } from './utils/constants'
import { initializeJwtCookieMiddleware } from './enterprise/middleware/passport' // Removed verifyToken
import { IdentityManager } from './IdentityManager'
import { SSEStreamer } from './utils/SSEStreamer'
// Removed getAPIKeyWorkspaceID, validateAPIKey from './utils/validateKey'
import { LoggedInUser } from './enterprise/Interface.Enterprise' // Keeping LoggedInUser for now
import { IMetricsProvider } from './Interface.Metrics'
import { Prometheus } from './metrics/Prometheus'
import { OpenTelemetry } from './metrics/OpenTelemetry'
import { QueueManager } from './queue/QueueManager'
import { RedisEventSubscriber } from './queue/RedisEventSubscriber'
import 'global-agent/bootstrap'
import { UsageCacheManager } from './UsageCacheManager'
// Removed Workspace, Organization, GeneralRole, Role imports
import { migrateApiKeysFromJsonToDb } from './utils/apiKey'
import flowiseUserService from './services/flowise-user'

declare global {
    namespace Express {
        // Ensure Express.User is based on LoggedInUser
        interface User extends LoggedInUser {
            isAuthenticatedByHeader?: boolean; // Added optional property
        }

        // The Request interface should use the User type defined above.
        interface Request {
            user?: User;
        }
        
        // Multer definition can remain if it exists and is correct
        namespace Multer {
            interface File {
                bucket: string
                key: string
                acl: string
                contentType: string
                contentDisposition: null
                storageClass: string
                serverSideEncryption: null
                metadata: any
                location: string
                etag: string
            }
        }
    }
}

export class App {
    app: express.Application
    nodesPool: NodesPool
    abortControllerPool: AbortControllerPool
    cachePool: CachePool
    telemetry: Telemetry
    rateLimiterManager: RateLimiterManager
    AppDataSource: DataSource = getDataSource()
    sseStreamer: SSEStreamer
    identityManager: IdentityManager
    metricsProvider: IMetricsProvider
    queueManager: QueueManager
    redisSubscriber: RedisEventSubscriber
    usageCacheManager: UsageCacheManager

    constructor() {
        this.app = express()
    }

    async initDatabase() {
        // Initialize database
        try {
            await this.AppDataSource.initialize()
            logger.info('📦 [server]: Data Source is initializing...')

            // Run Migrations Scripts
            await this.AppDataSource.runMigrations({ transaction: 'each' })

            // Initialize Identity Manager
            this.identityManager = await IdentityManager.getInstance()

            // Initialize nodes pool
            this.nodesPool = new NodesPool()
            await this.nodesPool.initialize()

            // Initialize abort controllers pool
            this.abortControllerPool = new AbortControllerPool()

            // Initialize encryption key
            await getEncryptionKey()

            // Initialize Rate Limit
            this.rateLimiterManager = RateLimiterManager.getInstance()
            await this.rateLimiterManager.initializeRateLimiters(await getDataSource().getRepository(ChatFlow).find())

            // Initialize cache pool
            this.cachePool = new CachePool()

            // Initialize usage cache manager
            this.usageCacheManager = await UsageCacheManager.getInstance()

            // Initialize telemetry
            this.telemetry = new Telemetry()

            // Initialize SSE Streamer
            this.sseStreamer = new SSEStreamer()

            // Init Queues
            if (process.env.MODE === MODE.QUEUE) {
                this.queueManager = QueueManager.getInstance()
                this.queueManager.setupAllQueues({
                    componentNodes: this.nodesPool.componentNodes,
                    telemetry: this.telemetry,
                    cachePool: this.cachePool,
                    appDataSource: this.AppDataSource,
                    abortControllerPool: this.abortControllerPool,
                    usageCacheManager: this.usageCacheManager
                })
                logger.info('✅ [Queue]: All queues setup successfully')
                this.redisSubscriber = new RedisEventSubscriber(this.sseStreamer)
                await this.redisSubscriber.connect()
            }

            // TODO: Remove this by end of 2025
            await migrateApiKeysFromJsonToDb(this.AppDataSource, this.identityManager.getPlatformType())

            logger.info('📦 [server]: Data Source has been initialized!')
        } catch (error) {
            logger.error('❌ [server]: Error during Data Source initialization:', error)
        }
    }

    async config() {
        // Limit is needed to allow sending/receiving base64 encoded string
        const flowise_file_size_limit = process.env.FLOWISE_FILE_SIZE_LIMIT || '50mb'
        this.app.use(express.json({ limit: flowise_file_size_limit }))
        this.app.use(express.urlencoded({ limit: flowise_file_size_limit, extended: true }))

        // Enhanced trust proxy settings for load balancer
        this.app.set('trust proxy', true) // Trust all proxies

        // Allow access from specified domains
        this.app.use(cors(getCorsOptions()))

        // Parse cookies
        this.app.use(cookieParser())

        // Allow embedding from specified domains.
        this.app.use((req, res, next) => {
            const allowedOrigins = getAllowedIframeOrigins()
            if (allowedOrigins == '*') {
                next()
            } else {
                const csp = `frame-ancestors ${allowedOrigins}`
                res.setHeader('Content-Security-Policy', csp)
                next()
            }
        })

        // Switch off the default 'X-Powered-By: Express' header
        this.app.disable('x-powered-by')

        // Add the expressRequestLogger middleware to log all requests
        this.app.use(expressRequestLogger)

        // Add the sanitizeMiddleware to guard against XSS
        this.app.use(sanitizeMiddleware)

        this.app.use((req, res, next) => {
            res.header('Access-Control-Allow-Credentials', 'true') // Allow credentials (cookies, etc.)
            if (next) next()
        })

        const whitelistURLs = WHITELIST_URLS
        const URL_CASE_INSENSITIVE_REGEX: RegExp = /\/api\/v1\//i
        const URL_CASE_SENSITIVE_REGEX: RegExp = /\/api\/v1\//

        await initializeJwtCookieMiddleware(this.app, this.identityManager) // This can be kept if it doesn't interfere with the new logic (e.g. sets cookies but doesn't block)

        // Simplified Authentication Middleware
        this.app.use(async (req: Request, res: Response, next: express.NextFunction) => {
            if (URL_CASE_INSENSITIVE_REGEX.test(req.path)) {
                if (URL_CASE_SENSITIVE_REGEX.test(req.path)) {
                    const isWhitelisted = whitelistURLs.some((url) => req.path.startsWith(url));
                    if (isWhitelisted) {
                        return next(); // Whitelisted, proceed
                    }

                    // If not whitelisted, check for X-Forwarded-Email header
                    const forwardedEmail = req.headers['x-forwarded-email'] as string;
                    if (forwardedEmail) {
                        try {
                            const flowiseDbUser = await flowiseUserService.findOrCreateUserByEmail(forwardedEmail);
                            
                            const loggedInUserShape: Express.User = {
                                // Core properties from FlowiseUser
                                id: flowiseDbUser.id,
                                email: flowiseDbUser.email,
                        
                                // Custom flag
                                isAuthenticatedByHeader: true,
                        
                                // Default/placeholder values for other LoggedInUser properties
                                name: flowiseDbUser.email, // Defaulting name to email
                                roleId: '', // Default to empty string or a specific "guest/header" role ID
                                activeOrganizationId: '', // Default to empty string or specific placeholder
                                activeOrganizationSubscriptionId: '', // Default
                                activeOrganizationCustomerId: '', // Default
                                activeOrganizationProductId: '', // Default
                                isOrganizationAdmin: false, // Default
                                activeWorkspaceId: '', // Default
                                activeWorkspace: '', // Default
                                assignedWorkspaces: [], // Default
                                isApiKeyValidated: false, // Default
                                permissions: [], // Default
                                features: {}, // Default
                                ssoRefreshToken: undefined, // Default
                                ssoToken: undefined, // Default
                                ssoProvider: undefined // Default
                            };
                            req.user = loggedInUserShape;
                            return next();
                        } catch (error) {
                            logger.error('Error during X-Forwarded-Email authentication:', error);
                            return res.status(500).json({ error: 'Internal Server Error during authentication' });
                        }
                    } else {
                        // Not whitelisted and no X-Forwarded-Email header for an /api/v1/ path
                        return res.status(401).json({ error: 'Unauthorized: X-Forwarded-Email header is required' });
                    }
                } else { // Path does not match URL_CASE_SENSITIVE_REGEX (e.g. /api/v1/UPPERCASE_PATH)
                    return res.status(401).json({ error: 'Unauthorized Access - Invalid Path Structure' });
                }
            } else { // Path does not contain /api/v1 (e.g. /assets, /canvas)
                return next();
            }
        });
        
        // this is for SSO and must be after the JWT cookie middleware
        await this.identityManager.initializeSSO(this.app)

        if (process.env.ENABLE_METRICS === 'true') {
            switch (process.env.METRICS_PROVIDER) {
                // default to prometheus
                case 'prometheus':
                case undefined:
                    this.metricsProvider = new Prometheus(this.app)
                    break
                case 'open_telemetry':
                    this.metricsProvider = new OpenTelemetry(this.app)
                    break
                // add more cases for other metrics providers here
            }
            if (this.metricsProvider) {
                await this.metricsProvider.initializeCounters()
                logger.info(`📊 [server]: Metrics Provider [${this.metricsProvider.getName()}] has been initialized!`)
            } else {
                logger.error(
                    "❌ [server]: Metrics collection is enabled, but failed to initialize provider (valid values are 'prometheus' or 'open_telemetry'."
                )
            }
        }

        this.app.use('/api/v1', flowiseApiV1Router)

        // ----------------------------------------
        // Configure number of proxies in Host Environment
        // ----------------------------------------
        this.app.get('/api/v1/ip', (request, response) => {
            response.send({
                ip: request.ip,
                msg: 'Check returned IP address in the response. If it matches your current IP address ( which you can get by going to http://ip.nfriedly.com/ or https://api.ipify.org/ ), then the number of proxies is correct and the rate limiter should now work correctly. If not, increase the number of proxies by 1 and restart Cloud-Hosted Flowise until the IP address matches your own. Visit https://docs.flowiseai.com/configuration/rate-limit#cloud-hosted-rate-limit-setup-guide for more information.'
            })
        })

        if (process.env.MODE === MODE.QUEUE && process.env.ENABLE_BULLMQ_DASHBOARD === 'true' && !this.identityManager.isCloud()) {
            this.app.use('/admin/queues', this.queueManager.getBullBoardRouter())
        }

        // ----------------------------------------
        // Serve UI static
        // ----------------------------------------

        const packagePath = getNodeModulesPackagePath('flowise-ui')
        const uiBuildPath = path.join(packagePath, 'build')
        const uiHtmlPath = path.join(packagePath, 'build', 'index.html')

        this.app.use('/', express.static(uiBuildPath))

        // All other requests not handled will return React app
        this.app.use((req: Request, res: Response) => {
            res.sendFile(uiHtmlPath)
        })

        // Error handling
        this.app.use(errorHandlerMiddleware)
    }

    async stopApp() {
        try {
            const removePromises: any[] = []
            removePromises.push(this.telemetry.flush())
            if (this.queueManager) {
                removePromises.push(this.redisSubscriber.disconnect())
            }
            await Promise.all(removePromises)
        } catch (e) {
            logger.error(`❌[server]: Flowise Server shut down error: ${e}`)
        }
    }
}

let serverApp: App | undefined

export async function start(): Promise<void> {
    serverApp = new App()

    const host = process.env.HOST
    const port = parseInt(process.env.PORT || '', 10) || 3000
    const server = http.createServer(serverApp.app)

    await serverApp.initDatabase()
    await serverApp.config()

    server.listen(port, host, () => {
        logger.info(`⚡️ [server]: Flowise Server is listening at ${host ? 'http://' + host : ''}:${port}`)
    })
}

export function getInstance(): App | undefined {
    return serverApp
}
