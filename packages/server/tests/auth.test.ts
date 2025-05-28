import request from 'supertest'
import { Server } from 'http'
import { App, getInstance, start } from '../src/index'
import flowiseUserService from '../src/services/flowise-user'
import * as validateKey from '../src/utils/validateKey'
import { getDataSource } from '../src/DataSource'
import { Platform } from '../src/Interface'
import { IdentityManager } from '../src/IdentityManager'
import { Workspace } from '../src/enterprise/database/entities/workspace.entity'
import { Organization } from '../src/enterprise/database/entities/organization.entity'
import { GeneralRole, Role } from '../src/enterprise/database/entities/role.entity'
import { DataSource, IsNull } from 'typeorm'

// Mock actual services and utilities
jest.mock('../src/services/flowise-user')
jest.mock('../src/utils/validateKey')
jest.mock('../src/IdentityManager')

// Constants for test users and API keys
const NEW_USER_EMAIL = 'new.user@example.com'
const EXISTING_USER_EMAIL = 'existing.user@example.com'
const MOCK_USER_ID = 'mock-user-id'
const MOCK_WORKSPACE_ID = 'mock-workspace-id'
const VALID_API_KEY = 'valid-api-key'

const PROTECTED_ROUTE = '/api/v1/chatflows' // Assuming this is a protected route
const WHITELISTED_ROUTE = '/api/v1/marketplaces/chatflows' // Assuming this is a whitelisted route

describe('Authentication Middleware Tests', () => {
    let appInstance: App
    let server: Server
    let dataSource: DataSource

    beforeAll(async () => {
        // Mock IdentityManager
        const mockIdentityManagerInstance = {
            getPlatformType: jest.fn().mockReturnValue(Platform.OPEN_SOURCE), // Default to OSS to bypass license checks
            isLicenseValid: jest.fn().mockReturnValue(true),
            getFeaturesByPlan: jest.fn().mockResolvedValue({}),
            getProductIdFromSubscription: jest.fn().mockResolvedValue(''),
            initializeSSO: jest.fn().mockResolvedValue(undefined)
        }
        ;(IdentityManager.getInstance as jest.Mock).mockResolvedValue(mockIdentityManagerInstance)

        // Start the server
        await start() // This will initialize the app and data source
        appInstance = getInstance()!
        server = appInstance.app.listen() // Get the server instance for supertest
        dataSource = getDataSource()

        // Mock TypeORM repositories for API key auth path (if needed)
        // @ts-ignore
        jest.spyOn(dataSource, 'getRepository').mockImplementation((entity: any) => {
            if (entity === Workspace) {
                return {
                    findOne: jest.fn().mockResolvedValue({
                        id: MOCK_WORKSPACE_ID,
                        name: 'Mock Workspace',
                        organizationId: 'mock-org-id'
                    })
                }
            }
            if (entity === Role) {
                return {
                    findOne: jest.fn().mockResolvedValue({
                        name: GeneralRole.OWNER,
                        permissions: JSON.stringify(['*'])
                    })
                }
            }
            if (entity === Organization) {
                return {
                    findOne: jest.fn().mockResolvedValue({
                        id: 'mock-org-id',
                        subscriptionId: 'mock-sub-id',
                        customerId: 'mock-customer-id'
                    })
                }
            }
            return {
                findOne: jest.fn(),
                findOneBy: jest.fn(),
                save: jest.fn()
            } // Default mock for other repositories
        })
    })

    afterAll(async () => {
        if (server) {
            server.close()
        }
        if (dataSource && dataSource.isInitialized) {
            await dataSource.destroy()
        }
        jest.restoreAllMocks() // Restore all mocks
    })

    beforeEach(() => {
        // Reset mocks before each test
        jest.clearAllMocks()

        // Default mock implementations
        ;(flowiseUserService.findOrCreateUserByEmail as jest.Mock).mockImplementation(async (email: string) => {
            if (email === NEW_USER_EMAIL) {
                return { id: MOCK_USER_ID, email, createdDate: new Date(), updatedDate: new Date() }
            }
            if (email === EXISTING_USER_EMAIL) {
                return { id: 'existing-user-id', email, createdDate: new Date(), updatedDate: new Date() }
            }
            return null
        })
        ;(validateKey.validateAPIKey as jest.Mock).mockResolvedValue(false)
        ;(validateKey.getAPIKeyWorkspaceID as jest.Mock).mockResolvedValue(null)

        // Re-mock IdentityManager for each test if needed, or rely on beforeAll
        const mockIdentityManagerInstance = IdentityManager.getInstance() as jest.Mocked<IdentityManager>
        mockIdentityManagerInstance.getPlatformType.mockReturnValue(Platform.OPEN_SOURCE)
        mockIdentityManagerInstance.isLicenseValid.mockReturnValue(true)
    })

    // Test Case 1: X-Forwarded-Email Authentication - New User
    test('1. X-Forwarded-Email - New User: should return 200 and create user', async () => {
        const response = await request(server)
            .get(PROTECTED_ROUTE)
            .set('X-Forwarded-Email', NEW_USER_EMAIL)

        expect(response.status).toBe(200) // Or appropriate success code for the route
        expect(flowiseUserService.findOrCreateUserByEmail).toHaveBeenCalledWith(NEW_USER_EMAIL)
        // Check req.user (this requires the route handler to expose it or test its effects)
        // For now, we assume the middleware correctly populates it based on service call.
        // If the protected route returns the user, we can check:
        // expect(response.body.user.email).toBe(NEW_USER_EMAIL);
        // expect(response.body.user.isAuthenticatedByHeader).toBe(true);
    })

    // Test Case 2: X-Forwarded-Email Authentication - Existing User
    test('2. X-Forwarded-Email - Existing User: should return 200 and find user', async () => {
        const response = await request(server)
            .get(PROTECTED_ROUTE)
            .set('X-Forwarded-Email', EXISTING_USER_EMAIL)

        expect(response.status).toBe(200)
        expect(flowiseUserService.findOrCreateUserByEmail).toHaveBeenCalledWith(EXISTING_USER_EMAIL)
    })

    // Test Case 3: No Authentication - Protected Route
    test('3. No Authentication - Protected Route: should return 401', async () => {
        const response = await request(server).get(PROTECTED_ROUTE)

        expect(response.status).toBe(401)
        expect(response.body.error).toContain('Missing or Invalid API Key') // Or the specific error from the middleware
    })

    // Test Case 4: API Key Authentication - Valid Key
    test('4. API Key Auth - Valid Key: should return 200', async () => {
        ;(validateKey.validateAPIKey as jest.Mock).mockResolvedValue(true)
        ;(validateKey.getAPIKeyWorkspaceID as jest.Mock).mockResolvedValue(MOCK_WORKSPACE_ID)

        const response = await request(server)
            .get(PROTECTED_ROUTE)
            .set('Authorization', `Bearer ${VALID_API_KEY}`)

        expect(response.status).toBe(200)
        expect(validateKey.validateAPIKey).toHaveBeenCalled()
        expect(validateKey.getAPIKeyWorkspaceID).toHaveBeenCalled()
        expect(flowiseUserService.findOrCreateUserByEmail).not.toHaveBeenCalled()
    })

    // Test Case 5: X-Forwarded-Email Takes Precedence over API Key
    test('5. X-Forwarded-Email takes precedence: should use email, ignore API key', async () => {
        ;(validateKey.validateAPIKey as jest.Mock).mockResolvedValue(true) // Mock API key as valid

        const response = await request(server)
            .get(PROTECTED_ROUTE)
            .set('X-Forwarded-Email', EXISTING_USER_EMAIL)
            .set('Authorization', `Bearer ${VALID_API_KEY}`)

        expect(response.status).toBe(200)
        expect(flowiseUserService.findOrCreateUserByEmail).toHaveBeenCalledWith(EXISTING_USER_EMAIL)
        expect(validateKey.validateAPIKey).not.toHaveBeenCalled()
    })

    // Test Case 6: Whitelisted Route - No Authentication
    test('6. Whitelisted Route - No Auth: should return 200', async () => {
        const response = await request(server).get(WHITELISTED_ROUTE)

        expect(response.status).toBe(200) // Or success code for this route
        expect(flowiseUserService.findOrCreateUserByEmail).not.toHaveBeenCalled()
        expect(validateKey.validateAPIKey).not.toHaveBeenCalled()
    })

    // Additional test for Enterprise: License check if X-Forwarded-Email is not present
    test('7. Enterprise - Invalid License - No X-Forwarded-Email: should return 401', async () => {
        const mockIdentityManagerInstance = IdentityManager.getInstance() as jest.Mocked<IdentityManager>
        mockIdentityManagerInstance.getPlatformType.mockReturnValue(Platform.ENTERPRISE) // Simulate Enterprise
        mockIdentityManagerInstance.isLicenseValid.mockReturnValue(false) // Simulate invalid license

        // No X-Forwarded-Email, API key validation will be attempted after license check
        const response = await request(server).get(PROTECTED_ROUTE)

        expect(response.status).toBe(401)
        expect(response.body.error).toContain('Invalid License')
        expect(flowiseUserService.findOrCreateUserByEmail).not.toHaveBeenCalled()
        expect(validateKey.validateAPIKey).not.toHaveBeenCalled() // Should fail before API key check
    })
})
