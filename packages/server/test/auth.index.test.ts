import request from 'supertest'
import { Server } from 'http'
import { App, getInstance, start } from '../src/index'
import flowiseUserService from '../src/services/flowise-user'
// import * as validateKey from '../src/utils/validateKey' // No longer needed
import { getDataSource } from '../src/DataSource'
// import { Platform } from '../src/Interface' // No longer needed
import { IdentityManager } from '../src/IdentityManager'
// import { Workspace } from '../src/enterprise/database/entities/workspace.entity' // No longer needed
// import { Organization } from '../src/enterprise/database/entities/organization.entity' // No longer needed
// import { GeneralRole, Role } from '../src/enterprise/database/entities/role.entity' // No longer needed
import { DataSource } from 'typeorm' // IsNull no longer needed

// Mock actual services and utilities
jest.mock('../src/services/flowise-user')
// jest.mock('../src/utils/validateKey') // No longer needed as API key logic is removed from middleware
jest.mock('../src/IdentityManager')

// Constants for test users
const NEW_USER_EMAIL = 'new.user@example.com'
const EXISTING_USER_EMAIL = 'existing.user@example.com'
const MOCK_USER_ID = 'mock-user-id'
// const MOCK_WORKSPACE_ID = 'mock-workspace-id' // No longer needed
// const VALID_API_KEY = 'valid-api-key' // No longer needed

const PROTECTED_ROUTE = '/api/v1/chatflows' 
const WHITELISTED_ROUTE = '/api/v1/marketplaces/chatflows'

describe('Authentication Middleware Tests (Simplified)', () => {
    let appInstance: App
    let server: Server
    let dataSource: DataSource

    beforeAll(async () => {
        // Minimal Mock for IdentityManager - for app initialization if needed
        const mockIdentityManagerInstance = {
            initializeSSO: jest.fn().mockResolvedValue(undefined),
            // Add other methods if start() or other parts of app setup call them
            getPlatformType: jest.fn().mockReturnValue('OPEN_SOURCE'), // Mock basic platform type if needed by other init logic
            isLicenseValid: jest.fn().mockReturnValue(true) // Mock basic license validity if needed
        }
        ;(IdentityManager.getInstance as jest.Mock).mockResolvedValue(mockIdentityManagerInstance)

        // Start the server
        await start() 
        appInstance = getInstance()!
        server = appInstance.app.listen() 
        dataSource = getDataSource()

        // Remove TypeORM repository mocks for Workspace, Role, Organization
        // The original spy might still be needed if other parts of start() use getRepository
        // For simplicity, if getRepository is only used by the removed logic, this can be removed.
        // Assuming other parts of the app might still call getRepository, keep a generic spy.
        const originalGetRepository = dataSource.getRepository
        // @ts-ignore
        jest.spyOn(dataSource, 'getRepository').mockImplementation((entity: any) => {
            // Return a default mock for any other entity if needed by app startup
            return {
                findOne: jest.fn(),
                findOneBy: jest.fn(),
                save: jest.fn(),
                // Add other repository methods if called during startup for unrelated entities
            } as any; // Use 'as any' to simplify generic mocking
        });
        // If specific entities are still needed for app init, mock them, otherwise the generic one handles it.
    })

    afterAll(async () => {
        if (server) {
            server.close()
        }
        if (dataSource && dataSource.isInitialized) {
            await dataSource.destroy()
        }
        jest.restoreAllMocks() 
    })

    beforeEach(() => {
        jest.clearAllMocks()

        ;(flowiseUserService.findOrCreateUserByEmail as jest.Mock).mockImplementation(async (email: string) => {
            if (email === NEW_USER_EMAIL) {
                return { id: MOCK_USER_ID, email, createdDate: new Date(), updatedDate: new Date() }
            }
            if (email === EXISTING_USER_EMAIL) {
                return { id: 'existing-user-id', email, createdDate: new Date(), updatedDate: new Date() }
            }
            return null
        })
        // Removed mocks for validateKey and getAPIKeyWorkspaceID
        // Removed IdentityManager mocks for getPlatformType and isLicenseValid specific to tests
    })

    test('1. X-Forwarded-Email - New User: should allow access and call findOrCreateUserByEmail', async () => {
        const response = await request(server)
            .get(PROTECTED_ROUTE)
            .set('X-Forwarded-Email', NEW_USER_EMAIL)

        // Assuming the protected route returns 200 on successful authentication.
        expect(response.status).toBe(200) 
        expect(flowiseUserService.findOrCreateUserByEmail).toHaveBeenCalledWith(NEW_USER_EMAIL)
        // Based on the middleware changes, req.user would be populated as follows:
        // const expectedUserShape = {
        //     id: MOCK_USER_ID,
        //     email: NEW_USER_EMAIL,
        //     isAuthenticatedByHeader: true,
        //     name: NEW_USER_EMAIL, 
        //     roleId: '', 
        //     activeOrganizationId: '', 
        //     activeOrganizationSubscriptionId: '',
        //     activeOrganizationCustomerId: '',
        //     activeOrganizationProductId: '',
        //     isOrganizationAdmin: false, 
        //     activeWorkspaceId: '', 
        //     activeWorkspace: '', 
        //     assignedWorkspaces: [], 
        //     isApiKeyValidated: false, 
        //     permissions: [], 
        //     features: {}, 
        //     ssoRefreshToken: undefined, 
        //     ssoToken: undefined, 
        //     ssoProvider: undefined 
        // };
        // Direct assertion of req.user is not feasible here without modifying the endpoint
        // or test setup to expose req.user.
    })

    test('2. X-Forwarded-Email - Existing User: should allow access and call findOrCreateUserByEmail', async () => {
        const response = await request(server)
            .get(PROTECTED_ROUTE)
            .set('X-Forwarded-Email', EXISTING_USER_EMAIL)

        expect(response.status).toBe(200)
        expect(flowiseUserService.findOrCreateUserByEmail).toHaveBeenCalledWith(EXISTING_USER_EMAIL)
        // Based on the middleware changes, req.user would be populated similarly to the new user case,
        // but with id: 'existing-user-id' and email: EXISTING_USER_EMAIL.
        // const expectedUserShape = {
        //     id: 'existing-user-id',
        //     email: EXISTING_USER_EMAIL,
        //     isAuthenticatedByHeader: true,
        //     name: EXISTING_USER_EMAIL,
        //     roleId: '', 
        //     // ... other LoggedInUser fields with default values
        // };
    })

    test('3. No Authentication - Protected Route: should return 401 with specific error', async () => {
        const response = await request(server).get(PROTECTED_ROUTE)

        expect(response.status).toBe(401)
        expect(response.body.error).toBe('Unauthorized: X-Forwarded-Email header is required')
    })

    // Test cases 4, 5, and 7 are removed as they relate to API Key or Enterprise features
    // now removed from the main authentication middleware.

    test('6. Whitelisted Route - No Auth: should allow access', async () => {
        const response = await request(server).get(WHITELISTED_ROUTE)

        expect(response.status).toBe(200) 
        expect(flowiseUserService.findOrCreateUserByEmail).not.toHaveBeenCalled()
    })
})
