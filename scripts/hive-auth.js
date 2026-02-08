/**
 * Friend`S - Hive Authentication Module
 * @version 1.0.0
 * @description Módulo completo de autenticación con Hive y Hive Keychain
 */

const hiveAuth = (function() {
    'use strict';

    // Configuration
    const CONFIG = {
        HIVE_API_NODES: [
            'https://api.hive.blog',
            'https://api.hivekings.com',
            'https://anyx.io',
            'https://api.pharesim.me'
        ],
        HIVE_ACCOUNT_CREATION: 'https://signup.hive.io/',
        KEYCHAIN_CHROME: 'https://chrome.google.com/webstore/detail/hive-keychain/jcacnejopjdphbnjgfaaobbfafkihpep',
        KEYCHAIN_FIREFOX: 'https://addons.mozilla.org/en-US/firefox/addon/hive-keychain/',
        APP_NAME: 'Friend`S',
        APP_VERSION: '1.0.0',
        SESSION_DURATION: 7 * 24 * 60 * 60 * 1000, // 7 days in milliseconds
        MAX_LOGIN_ATTEMPTS: 5,
        LOGIN_TIMEOUT: 30000, // 30 seconds
        MIN_USERNAME_LENGTH: 3,
        MAX_USERNAME_LENGTH: 16
    };

    // State
    let state = {
        currentUser: null,
        sessionExpiry: null,
        loginAttempts: 0,
        isKeychainInstalled: false,
        isKeychainConnected: false,
        hiveNodes: CONFIG.HIVE_API_NODES,
        currentNodeIndex: 0,
        lastActivity: null
    };

    // Event system
    const events = {};
    
    /**
     * Initialize the Hive authentication module
     */
    function init() {
        try {
            checkKeychainInstallation();
            loadSession();
            checkSession();
            setupEventListeners();
            
            console.log(` Friend\`S Hive Auth v${CONFIG.APP_VERSION} initialized`);
            return true;
        } catch (error) {
            console.error('Error initializing Hive Auth:', error);
            return false;
        }
    }

    /**
     * Check if Hive Keychain is installed
     */
    function checkKeychainInstallation() {
        try {
            state.isKeychainInstalled = typeof window.hive_keychain !== 'undefined';
            
            if (state.isKeychainInstalled) {
                console.log(' Hive Keychain detected');
                
                // Check if Keychain is connected
                if (typeof window.hive_keychain.requestHandshake === 'function') {
                    window.hive_keychain.requestHandshake((response) => {
                        if (response && response.success) {
                            state.isKeychainConnected = true;
                            console.log('🔗 Hive Keychain connected');
                            dispatchEvent('hive:keychain-connected', {});
                        }
                    });
                }
            } else {
                console.log(' Hive Keychain not detected');
            }
        } catch (error) {
            console.error('Error checking Keychain installation:', error);
            state.isKeychainInstalled = false;
            state.isKeychainConnected = false;
        }
    }

    /**
     * Load session from localStorage
     * @returns {boolean} True if session was loaded successfully
     */
    function loadSession() {
        try {
            const sessionData = localStorage.getItem('friend_s_hive_session');
            if (sessionData) {
                const session = JSON.parse(sessionData);
                
                // Check if session is still valid
                if (session.expiry && new Date(session.expiry) > new Date()) {
                    state.currentUser = session.user;
                    state.sessionExpiry = new Date(session.expiry);
                    state.lastActivity = new Date(session.lastActivity || Date.now());
                    console.log(` Session loaded for @${session.user.username}`);
                    
                    dispatchEvent('hive:session-loaded', { user: session.user });
                    return true;
                } else {
                    // Session expired, clear it
                    clearSession();
                    dispatchEvent('hive:session-expired', {});
                }
            }
        } catch (error) {
            console.error('Error loading session:', error);
            clearSession();
        }
        return false;
    }

    /**
     * Save session to localStorage
     * @param {Object} userData - User data to save
     * @returns {boolean} True if session was saved successfully
     */
    function saveSession(userData) {
        try {
            const session = {
                user: userData,
                expiry: new Date(Date.now() + CONFIG.SESSION_DURATION).toISOString(),
                created: new Date().toISOString(),
                lastActivity: new Date().toISOString()
            };
            
            localStorage.setItem('friend_s_hive_session', JSON.stringify(session));
            state.currentUser = userData;
            state.sessionExpiry = new Date(session.expiry);
            state.lastActivity = new Date();
            
            console.log(` Session saved for @${userData.username}`);
            dispatchEvent('hive:session-saved', { user: userData });
            return true;
        } catch (error) {
            console.error('Error saving session:', error);
            dispatchEvent('hive:session-error', { error: error.message });
            return false;
        }
    }

    /**
     * Update session activity timestamp
     */
    function updateSessionActivity() {
        if (state.currentUser) {
            try {
                const sessionData = localStorage.getItem('friend_s_hive_session');
                if (sessionData) {
                    const session = JSON.parse(sessionData);
                    session.lastActivity = new Date().toISOString();
                    localStorage.setItem('friend_s_hive_session', JSON.stringify(session));
                    state.lastActivity = new Date();
                }
            } catch (error) {
                console.error('Error updating session activity:', error);
            }
        }
    }

    /**
     * Clear session data
     */
    function clearSession() {
        const previousUser = state.currentUser;
        
        localStorage.removeItem('friend_s_hive_session');
        state.currentUser = null;
        state.sessionExpiry = null;
        state.lastActivity = null;
        
        console.log('🧹 Session cleared');
        dispatchEvent('hive:session-cleared', { previousUser });
    }

    /**
     * Check if session is valid
     * @returns {boolean} True if session is valid
     */
    function checkSession() {
        try {
            if (state.sessionExpiry && new Date() > state.sessionExpiry) {
                console.log(' Session expired');
                clearSession();
                dispatchEvent('hive:session-expired', {});
                return false;
            }
            
            // Update activity if user is active
            if (state.currentUser && state.lastActivity) {
                const inactiveTime = Date.now() - state.lastActivity.getTime();
                if (inactiveTime > 30 * 60 * 1000) { // 30 minutes
                    updateSessionActivity();
                }
            }
            
            return state.currentUser !== null;
        } catch (error) {
            console.error('Error checking session:', error);
            return false;
        }
    }

    /**
     * Get current authenticated user
     * @returns {Object|null} Current user data or null
     */
    function getCurrentUser() {
        return state.currentUser;
    }

    /**
     * Check if user is authenticated
     * @returns {boolean} True if user is authenticated
     */
    function isAuthenticated() {
        return checkSession();
    }

    /**
     * Login with Hive credentials
     * @param {string} username - Hive username
     * @param {string} postingKey - Posting key
     * @returns {Promise<Object>} User data
     */
    async function loginWithHive(username, postingKey) {
        return new Promise(async (resolve, reject) => {
            try {
                // Validate input
                if (!username || !postingKey) {
                    reject(new Error('Username and posting key are required'));
                    return;
                }

                // Validate username format
                if (!isValidHiveUsername(username)) {
                    reject(new Error('Invalid Hive username format'));
                    return;
                }

                // Check login attempts
                if (state.loginAttempts >= CONFIG.MAX_LOGIN_ATTEMPTS) {
                    reject(new Error('Too many login attempts. Please try again later.'));
                    return;
                }

                state.loginAttempts++;

                // Get account info first to verify user exists
                const accountInfo = await getAccountInfo(username);
                if (!accountInfo) {
                    reject(new Error('Hive account not found'));
                    return;
                }

                // Note: In production, you would verify the posting key properly
                // For demo purposes, we accept any non-empty posting key
                
                // Get user profile data
                const userProfile = await getUserProfile(username);
                
                // Generate session token
                const authToken = generateAuthToken(username);
                
                // Create user data object
                const userData = {
                    username: username,
                    profile: userProfile,
                    account: accountInfo,
                    authToken: authToken,
                    lastLogin: new Date().toISOString(),
                    loginMethod: 'hive',
                    permissions: ['posting']
                };

                // Save session
                if (saveSession(userData)) {
                    state.loginAttempts = 0; // Reset attempts on successful login
                    
                    // Dispatch login event
                    dispatchEvent('hive:login', { user: userData, method: 'hive' });
                    
                    resolve(userData);
                } else {
                    reject(new Error('Failed to create session'));
                }

            } catch (error) {
                console.error('Login error:', error);
                
                // Dispatch error event
                dispatchEvent('hive:login-error', { 
                    error: error.message, 
                    method: 'hive',
                    username: username 
                });
                
                reject(error);
            }
        });
    }

    /**
     * Login with Hive Keychain
     * @returns {Promise<Object>} User data
     */
    async function loginWithKeychain() {
        return new Promise((resolve, reject) => {
            try {
                // Check if Keychain is installed
                if (!state.isKeychainInstalled) {
                    reject(new Error('HIVE_KEYCHAIN_NOT_INSTALLED'));
                    return;
                }

                // Request login via Keychain
                window.hive_keychain.requestSignBuffer(
                    '', // Empty username to prompt for selection
                    `Login to ${CONFIG.APP_NAME} at ${new Date().toISOString()}`,
                    'Posting',
                    async (response) => {
                        if (response && response.success) {
                            const username = response.data.username;
                            
                            try {
                                // Verify the user exists
                                const accountInfo = await getAccountInfo(username);
                                if (!accountInfo) {
                                    reject(new Error('Hive account not found'));
                                    return;
                                }

                                // Get user profile
                                const userProfile = await getUserProfile(username);
                                
                                // Generate session token
                                const authToken = generateAuthToken(username);
                                
                                // Create user data object
                                const userData = {
                                    username: username,
                                    profile: userProfile,
                                    account: accountInfo,
                                    authToken: authToken,
                                    lastLogin: new Date().toISOString(),
                                    loginMethod: 'keychain',
                                    publicKey: response.data.publicKey,
                                    permissions: ['posting']
                                };

                                // Save session
                                if (saveSession(userData)) {
                                    // Dispatch login event
                                    dispatchEvent('hive:login', { user: userData, method: 'keychain' });
                                    dispatchEvent('hive:keychain-login', { user: userData });
                                    
                                    resolve(userData);
                                } else {
                                    reject(new Error('Failed to create session'));
                                }
                            } catch (error) {
                                console.error('Keychain login verification error:', error);
                                
                                dispatchEvent('hive:keychain-error', { 
                                    error: error.message,
                                    username: username 
                                });
                                
                                reject(error);
                            }
                        } else {
                            const errorMsg = response ? response.error : 'Keychain login failed';
                            dispatchEvent('hive:keychain-error', { error: errorMsg });
                            reject(new Error(errorMsg));
                        }
                    }
                );

            } catch (error) {
                console.error('Keychain login error:', error);
                
                // Dispatch error event
                dispatchEvent('hive:keychain-error', { error: error.message });
                
                reject(error);
            }
        });
    }

    /**
     * Simple login - just username (for demo/testing)
     * @param {string} username - Hive username
     * @returns {Promise<Object>} User data
     */
    async function simpleLogin(username) {
        return new Promise(async (resolve, reject) => {
            try {
                if (!username) {
                    reject(new Error('Username is required'));
                    return;
                }

                // Validate username format
                if (!isValidHiveUsername(username)) {
                    reject(new Error('Invalid Hive username format'));
                    return;
                }

                // Get account info
                const accountInfo = await getAccountInfo(username);
                if (!accountInfo) {
                    reject(new Error('Hive account not found'));
                    return;
                }

                // Get user profile
                const userProfile = await getUserProfile(username);
                
                // Generate session token
                const authToken = generateAuthToken(username);
                
                // Create user data object
                const userData = {
                    username: username,
                    profile: userProfile,
                    account: accountInfo,
                    authToken: authToken,
                    lastLogin: new Date().toISOString(),
                    loginMethod: 'simple',
                    permissions: ['posting']
                };

                // Save session
                if (saveSession(userData)) {
                    // Dispatch login event
                    dispatchEvent('hive:login', { user: userData, method: 'simple' });
                    
                    resolve(userData);
                } else {
                    reject(new Error('Failed to create session'));
                }

            } catch (error) {
                console.error('Simple login error:', error);
                reject(error);
            }
        });
    }

    /**
     * Logout current user
     * @returns {boolean} True if logout was successful
     */
    function logout() {
        if (!state.currentUser) {
            return false;
        }
        
        const user = state.currentUser;
        clearSession();
        
        // Dispatch logout event
        dispatchEvent('hive:logout', { user: user });
        
        console.log(` User @${user.username} logged out`);
        return true;
    }

    /**
     * Get account info from Hive blockchain
     * @param {string} username - Hive username
     * @returns {Promise<Object|null>} Account information
     */
    async function getAccountInfo(username) {
        try {
            const response = await callHiveApi('condenser_api.get_accounts', [[username]]);
            
            if (response && response.length > 0) {
                const account = response[0];
                
                // Parse metadata safely
                let metadata = {};
                if (account.json_metadata) {
                    try {
                        metadata = JSON.parse(account.json_metadata);
                    } catch (e) {
                        console.warn('Failed to parse JSON metadata for', username);
                    }
                }
                
                return {
                    name: account.name,
                    created: account.created,
                    reputation: calculateReputation(account.reputation),
                    posting: {
                        weight_threshold: account.posting.weight_threshold,
                        account_auths: account.posting.account_auths,
                        key_auths: account.posting.key_auths
                    },
                    balance: {
                        hive: account.balance || '0.000 HIVE',
                        hbd: account.hbd_balance || '0.000 HBD',
                        vesting: account.vesting_shares || '0.000000 VESTS',
                        savings_hive: account.savings_balance || '0.000 HIVE',
                        savings_hbd: account.savings_hbd_balance || '0.000 HBD'
                    },
                    metadata: metadata,
                    last_post: account.last_post || account.last_root_post || '',
                    last_vote_time: account.last_vote_time || '',
                    post_count: account.post_count || 0,
                    voting_power: account.voting_power || 0,
                    downvote_mana: account.downvote_mana || 0,
                    rc_mana: account.rc_mana || 0,
                    witness_votes: account.witness_votes || []
                };
            }
            return null;
        } catch (error) {
            console.error('Error getting account info for', username, ':', error);
            return null;
        }
    }

    /**
     * Get user profile from metadata
     * @param {string} username - Hive username
     * @returns {Promise<Object>} User profile
     */
    async function getUserProfile(username) {
        try {
            const accountInfo = await getAccountInfo(username);
            
            if (accountInfo && accountInfo.metadata) {
                const metadata = accountInfo.metadata;
                const profile = metadata.profile || {};
                
                return {
                    name: profile.name || username,
                    about: profile.about || '',
                    location: profile.location || '',
                    website: profile.website || '',
                    avatar: profile.profile_image || `https://images.hive.blog/u/${username}/avatar`,
                    cover: profile.cover_image || '',
                    joined: accountInfo.created,
                    reputation: accountInfo.reputation || 25,
                    verified: profile.verified || false,
                    pinned: profile.pinned || []
                };
            }
            
            return {
                name: username,
                about: '',
                reputation: accountInfo?.reputation || 25,
                avatar: `https://images.hive.blog/u/${username}/avatar`,
                joined: accountInfo?.created || new Date().toISOString()
            };
        } catch (error) {
            console.error('Error getting user profile for', username, ':', error);
            return {
                name: username,
                about: '',
                reputation: 25,
                avatar: `https://images.hive.blog/u/${username}/avatar`,
                joined: new Date().toISOString()
            };
        }
    }

    /**
     * Create new Hive account through Keychain
     * @param {string} referrer - Referrer account name
     * @param {string} newAccountName - New account name
     * @param {string} ownerKey - Owner public key
     * @param {string} activeKey - Active public key
     * @param {string} postingKey - Posting public key
     * @param {string} memoKey - Memo public key
     * @returns {Promise<Object>} Account creation result
     */
    async function createHiveAccount(referrer, newAccountName, ownerKey, activeKey, postingKey, memoKey) {
        return new Promise((resolve, reject) => {
            try {
                if (!state.isKeychainInstalled) {
                    reject(new Error('HIVE_KEYCHAIN_NOT_INSTALLED'));
                    return;
                }

                // Validate new account name
                if (!isValidHiveUsername(newAccountName)) {
                    reject(new Error('Invalid new account name format'));
                    return;
                }

                // Request account creation via Keychain
                window.hive_keychain.requestCreateAccount(
                    referrer,
                    newAccountName,
                    ownerKey,
                    activeKey,
                    postingKey,
                    memoKey,
                    'Account creation for Friend`S',
                    (response) => {
                        if (response && response.success) {
                            const result = {
                                success: true,
                                account: newAccountName,
                                transactionId: response.result.id,
                                blockNumber: response.result.block_num,
                                timestamp: new Date().toISOString()
                            };
                            
                            dispatchEvent('hive:account-created', result);
                            resolve(result);
                        } else {
                            const error = new Error(response ? response.error : 'Account creation failed');
                            dispatchEvent('hive:account-creation-error', { 
                                error: error.message,
                                account: newAccountName 
                            });
                            reject(error);
                        }
                    }
                );
            } catch (error) {
                console.error('Account creation error:', error);
                dispatchEvent('hive:account-creation-error', { 
                    error: error.message,
                    account: newAccountName 
                });
                reject(error);
            }
        });
    }

    /**
     * Verify posting authority with Keychain
     * @param {string} username - Hive username
     * @returns {Promise<boolean>} True if user has posting authority
     */
    async function verifyPostingAuthority(username) {
        return new Promise((resolve, reject) => {
            try {
                if (!state.isKeychainInstalled) {
                    resolve(false);
                    return;
                }

                window.hive_keychain.requestVerifyKey(
                    username,
                    '', // Empty key to check current
                    'Posting',
                    (response) => {
                        resolve(response ? response.success : false);
                    }
                );
            } catch (error) {
                console.error('Error verifying posting authority:', error);
                resolve(false);
            }
        });
    }

    /**
     * Generate authentication token
     * @param {string} username - Hive username
     * @returns {string} Authentication token
     */
    function generateAuthToken(username) {
        const timestamp = Date.now();
        const random = Math.random().toString(36).substring(2, 15);
        const data = `${username}:${timestamp}:${random}:${CONFIG.APP_NAME}`;
        
        // Create a simple hash
        let hash = 0;
        for (let i = 0; i < data.length; i++) {
            const char = data.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash;
        }
        
        return btoa(`${username}:${timestamp}:${Math.abs(hash)}`).replace(/=/g, '');
    }

    /**
     * Validate Hive username format
     * @param {string} username - Username to validate
     * @returns {boolean} True if username is valid
     */
    function isValidHiveUsername(username) {
        if (!username || typeof username !== 'string') {
            return false;
        }
        
        if (username.length < CONFIG.MIN_USERNAME_LENGTH || 
            username.length > CONFIG.MAX_USERNAME_LENGTH) {
            return false;
        }
        
        // Hive username regex: lowercase letters, digits, dots, hyphens
        // Must start with a letter
        const pattern = /^[a-z][a-z0-9\-.]*$/;
        
        if (!pattern.test(username)) {
            return false;
        }
        
        // Cannot end with a dot or hyphen
        if (username.endsWith('.') || username.endsWith('-')) {
            return false;
        }
        
        // Cannot have consecutive dots, hyphens, or dot-hyphen combinations
        if (username.includes('..') || username.includes('--') || 
            username.includes('.-') || username.includes('-.')) {
            return false;
        }
        
        return true;
    }

    /**
     * Calculate reputation score from raw reputation
     * @param {string|number} rawReputation - Raw reputation value
     * @returns {number} Calculated reputation score (1-99)
     */
    function calculateReputation(rawReputation) {
        if (!rawReputation) return 25;
        
        // Convert to number if it's a string
        let rep = parseInt(rawReputation);
        if (isNaN(rep)) return 25;
        
        if (rep === 0) return 25;
        
        // Hive reputation formula
        const score = Math.log10(Math.abs(rep));
        let reputationScore = rep < 0 ? -score : score;
        
        // Scale to 1-99 range
        reputationScore = Math.max(1, Math.min(99, Math.round(reputationScore * 9 + 25)));
        
        return reputationScore;
    }

    /**
     * Call Hive API with automatic failover
     * @param {string} method - API method to call
     * @param {Array} params - Method parameters
     * @returns {Promise<any>} API response
     */
    async function callHiveApi(method, params = []) {
        let lastError = null;
        
        for (let i = 0; i < state.hiveNodes.length; i++) {
            const nodeIndex = (state.currentNodeIndex + i) % state.hiveNodes.length;
            const node = state.hiveNodes[nodeIndex];
            
            try {
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), CONFIG.LOGIN_TIMEOUT);
                
                const response = await fetch(node, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Accept': 'application/json'
                    },
                    body: JSON.stringify({
                        jsonrpc: '2.0',
                        method: method,
                        params: params,
                        id: 1
                    }),
                    signal: controller.signal
                });
                
                clearTimeout(timeoutId);
                
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }
                
                const data = await response.json();
                
                if (data.error) {
                    throw new Error(data.error.message || `API error: ${JSON.stringify(data.error)}`);
                }
                
                // Success - update current node index
                state.currentNodeIndex = nodeIndex;
                return data.result;
                
            } catch (error) {
                lastError = error;
                
                if (error.name === 'AbortError') {
                    console.warn(`Node ${node} timeout`);
                } else {
                    console.warn(`Node ${node} failed:`, error.message);
                }
                
                continue;
            }
        }
        
        throw new Error(`All Hive nodes failed. Last error: ${lastError ? lastError.message : 'Unknown error'}`);
    }

    /**
     * Add event listener
     * @param {string} event - Event name
     * @param {Function} callback - Event handler
     */
    function on(event, callback) {
        if (!events[event]) {
            events[event] = [];
        }
        events[event].push(callback);
    }
    
    /**
     * Remove event listener
     * @param {string} event - Event name
     * @param {Function} callback - Event handler to remove
     */
    function off(event, callback) {
        if (!events[event]) return;
        const index = events[event].indexOf(callback);
        if (index > -1) {
            events[event].splice(index, 1);
        }
    }
    
    /**
     * Dispatch event to all listeners
     * @param {string} event - Event name
     * @param {Object} data - Event data
     */
    function dispatchEvent(event, data) {
        if (!events[event]) return;
        
        // Clone the array to avoid issues if listeners are added/removed during iteration
        const listeners = events[event].slice();
        
        listeners.forEach(callback => {
            try {
                callback(data);
            } catch (error) {
                console.error(`Error in ${event} event handler:`, error);
            }
        });
    }

    /**
     * Setup global event listeners
     */
    function setupEventListeners() {
        // Listen for Keychain installation
        if (!state.isKeychainInstalled) {
            const checkInterval = setInterval(() => {
                if (typeof window.hive_keychain !== 'undefined') {
                    clearInterval(checkInterval);
                    state.isKeychainInstalled = true;
                    dispatchEvent('hive:keychain-installed', {});
                    
                    // Now request handshake
                    if (typeof window.hive_keychain.requestHandshake === 'function') {
                        window.hive_keychain.requestHandshake((response) => {
                            if (response && response.success) {
                                state.isKeychainConnected = true;
                                dispatchEvent('hive:keychain-connected', {});
                            }
                        });
                    }
                }
            }, 1000);
        }

        // Listen for storage changes (other tabs)
        if (typeof window.addEventListener === 'function') {
            window.addEventListener('storage', (event) => {
                if (event.key === 'friend_s_hive_session') {
                    if (!event.newValue) {
                        // Session cleared in another tab
                        clearSession();
                        dispatchEvent('hive:session-cleared-external', {});
                    } else if (event.newValue !== event.oldValue) {
                        // Session updated in another tab
                        try {
                            const session = JSON.parse(event.newValue);
                            if (session.user && session.user.username !== (state.currentUser ? state.currentUser.username : null)) {
                                // Different user logged in another tab
                                clearSession();
                                dispatchEvent('hive:session-changed-external', { newUser: session.user });
                            }
                        } catch (error) {
                            console.error('Error parsing session from storage event:', error);
                        }
                    }
                }
            });

            // Update activity on user interaction
            const activityEvents = ['mousedown', 'keydown', 'touchstart', 'scroll'];
            activityEvents.forEach(eventName => {
                document.addEventListener(eventName, () => {
                    if (state.currentUser) {
                        updateSessionActivity();
                    }
                }, { passive: true });
            });

            // Save state before page unload
            window.addEventListener('beforeunload', () => {
                if (state.currentUser) {
                    updateSessionActivity();
                    dispatchEvent('hive:before-unload', { user: state.currentUser });
                }
            });
        }

        // Periodic session check
        if (typeof setInterval === 'function') {
            setInterval(() => {
                checkSession();
            }, 60 * 1000); // Check every minute
        }
    }

    /**
     * Get session time remaining in milliseconds
     * @returns {number} Time remaining in ms, or 0 if no session
     */
    function getSessionTimeRemaining() {
        if (!state.sessionExpiry) return 0;
        return state.sessionExpiry.getTime() - Date.now();
    }

    /**
     * Format session time remaining as human-readable string
     * @returns {string} Formatted time remaining
     */
    function getSessionTimeRemainingFormatted() {
        const ms = getSessionTimeRemaining();
        if (ms <= 0) return 'Expired';
        
        const days = Math.floor(ms / (1000 * 60 * 60 * 24));
        const hours = Math.floor((ms % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
        const minutes = Math.floor((ms % (1000 * 60 * 60)) / (1000 * 60));
        
        if (days > 0) return `${days}d ${hours}h`;
        if (hours > 0) return `${hours}h ${minutes}m`;
        return `${minutes}m`;
    }

    // Public API
    return {
        // Core functions
        init,
        loginWithHive,
        loginWithKeychain,
        simpleLogin,
        logout,
        getCurrentUser,
        isAuthenticated,
        createHiveAccount,
        
        // Session management
        clearSession,
        checkSession,
        getSessionTimeRemaining,
        getSessionTimeRemainingFormatted,
        updateSessionActivity,
        
        // Verification
        verifyPostingAuthority,
        isValidHiveUsername,
        
        // Data retrieval
        getAccountInfo,
        getUserProfile,
        
        // Keychain status
        isKeychainInstalled: () => state.isKeychainInstalled,
        isKeychainConnected: () => state.isKeychainConnected,
        
        // Configuration
        config: CONFIG,
        
        // Event system
        on,
        off,
        
        // For debugging and testing
        _state: () => ({ ...state }),
        _events: () => ({ ...events }),
        _test: {
            calculateReputation,
            generateAuthToken,
            callHiveApi
        }
    };
})();

// Auto-initialize when loaded in browser
if (typeof window !== 'undefined') {
    // Wait for DOM to be ready
    if (document.readyState === 'loading') {
        if (typeof document.addEventListener === 'function') {
            document.addEventListener('DOMContentLoaded', () => {
                if (typeof hiveAuth.init === 'function') {
                    hiveAuth.init();
                }
            });
        }
    } else {
        // DOM already loaded
        if (typeof hiveAuth.init === 'function') {
            hiveAuth.init();
        }
    }
}

// Export for Node.js/ES6 modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = hiveAuth;
}

// Export for AMD
if (typeof define === 'function' && define.amd) {
    define([], function() {
        return hiveAuth;
    });
}

// Global namespace (for browser)
if (typeof window !== 'undefined') {
    window.hiveAuth = hiveAuth;
}