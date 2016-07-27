'use strict'
let debug = require('debug')('koa-jwt-redis-session')

import redis from 'ioredis'
import JWT from 'jsonwebtoken'
import thunkify from 'thunkify'
import uid from 'uid2'
import co from 'co'

const DEBUG_LOG_HEADER = '[koa-jwt-redis-session]'
const EXPIRES_IN_SECONDS = 60 * 60

// Options
// JWT Options
let jwtOptions , contentType , charset, secret, authPath, registerPath, expiresIn, accountKey;
let passwordKey, authHandler, registerHandler, jwtOpt, refreshTokenPath;
// Session
let sessionKey, sidKey, sessOpt;
// Redis Options
let redisOptions, redisStore, store;

function parseOptions(opts) {
    // Options
    const options = opts || {}
    debug('Parsing options:', options);
    // JWT Options
    jwtOptions = options.jwt || {}
    contentType = jwtOptions.contentType || 'application/json'
    charset = jwtOptions.charset || 'utf-8'
    secret = jwtOptions.secret || 'koa-jwt-redis-session' + new Date().getTime()
    authPath = jwtOptions.authPath || '/authorize';
    registerPath = jwtOptions.registerPath || '/register';
    refreshTokenPath = jwtOptions.refreshTokenPath || '/refreshToken';
    expiresIn = jwtOptions.expiresIn || EXPIRES_IN_SECONDS;
    accountKey = jwtOptions.accountKey || 'account';
    passwordKey = jwtOptions.passwordKey || 'password';
    authHandler = jwtOptions.authHandler || function (account, password) {
            if (account && password) {
                let user = {};
                user[accountKey] = account;
                return user;
            }
            return false;
        }
    registerHandler = jwtOptions.registerHandler || function (account, password) {
            if (account && password) {
                let user = {};
                user[accountKey] = account;
                return user;
            }
            return false;
        }
    jwtOpt = {expiresIn};
    // Session
    let sessionOptions = options.session || {}
    sessionKey = sessionOptions.sessionKey || 'session';
    sidKey = sessionOptions.sidKey || 'koa:sess';
    sessOpt = {sidKey};
    // Redis Options
    redisOptions = options.redis || {}
    redisStore = new RedisStore(redisOptions);
    store = redisStore;
}

let createSession = async (ctx, user)=>{
    let sess = await Session.create(store, user, sessOpt);
    const token = await JWT.sign(user,secret,jwtOpt)
    ctx[sessionKey] = sess;
    debug('Generated token:', token)
    return {token, expiresIn};
}

let authoriseRequest = async (ctx) => {
    //if(ctx.header.authorization){
    if(ctx && ctx.header && ctx.header.authorization) {
        const authComponents = ctx.header.authorization.split(' ');
        if (authComponents.length === 2 && authComponents[0] === 'Bearer') {
            let user = await JWT.verify(authComponents[1], secret, jwtOpt)
            return user;
        }
    }
    return null;
}

function middleware(opts) {
    parseOptions(opts);

    // Utilities
    function sendToken(ctx, token){
        if(contentType.toLowerCase() === 'application/json')
            ctx.body = token;
        else ctx.body = token.token;
    }

    // Authorization by JWT
    return async function (ctx, next) {
        try {
            ctx.type = contentType + ';' + 'charset=' + charset;
            if (ctx.path === refreshTokenPath && ctx.method.toUpperCase() === 'POST'
            ) {
                let user = await authoriseRequest(ctx);
                if(user){
                    delete user.iat, user.exp;
                    let token = await createSession(ctx, user);
                    debug('Refreshed token:', token, 'user:', user)
                    sendToken(ctx, token);
                }else{
                    // ctx.body= 'Authorization failed';
                    ctx.status = 401;
                }
            // SignIn
            }else if (ctx.path === authPath && ctx.method.toUpperCase() === 'POST'
                && ctx.request.body[accountKey] && ctx.request.body[passwordKey]
            ) {
                const account = ctx.request.body[accountKey];
                const password = ctx.request.body[passwordKey];
                debug('checking authorization:', account, password);
                let user = await authHandler(account, password);
                if( (typeof user === 'boolean'  && user ) || 
                    Object.prototype.toString.call(user).toLowerCase() === "[object object]"){
                    let userObj;
                    if(typeof user === 'boolean'){
                        userObj = {};
                        userObj[accountKey] = account;
                    }else userObj = user;
                    let token = await createSession(ctx, userObj)
                    sendToken(ctx, token);
                }else{
                    // ctx.body= 'Authorization failed';
                    ctx.status = 401;
                }
            // Register
            } else if (ctx.path === registerPath && ctx.method.toUpperCase() === 'POST'
                && ctx.request.body[accountKey] && ctx.request.body[passwordKey]
            ) {
                const account = ctx.request.body[accountKey];
                const password = ctx.request.body[passwordKey];

                let user = await registerHandler(account, password);
                if( (typeof user === 'boolean'  && user ) || 
                    Object.prototype.toString.call(user).toLowerCase() === "[object object]"
                    ){
                    let userObj;
                    if(typeof user === 'boolean'){
                        userObj = {};
                        userObj[accountKey] = account;
                    }else userObj = user;
                    let token = await createSession(ctx, userObj)
                    sendToken(ctx, token);
                }else{
                    // ctx.body= 'Authorization failed';
                    ctx.status = 401;
                }
            }else {
                let user = await authoriseRequest(ctx)
                if(user){
                    debug('Authorized user:', user)
                    ctx[sessionKey] = await Session.create(store, user, sessOpt);
                    await next();
                    if(ctx[sessionKey] == undefined || ctx[sessionKey] === false){
                        // session is destroyed in the business
                    }else{
                        await ctx[sessionKey].save(store);
                    }
                }
            }
        } catch (ex) {
            if(ex.name !== 'UnauthorizedError' || ex.name !== 'JsonWebTokenError' ) {
                debug(DEBUG_LOG_HEADER, '[ERROR] catch something wrong:', ex)
                ctx.status = 500;
                if (ex.message && !ctx.body) ctx.body = ex.message;
            }else{
                ctx.status = 401;
            }
        }
    };
}
export default middleware;
export {createSession, authoriseRequest};

// Session Model
class Session {
    constructor (obj) {
        if (!obj) this.isNew = true;
        else for (var k in obj) this[k] = obj[k];
    }

    /**
    * JSON representation of the session.
    *
    * @return {Object}
    * @api public
    */
    get json() {
        var self = this;
        var obj = {};

        Object.keys(this).forEach(function (key) {
            if ('isNew' === key) return;
            if ('_' === key[0]) return;
            obj[key] = self[key];
        });

        return obj;
    }

    get string () {
        return this._json || JSON.stringify(this.json)
    }

    /**
     * Check if the session has changed relative to the `prev`
     * JSON value from the request.
     *
     * @param {String} [prev]
     * @return {Boolean}
     * @api private
     */
    changed (prev) {
        if (!prev) return true;
        this._json = JSON.stringify(this);
        return this._json !== prev;
    }

    /**
     * Return how many values there are in the session object.
     * Used to see if it's "populated".
     *
     * @return {Number}
     * @api public
     */
    get length  (){
        return Object.keys(this.toJSON()).length;
    }


    /**
     * populated flag, which is just a boolean alias of .length.
     *
     * @return {Boolean}
     * @api public
     */
    get populated (){
        return !!this.length;
    }

    static generateSessionId (header){
        if(!header){
            return uid(24);
        }else{
            return header+":"+uid(24);
        }
    }

    /**
     * Create a session instance
     * @param store
     * @param user
     */
    static async create(store, user, opts){
        let instance = user || {};
        let options = opts || {
                sidKey: 'sid'
            };
        debug('User for creating session:', instance);
        debug('Session options for creating session:', opts);
        if(!instance[options.sidKey]) {
            debug('Creating session');
            // Creating
            let sid = Session.generateSessionId(options.sidKey);
            while (await store.exists(sid)){
                debug('sid', sid, 'exists');
                sid = Session.generateSessionId(options.sidKey);
            }
            debug('new sid:', sid);
            user[options.sidKey] = sid;
            instance[options.sidKey] = sid;
            let session = new Session(instance);
            session._sessionId = sid;
            await session.save(store);
            return session;
        }else{
            debug('Loading session, sid:',instance[options.sidKey])
            // loading
            instance = await store.get(instance[options.sidKey]);
            instance._sessionId = instance[options.sidKey];
            let session = new Session(instance);
            debug('loaded session:', session.json)
            return session;
        }
    }

    async save(store) {
        if(!store) return;
        if(store.type === 'redis'){
            await store.set(this._sessionId, this.json);
        }
    }
}

// Store Base Class
class Store {
    constructor(opts){
    }
    async exists(key){
        let exists = true;
        if(this.type === 'redis') {
            if (!key || !this.client || !this.client.exists) return exists;
            const client = this.client;
            try {
                return await co(function*() {
                    return yield client.exists(key);
                })
            }catch (ex){
                // under some condition, it may not support exists command, wield
                debug('Error when trying invoke "exists" of redis driver:', ex);
                let value = await co(function*(){
                    return yield client.get(key);
                })
                if(value) return true;
                else return false;
            }
        }else{
            return exists;
        }
    }

    async set(key, value){
        if(this.type === 'redis'){
            if(!key || !this.client || !this.client.set) return;
            let storedValue = (typeof value === 'object') ? JSON.stringify(value): value;
            await this.client.set(key, storedValue);
            await this.client.ttl(key)
        }
    }

    async get(key){
        if(this.type === 'redis'){
            if(!key || !this.client || !this.client.get) return null;
            const client = this.client;
            let value = await co(function*(){
                return yield client.get(key);
            })
            if(value && typeof value === 'string') return JSON.parse(value);
            else return value;
        }
    }
}

// Redis store
class RedisStore extends  Store{
    constructor (opts){
        super(opts)
        this.type = 'redis'
        let redisOptions = opts || {}
        debug('Redis options:', redisOptions);

        const db = redisOptions.db || 0
        const ttl = this.ttl = redisOptions.ttl || expiresIn || EXPIRES_IN_SECONDS

        //redis client for session
        this.client = new redis(redisOptions)

        const client = this.client;

        client.select(db, function () {
            debug('redis changed to db %d', db);
        });

        client.get = thunkify(client.get);
        client.exists = thunkify(client.exists);
        client.ttl = ttl ? (key)=>{ client.expire(key, ttl); } : ()=>{};

        client.on('connect', function () {
            debug('redis is connecting');
        });

        client.on('ready', function () {
            debug('redis ready');
        });

        client.on('reconnect', function () {
            debug('redis is reconnecting');
        });

        client.on('error', function (err) {
            debug('redis encouters error: %j', err.stack || err);
        });

        client.on('end', function () {
            debug('redis connection ended');
        });
    }
}
