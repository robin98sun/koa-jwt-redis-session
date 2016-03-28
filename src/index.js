'use strict'
let debug = require('debug')('koa-jwt-redis-session')

import redis from 'redis'
import JWT from 'jsonwebtoken'
import thunkify from 'thunkify'
import uid from 'uid2'
import co from 'co'

const DEBUG_LOG_HEADER = '[koa-jwt-redis-session]'
const EXPIRES_IN_SECONDS = 60 * 60

function middleware(opts) {
    // Options
    const options = opts || {}
    // JWT Options
    const jwtOptions = options.jwt || {}
    const contentType = jwtOptions.contentType || 'application/json'
    const charset = jwtOptions.charset || 'utf-8'
    const secret = jwtOptions.secret || 'koa-jwt-redis-session' + new Date().getTime()
    const authPath = jwtOptions.authPath || '/authorize';
    const registerPath = jwtOptions.registerPath || '/register';
    const expiresIn = jwtOptions.expiresIn || EXPIRES_IN_SECONDS;
    const accountKey = jwtOptions.accountKey || 'account';
    const passwordKey = jwtOptions.passwordKey || 'password';
    const authHandler = jwtOptions.authHandler || function (account, password) {
				if (account && password) {
					let user = {};
					user[accountKey] = account;
					user[passwordKey] = password;
					return user;
				}
				return false;
		}
    const registerHandler = jwtOptions.registerHandler || function (account, password) {
				if (account && password) {
					let user = {};
					user[accountKey] = account;
					user[passwordKey] = password;
					return user;
				}
				return false;
    }
    const jwtOpt = {expiresIn};
    // Session
    const sessionOptions = options.session || {}
    const sessionKey = sessionOptions.sessionKey || 'session';
    const sidKey = sessionOptions.sidKey || 'koa:sess';
    const sessOpt = {sidKey};
    // Redis Options
    const redisOptions = options.redis || {}
    const redisStore = new RedisStore(redisOptions);
    const store = redisStore;

    // Utilities
    function sendToken(ctx, token){
        if(contentType.toLowerCase() === 'application/json')
            ctx.body = {token};
        else ctx.body = token;
    }

    // Authorization by JWT
    return async function (ctx, next) {
        try {
            ctx.type = contentType + ';' + 'charset=' + charset;
            // SignIn
            if (ctx.path === authPath && ctx.method.toUpperCase() === 'POST'
                && ctx.request.body[accountKey] && ctx.request.body[passwordKey]
            ) {
                const account = ctx.request.body[accountKey];
                const password = ctx.request.body[passwordKey];
                debug('checking authorization:', account, password);
                let user = await authHandler(account, password);
                if(typeof(user) === "object"
                  && Object.prototype.toString.call(user).toLowerCase() === "[object object]"
                  && !user.length){
                    ctx[sessionKey] = await Session.create(store, user, sessOpt);
                    const token = await JWT.sign(user,secret,jwtOpt)
                    debug('Generated token:', token)
                    sendToken(ctx, token);
                }else{
                    ctx.throw(401, 'Authorization failed');
                }
            // Register
            } else if (ctx.path === registerPath && ctx.method.toUpperCase() === 'POST'
                && ctx.request.body[accountKey] && ctx.request.body[passwordKey]
            ) {
                const account = ctx.request.body[accountKey];
                const password = ctx.request.body[passwordKey];

                let user = await registerHandler(account, password);
                if( typeof(user) === "object"
                  && Object.prototype.toString.call(user).toLowerCase() === "[object object]"
                  && !user.length){
                    ctx[sessionKey] = await Session.create(store, user, sessOpt);
                    const token = await JWT.sign(user,secret,jwtOpt)
                    debug('Generated token:', token)
                    sendToken(ctx, token);
                }else{
                    ctx.throw(401, 'Register failed')
                }
            }else {
                if(ctx.header.authorization){
                    const authComponents = ctx.header.authorization.split(' ');
                    if(authComponents.length === 2 && authComponents[0] === 'Bearer'){
                        let user = JWT.verify(authComponents[1],secret,jwtOpt)
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
                }
            }
        } catch (ex) {
            console.error(DEBUG_LOG_HEADER, '[ERROR] catch something wrong:', ex)
            ctx.response.status = 401;
            if(ex.message) ctx.body = ex.message;
        }
    };
}
export default middleware;

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

    static generateSessionId (){
        return uid(24);
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
            }

        if(!instance[options.sidKey]) {
            debug('Creating session')
            // Creating
            let sid = Session.generateSessionId();
            while (await store.exists(sid)){
                debug('sid', sid, 'exists')
                sid = Session.generateSessionId();
            }
            debug('new sid:', sid)
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
            return await co(function*(){
                return yield  client.exists(key);
            })
        }else{
            return exists;
        }
    }

    async set(key, value){
        if(this.type === 'redis'){
            if(!key || !this.client || !this.client.set) return;
            let redisValue = (typeof value === 'object') ? JSON.stringify(value): value;
            await this.client.set(key, redisValue);
            await this.client.ttl(key)
        }
    }

    async get(key){
        if(this.type === 'redis'){
            if(!key || !this.client || !this.client.get) return null;
            const client = this.client;
            let redisValue = await co(function*(){
                return yield client.get(key);
            })
            if(redisValue && typeof redisValue === 'string') return JSON.parse(redisValue);
            else return redisValue;
        }
    }
}
// Redis store
class RedisStore extends  Store{
    constructor (opts){
        super(opts)
        this.type = 'redis'
        const redisOptions = opts || {}
        const port = this.port = redisOptions.port || 6379
        const host = this.host = redisOptions.host || '127.0.0.1'
        const db = this.db = redisOptions.db || 0
        const ttl = this.ttl = redisOptions.ttl || EXPIRES_IN_SECONDS
        const options = this.options = redisOptions.options || {}

        //redis client for session
        this.client = redis.createClient(
            port,
            host,
            options
        );

        const client = this.client;

        client.select(db, function () {
            debug('redis changed to db %d', db);
        });

        client.get = thunkify(client.get);
        client.exists = thunkify(client.exists);
        client.ttl = ttl ? function expire(key) { client.expire(key, ttl); }: function () {};

        client.on('connect', function () {
            debug('redis is connecting');
        });

        client.on('ready', function () {
            debug('redis ready');
            debug('redis host: %s', host);
            debug('redis port: %s', port);
            debug('redis parser: %s', client.reply_parser.name);
            debug('redis server info: %j', client.server_info);
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
