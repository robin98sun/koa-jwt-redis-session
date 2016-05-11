'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});
exports.createSession = undefined;

var _getPrototypeOf = require('babel-runtime/core-js/object/get-prototype-of');

var _getPrototypeOf2 = _interopRequireDefault(_getPrototypeOf);

var _possibleConstructorReturn2 = require('babel-runtime/helpers/possibleConstructorReturn');

var _possibleConstructorReturn3 = _interopRequireDefault(_possibleConstructorReturn2);

var _inherits2 = require('babel-runtime/helpers/inherits');

var _inherits3 = _interopRequireDefault(_inherits2);

var _typeof2 = require('babel-runtime/helpers/typeof');

var _typeof3 = _interopRequireDefault(_typeof2);

var _keys = require('babel-runtime/core-js/object/keys');

var _keys2 = _interopRequireDefault(_keys);

var _stringify = require('babel-runtime/core-js/json/stringify');

var _stringify2 = _interopRequireDefault(_stringify);

var _classCallCheck2 = require('babel-runtime/helpers/classCallCheck');

var _classCallCheck3 = _interopRequireDefault(_classCallCheck2);

var _createClass2 = require('babel-runtime/helpers/createClass');

var _createClass3 = _interopRequireDefault(_createClass2);

var _regenerator = require('babel-runtime/regenerator');

var _regenerator2 = _interopRequireDefault(_regenerator);

var _asyncToGenerator2 = require('babel-runtime/helpers/asyncToGenerator');

var _asyncToGenerator3 = _interopRequireDefault(_asyncToGenerator2);

var _redis = require('redis');

var _redis2 = _interopRequireDefault(_redis);

var _jsonwebtoken = require('jsonwebtoken');

var _jsonwebtoken2 = _interopRequireDefault(_jsonwebtoken);

var _thunkify = require('thunkify');

var _thunkify2 = _interopRequireDefault(_thunkify);

var _uid = require('uid2');

var _uid2 = _interopRequireDefault(_uid);

var _co = require('co');

var _co2 = _interopRequireDefault(_co);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

var debug = require('debug')('koa-jwt-redis-session');

var DEBUG_LOG_HEADER = '[koa-jwt-redis-session]';
var EXPIRES_IN_SECONDS = 60 * 60;

// Options
// JWT Options
var jwtOptions = void 0,
    contentType = void 0,
    charset = void 0,
    secret = void 0,
    authPath = void 0,
    registerPath = void 0,
    expiresIn = void 0,
    accountKey = void 0;
var passwordKey = void 0,
    authHandler = void 0,
    registerHandler = void 0,
    jwtOpt = void 0;
// Session
var sessionOptions = void 0,
    sessionKey = void 0,
    sidKey = void 0,
    sessOpt = void 0;
// Redis Options
var redisOptions = void 0,
    redisStore = void 0,
    store = void 0;

function parseOptions(opts) {
    // Options
    var options = opts || {};
    // JWT Options
    jwtOptions = options.jwt || {};
    contentType = jwtOptions.contentType || 'application/json';
    charset = jwtOptions.charset || 'utf-8';
    secret = jwtOptions.secret || 'koa-jwt-redis-session' + new Date().getTime();
    authPath = jwtOptions.authPath || '/authorize';
    registerPath = jwtOptions.registerPath || '/register';
    expiresIn = jwtOptions.expiresIn || EXPIRES_IN_SECONDS;
    accountKey = jwtOptions.accountKey || 'account';
    passwordKey = jwtOptions.passwordKey || 'password';
    authHandler = jwtOptions.authHandler || function (account, password) {
        if (account && password) {
            var user = {};
            user[accountKey] = account;
            return user;
        }
        return false;
    };
    registerHandler = jwtOptions.registerHandler || function (account, password) {
        if (account && password) {
            var user = {};
            user[accountKey] = account;
            return user;
        }
        return false;
    };
    jwtOpt = { expiresIn: expiresIn };
    // Session
    sessionOptions = options.session || {};
    sessionKey = sessionOptions.sessionKey || 'session';
    sidKey = sessionOptions.sidKey || 'koa:sess';
    sessOpt = { sidKey: sidKey };
    // Redis Options
    redisOptions = options.redis || {};
    redisStore = new RedisStore(redisOptions);
    store = redisStore;
}

var createSession = function () {
    var ref = (0, _asyncToGenerator3.default)(_regenerator2.default.mark(function _callee(ctx, user) {
        var token;
        return _regenerator2.default.wrap(function _callee$(_context) {
            while (1) {
                switch (_context.prev = _context.next) {
                    case 0:
                        _context.next = 2;
                        return Session.create(store, user, sessOpt);

                    case 2:
                        ctx[sessionKey] = _context.sent;
                        _context.next = 5;
                        return _jsonwebtoken2.default.sign(user, secret, jwtOpt);

                    case 5:
                        token = _context.sent;

                        debug('Generated token:', token);
                        return _context.abrupt('return', { token: token, expiresIn: expiresIn });

                    case 8:
                    case 'end':
                        return _context.stop();
                }
            }
        }, _callee, undefined);
    }));
    return function createSession(_x, _x2) {
        return ref.apply(this, arguments);
    };
}();

exports.createSession = createSession;


function middleware(opts) {
    parseOptions(opts);

    // Utilities
    function sendToken(ctx, token) {
        if (contentType.toLowerCase() === 'application/json') ctx.body = token;else ctx.body = token.token;
    }

    // Authorization by JWT
    return function () {
        var ref = (0, _asyncToGenerator3.default)(_regenerator2.default.mark(function _callee2(ctx, next) {
            var account, password, user, userObj, token, _account, _password, _user, _userObj, _token, authComponents, _user2;

            return _regenerator2.default.wrap(function _callee2$(_context2) {
                while (1) {
                    switch (_context2.prev = _context2.next) {
                        case 0:
                            _context2.prev = 0;

                            ctx.type = contentType + ';' + 'charset=' + charset;
                            // SignIn

                            if (!(ctx.path === authPath && ctx.method.toUpperCase() === 'POST' && ctx.request.body[accountKey] && ctx.request.body[passwordKey])) {
                                _context2.next = 21;
                                break;
                            }

                            account = ctx.request.body[accountKey];
                            password = ctx.request.body[passwordKey];

                            debug('checking authorization:', account, password);
                            _context2.next = 8;
                            return authHandler(account, password);

                        case 8:
                            user = _context2.sent;

                            if (!(typeof user === 'boolean' && user || Object.prototype.toString.call(user).toLowerCase() === "[object object]")) {
                                _context2.next = 18;
                                break;
                            }

                            userObj = void 0;

                            if (typeof user === 'boolean') {
                                userObj = {};
                                userObj[accountKey] = account;
                            } else userObj = user;
                            _context2.next = 14;
                            return createSession(ctx, userObj);

                        case 14:
                            token = _context2.sent;

                            sendToken(ctx, token);
                            _context2.next = 19;
                            break;

                        case 18:
                            ctx.throw(401, 'Authorization failed');

                        case 19:
                            _context2.next = 55;
                            break;

                        case 21:
                            if (!(ctx.path === registerPath && ctx.method.toUpperCase() === 'POST' && ctx.request.body[accountKey] && ctx.request.body[passwordKey])) {
                                _context2.next = 39;
                                break;
                            }

                            _account = ctx.request.body[accountKey];
                            _password = ctx.request.body[passwordKey];
                            _context2.next = 26;
                            return registerHandler(_account, _password);

                        case 26:
                            _user = _context2.sent;

                            if (!(typeof _user === 'boolean' && _user || Object.prototype.toString.call(_user).toLowerCase() === "[object object]")) {
                                _context2.next = 36;
                                break;
                            }

                            _userObj = void 0;

                            if (typeof _user === 'boolean') {
                                _userObj = {};
                                _userObj[accountKey] = _account;
                            } else _userObj = _user;
                            _context2.next = 32;
                            return createSession(ctx, _userObj);

                        case 32:
                            _token = _context2.sent;

                            sendToken(ctx, _token);
                            _context2.next = 37;
                            break;

                        case 36:
                            ctx.throw(401, 'Register failed');

                        case 37:
                            _context2.next = 55;
                            break;

                        case 39:
                            if (!ctx.header.authorization) {
                                _context2.next = 55;
                                break;
                            }

                            authComponents = ctx.header.authorization.split(' ');

                            if (!(authComponents.length === 2 && authComponents[0] === 'Bearer')) {
                                _context2.next = 55;
                                break;
                            }

                            _user2 = _jsonwebtoken2.default.verify(authComponents[1], secret, jwtOpt);

                            if (!_user2) {
                                _context2.next = 55;
                                break;
                            }

                            debug('Authorized user:', _user2);

                            _context2.next = 47;
                            return Session.create(store, _user2, sessOpt);

                        case 47:
                            ctx[sessionKey] = _context2.sent;
                            _context2.next = 50;
                            return next();

                        case 50:
                            if (!(ctx[sessionKey] == undefined || ctx[sessionKey] === false)) {
                                _context2.next = 53;
                                break;
                            }

                            _context2.next = 55;
                            break;

                        case 53:
                            _context2.next = 55;
                            return ctx[sessionKey].save(store);

                        case 55:
                            _context2.next = 62;
                            break;

                        case 57:
                            _context2.prev = 57;
                            _context2.t0 = _context2['catch'](0);

                            console.error(DEBUG_LOG_HEADER, '[ERROR] catch something wrong:', _context2.t0);
                            ctx.response.status = 401;
                            if (_context2.t0.message) ctx.body = _context2.t0.message;

                        case 62:
                        case 'end':
                            return _context2.stop();
                    }
                }
            }, _callee2, this, [[0, 57]]);
        }));
        return function (_x3, _x4) {
            return ref.apply(this, arguments);
        };
    }();
}
exports.default = middleware;

// Session Model

var Session = function () {
    function Session(obj) {
        (0, _classCallCheck3.default)(this, Session);

        if (!obj) this.isNew = true;else for (var k in obj) {
            this[k] = obj[k];
        }
    }

    /**
    * JSON representation of the session.
    *
    * @return {Object}
    * @api public
    */


    (0, _createClass3.default)(Session, [{
        key: 'changed',


        /**
         * Check if the session has changed relative to the `prev`
         * JSON value from the request.
         *
         * @param {String} [prev]
         * @return {Boolean}
         * @api private
         */
        value: function changed(prev) {
            if (!prev) return true;
            this._json = (0, _stringify2.default)(this);
            return this._json !== prev;
        }

        /**
         * Return how many values there are in the session object.
         * Used to see if it's "populated".
         *
         * @return {Number}
         * @api public
         */

    }, {
        key: 'save',
        value: function () {
            var ref = (0, _asyncToGenerator3.default)(_regenerator2.default.mark(function _callee3(store) {
                return _regenerator2.default.wrap(function _callee3$(_context3) {
                    while (1) {
                        switch (_context3.prev = _context3.next) {
                            case 0:
                                if (store) {
                                    _context3.next = 2;
                                    break;
                                }

                                return _context3.abrupt('return');

                            case 2:
                                if (!(store.type === 'redis')) {
                                    _context3.next = 5;
                                    break;
                                }

                                _context3.next = 5;
                                return store.set(this._sessionId, this.json);

                            case 5:
                            case 'end':
                                return _context3.stop();
                        }
                    }
                }, _callee3, this);
            }));

            function save(_x5) {
                return ref.apply(this, arguments);
            }

            return save;
        }()
    }, {
        key: 'json',
        get: function get() {
            var self = this;
            var obj = {};

            (0, _keys2.default)(this).forEach(function (key) {
                if ('isNew' === key) return;
                if ('_' === key[0]) return;
                obj[key] = self[key];
            });

            return obj;
        }
    }, {
        key: 'string',
        get: function get() {
            return this._json || (0, _stringify2.default)(this.json);
        }
    }, {
        key: 'length',
        get: function get() {
            return (0, _keys2.default)(this.toJSON()).length;
        }

        /**
         * populated flag, which is just a boolean alias of .length.
         *
         * @return {Boolean}
         * @api public
         */

    }, {
        key: 'populated',
        get: function get() {
            return !!this.length;
        }
    }], [{
        key: 'generateSessionId',
        value: function generateSessionId(header) {
            if (!header) {
                return (0, _uid2.default)(24);
            } else {
                return header + ":" + (0, _uid2.default)(24);
            }
        }

        /**
         * Create a session instance
         * @param store
         * @param user
         */

    }, {
        key: 'create',
        value: function () {
            var ref = (0, _asyncToGenerator3.default)(_regenerator2.default.mark(function _callee4(store, user, opts) {
                var instance, options, sid, session, _session;

                return _regenerator2.default.wrap(function _callee4$(_context4) {
                    while (1) {
                        switch (_context4.prev = _context4.next) {
                            case 0:
                                instance = user || {};
                                options = opts || {
                                    sidKey: 'sid'
                                };

                                if (instance[options.sidKey]) {
                                    _context4.next = 22;
                                    break;
                                }

                                debug('Creating session');
                                // Creating
                                sid = Session.generateSessionId(options.sidKey);

                            case 5:
                                _context4.next = 7;
                                return store.exists(sid);

                            case 7:
                                if (!_context4.sent) {
                                    _context4.next = 12;
                                    break;
                                }

                                debug('sid', sid, 'exists');
                                sid = Session.generateSessionId(options.sidKey);
                                _context4.next = 5;
                                break;

                            case 12:
                                debug('new sid:', sid);
                                user[options.sidKey] = sid;
                                instance[options.sidKey] = sid;
                                session = new Session(instance);

                                session._sessionId = sid;
                                _context4.next = 19;
                                return session.save(store);

                            case 19:
                                return _context4.abrupt('return', session);

                            case 22:
                                debug('Loading session, sid:', instance[options.sidKey]);
                                // loading
                                _context4.next = 25;
                                return store.get(instance[options.sidKey]);

                            case 25:
                                instance = _context4.sent;

                                instance._sessionId = instance[options.sidKey];
                                _session = new Session(instance);

                                debug('loaded session:', _session.json);
                                return _context4.abrupt('return', _session);

                            case 30:
                            case 'end':
                                return _context4.stop();
                        }
                    }
                }, _callee4, this);
            }));

            function create(_x6, _x7, _x8) {
                return ref.apply(this, arguments);
            }

            return create;
        }()
    }]);
    return Session;
}();

// Store Base Class


var Store = function () {
    function Store(opts) {
        (0, _classCallCheck3.default)(this, Store);
    }

    (0, _createClass3.default)(Store, [{
        key: 'exists',
        value: function () {
            var ref = (0, _asyncToGenerator3.default)(_regenerator2.default.mark(function _callee7(key) {
                var _this = this;

                var exists, _ret;

                return _regenerator2.default.wrap(function _callee7$(_context7) {
                    while (1) {
                        switch (_context7.prev = _context7.next) {
                            case 0:
                                exists = true;

                                if (!(this.type === 'redis')) {
                                    _context7.next = 8;
                                    break;
                                }

                                return _context7.delegateYield(_regenerator2.default.mark(function _callee6() {
                                    var client;
                                    return _regenerator2.default.wrap(function _callee6$(_context6) {
                                        while (1) {
                                            switch (_context6.prev = _context6.next) {
                                                case 0:
                                                    if (!(!key || !_this.client || !_this.client.exists)) {
                                                        _context6.next = 2;
                                                        break;
                                                    }

                                                    return _context6.abrupt('return', {
                                                        v: exists
                                                    });

                                                case 2:
                                                    client = _this.client;
                                                    _context6.next = 5;
                                                    return (0, _co2.default)(_regenerator2.default.mark(function _callee5() {
                                                        return _regenerator2.default.wrap(function _callee5$(_context5) {
                                                            while (1) {
                                                                switch (_context5.prev = _context5.next) {
                                                                    case 0:
                                                                        _context5.next = 2;
                                                                        return client.exists(key);

                                                                    case 2:
                                                                        return _context5.abrupt('return', _context5.sent);

                                                                    case 3:
                                                                    case 'end':
                                                                        return _context5.stop();
                                                                }
                                                            }
                                                        }, _callee5, this);
                                                    }));

                                                case 5:
                                                    _context6.t0 = _context6.sent;
                                                    return _context6.abrupt('return', {
                                                        v: _context6.t0
                                                    });

                                                case 7:
                                                case 'end':
                                                    return _context6.stop();
                                            }
                                        }
                                    }, _callee6, _this);
                                })(), 't0', 3);

                            case 3:
                                _ret = _context7.t0;

                                if (!((typeof _ret === 'undefined' ? 'undefined' : (0, _typeof3.default)(_ret)) === "object")) {
                                    _context7.next = 6;
                                    break;
                                }

                                return _context7.abrupt('return', _ret.v);

                            case 6:
                                _context7.next = 9;
                                break;

                            case 8:
                                return _context7.abrupt('return', exists);

                            case 9:
                            case 'end':
                                return _context7.stop();
                        }
                    }
                }, _callee7, this);
            }));

            function exists(_x9) {
                return ref.apply(this, arguments);
            }

            return exists;
        }()
    }, {
        key: 'set',
        value: function () {
            var ref = (0, _asyncToGenerator3.default)(_regenerator2.default.mark(function _callee8(key, value) {
                var redisValue;
                return _regenerator2.default.wrap(function _callee8$(_context8) {
                    while (1) {
                        switch (_context8.prev = _context8.next) {
                            case 0:
                                if (!(this.type === 'redis')) {
                                    _context8.next = 8;
                                    break;
                                }

                                if (!(!key || !this.client || !this.client.set)) {
                                    _context8.next = 3;
                                    break;
                                }

                                return _context8.abrupt('return');

                            case 3:
                                redisValue = (typeof value === 'undefined' ? 'undefined' : (0, _typeof3.default)(value)) === 'object' ? (0, _stringify2.default)(value) : value;
                                _context8.next = 6;
                                return this.client.set(key, redisValue);

                            case 6:
                                _context8.next = 8;
                                return this.client.ttl(key);

                            case 8:
                            case 'end':
                                return _context8.stop();
                        }
                    }
                }, _callee8, this);
            }));

            function set(_x10, _x11) {
                return ref.apply(this, arguments);
            }

            return set;
        }()
    }, {
        key: 'get',
        value: function () {
            var ref = (0, _asyncToGenerator3.default)(_regenerator2.default.mark(function _callee11(key) {
                var _this2 = this;

                var _ret2;

                return _regenerator2.default.wrap(function _callee11$(_context11) {
                    while (1) {
                        switch (_context11.prev = _context11.next) {
                            case 0:
                                if (!(this.type === 'redis')) {
                                    _context11.next = 5;
                                    break;
                                }

                                return _context11.delegateYield(_regenerator2.default.mark(function _callee10() {
                                    var client, value;
                                    return _regenerator2.default.wrap(function _callee10$(_context10) {
                                        while (1) {
                                            switch (_context10.prev = _context10.next) {
                                                case 0:
                                                    if (!(!key || !_this2.client || !_this2.client.get)) {
                                                        _context10.next = 2;
                                                        break;
                                                    }

                                                    return _context10.abrupt('return', {
                                                        v: null
                                                    });

                                                case 2:
                                                    client = _this2.client;
                                                    _context10.next = 5;
                                                    return (0, _co2.default)(_regenerator2.default.mark(function _callee9() {
                                                        return _regenerator2.default.wrap(function _callee9$(_context9) {
                                                            while (1) {
                                                                switch (_context9.prev = _context9.next) {
                                                                    case 0:
                                                                        _context9.next = 2;
                                                                        return client.get(key);

                                                                    case 2:
                                                                        return _context9.abrupt('return', _context9.sent);

                                                                    case 3:
                                                                    case 'end':
                                                                        return _context9.stop();
                                                                }
                                                            }
                                                        }, _callee9, this);
                                                    }));

                                                case 5:
                                                    value = _context10.sent;

                                                    if (!(value && typeof value === 'string')) {
                                                        _context10.next = 10;
                                                        break;
                                                    }

                                                    return _context10.abrupt('return', {
                                                        v: JSON.parse(value)
                                                    });

                                                case 10:
                                                    return _context10.abrupt('return', {
                                                        v: value
                                                    });

                                                case 11:
                                                case 'end':
                                                    return _context10.stop();
                                            }
                                        }
                                    }, _callee10, _this2);
                                })(), 't0', 2);

                            case 2:
                                _ret2 = _context11.t0;

                                if (!((typeof _ret2 === 'undefined' ? 'undefined' : (0, _typeof3.default)(_ret2)) === "object")) {
                                    _context11.next = 5;
                                    break;
                                }

                                return _context11.abrupt('return', _ret2.v);

                            case 5:
                            case 'end':
                                return _context11.stop();
                        }
                    }
                }, _callee11, this);
            }));

            function get(_x12) {
                return ref.apply(this, arguments);
            }

            return get;
        }()
    }]);
    return Store;
}();

// Redis store


var RedisStore = function (_Store) {
    (0, _inherits3.default)(RedisStore, _Store);

    function RedisStore(opts) {
        (0, _classCallCheck3.default)(this, RedisStore);

        var _this3 = (0, _possibleConstructorReturn3.default)(this, (0, _getPrototypeOf2.default)(RedisStore).call(this, opts));

        _this3.type = 'redis';
        var redisOptions = opts || {};
        var port = _this3.port = redisOptions.port || 6379;
        var host = _this3.host = redisOptions.host || '127.0.0.1';
        var db = _this3.db = redisOptions.db || 0;
        var ttl = _this3.ttl = redisOptions.ttl || EXPIRES_IN_SECONDS;
        var options = _this3.options = redisOptions.options || {};

        //redis client for session
        _this3.client = _redis2.default.createClient(port, host, options);

        var client = _this3.client;

        client.select(db, function () {
            debug('redis changed to db %d', db);
        });

        client.get = (0, _thunkify2.default)(client.get);
        client.exists = (0, _thunkify2.default)(client.exists);
        client.ttl = ttl ? function expire(key) {
            client.expire(key, ttl);
        } : function () {};

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
        return _this3;
    }

    return RedisStore;
}(Store);