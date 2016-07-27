'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});
exports.authoriseRequest = exports.createSession = undefined;

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

var _ioredis = require('ioredis');

var _ioredis2 = _interopRequireDefault(_ioredis);

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
    jwtOpt = void 0,
    refreshTokenPath = void 0;
// Session
var sessionKey = void 0,
    sidKey = void 0,
    sessOpt = void 0;
// Redis Options
var redisOptions = void 0,
    redisStore = void 0,
    store = void 0;

function parseOptions(opts) {
    // Options
    var options = opts || {};
    debug('Parsing options:', options);
    // JWT Options
    jwtOptions = options.jwt || {};
    contentType = jwtOptions.contentType || 'application/json';
    charset = jwtOptions.charset || 'utf-8';
    secret = jwtOptions.secret || 'koa-jwt-redis-session' + new Date().getTime();
    authPath = jwtOptions.authPath || '/authorize';
    registerPath = jwtOptions.registerPath || '/register';
    refreshTokenPath = jwtOptions.refreshTokenPath || '/refreshToken';
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
    var sessionOptions = options.session || {};
    sessionKey = sessionOptions.sessionKey || 'session';
    sidKey = sessionOptions.sidKey || 'koa:sess';
    sessOpt = { sidKey: sidKey };
    // Redis Options
    redisOptions = options.redis || {};
    redisStore = new RedisStore(redisOptions);
    store = redisStore;
}

var createSession = function () {
    var _ref = (0, _asyncToGenerator3.default)(_regenerator2.default.mark(function _callee(ctx, user) {
        var sess, token;
        return _regenerator2.default.wrap(function _callee$(_context) {
            while (1) {
                switch (_context.prev = _context.next) {
                    case 0:
                        _context.next = 2;
                        return Session.create(store, user, sessOpt);

                    case 2:
                        sess = _context.sent;
                        _context.next = 5;
                        return _jsonwebtoken2.default.sign(user, secret, jwtOpt);

                    case 5:
                        token = _context.sent;

                        ctx[sessionKey] = sess;
                        debug('Generated token:', token);
                        return _context.abrupt('return', { token: token, expiresIn: expiresIn });

                    case 9:
                    case 'end':
                        return _context.stop();
                }
            }
        }, _callee, undefined);
    }));

    return function createSession(_x, _x2) {
        return _ref.apply(this, arguments);
    };
}();

var authoriseRequest = function () {
    var _ref2 = (0, _asyncToGenerator3.default)(_regenerator2.default.mark(function _callee2(ctx) {
        var authComponents, user;
        return _regenerator2.default.wrap(function _callee2$(_context2) {
            while (1) {
                switch (_context2.prev = _context2.next) {
                    case 0:
                        if (!(ctx && ctx.header && ctx.header.authorization)) {
                            _context2.next = 7;
                            break;
                        }

                        authComponents = ctx.header.authorization.split(' ');

                        if (!(authComponents.length === 2 && authComponents[0] === 'Bearer')) {
                            _context2.next = 7;
                            break;
                        }

                        _context2.next = 5;
                        return _jsonwebtoken2.default.verify(authComponents[1], secret, jwtOpt);

                    case 5:
                        user = _context2.sent;
                        return _context2.abrupt('return', user);

                    case 7:
                        return _context2.abrupt('return', null);

                    case 8:
                    case 'end':
                        return _context2.stop();
                }
            }
        }, _callee2, undefined);
    }));

    return function authoriseRequest(_x3) {
        return _ref2.apply(this, arguments);
    };
}();

function middleware(opts) {
    parseOptions(opts);

    // Utilities
    function sendToken(ctx, token) {
        if (contentType.toLowerCase() === 'application/json') ctx.body = token;else ctx.body = token.token;
    }

    // Authorization by JWT
    return function () {
        var _ref3 = (0, _asyncToGenerator3.default)(_regenerator2.default.mark(function _callee3(ctx, next) {
            var user, token, account, password, _user, userObj, _token, _account, _password, _user2, _userObj, _token2, _user3;

            return _regenerator2.default.wrap(function _callee3$(_context3) {
                while (1) {
                    switch (_context3.prev = _context3.next) {
                        case 0:
                            _context3.prev = 0;

                            ctx.type = contentType + ';' + 'charset=' + charset;

                            if (!(ctx.path === refreshTokenPath && ctx.method.toUpperCase() === 'POST')) {
                                _context3.next = 19;
                                break;
                            }

                            _context3.next = 5;
                            return authoriseRequest(ctx);

                        case 5:
                            user = _context3.sent;

                            if (!user) {
                                _context3.next = 15;
                                break;
                            }

                            delete user.iat, user.exp;
                            _context3.next = 10;
                            return createSession(ctx, user);

                        case 10:
                            token = _context3.sent;

                            debug('Refreshed token:', token, 'user:', user);
                            sendToken(ctx, token);
                            _context3.next = 17;
                            break;

                        case 15:
                            ctx.body = 'Authorization failed';
                            ctx.status = 401;

                        case 17:
                            _context3.next = 73;
                            break;

                        case 19:
                            if (!(ctx.path === authPath && ctx.method.toUpperCase() === 'POST' && ctx.request.body[accountKey] && ctx.request.body[passwordKey])) {
                                _context3.next = 39;
                                break;
                            }

                            account = ctx.request.body[accountKey];
                            password = ctx.request.body[passwordKey];

                            debug('checking authorization:', account, password);
                            _context3.next = 25;
                            return authHandler(account, password);

                        case 25:
                            _user = _context3.sent;

                            if (!(typeof _user === 'boolean' && _user || Object.prototype.toString.call(_user).toLowerCase() === "[object object]")) {
                                _context3.next = 35;
                                break;
                            }

                            userObj = void 0;

                            if (typeof _user === 'boolean') {
                                userObj = {};
                                userObj[accountKey] = account;
                            } else userObj = _user;
                            _context3.next = 31;
                            return createSession(ctx, userObj);

                        case 31:
                            _token = _context3.sent;

                            sendToken(ctx, _token);
                            _context3.next = 37;
                            break;

                        case 35:
                            ctx.body = 'Authorization failed';
                            ctx.status = 401;

                        case 37:
                            _context3.next = 73;
                            break;

                        case 39:
                            if (!(ctx.path === registerPath && ctx.method.toUpperCase() === 'POST' && ctx.request.body[accountKey] && ctx.request.body[passwordKey])) {
                                _context3.next = 58;
                                break;
                            }

                            _account = ctx.request.body[accountKey];
                            _password = ctx.request.body[passwordKey];
                            _context3.next = 44;
                            return registerHandler(_account, _password);

                        case 44:
                            _user2 = _context3.sent;

                            if (!(typeof _user2 === 'boolean' && _user2 || Object.prototype.toString.call(_user2).toLowerCase() === "[object object]")) {
                                _context3.next = 54;
                                break;
                            }

                            _userObj = void 0;

                            if (typeof _user2 === 'boolean') {
                                _userObj = {};
                                _userObj[accountKey] = _account;
                            } else _userObj = _user2;
                            _context3.next = 50;
                            return createSession(ctx, _userObj);

                        case 50:
                            _token2 = _context3.sent;

                            sendToken(ctx, _token2);
                            _context3.next = 56;
                            break;

                        case 54:
                            ctx.body = 'Authorization failed';
                            ctx.status = 401;

                        case 56:
                            _context3.next = 73;
                            break;

                        case 58:
                            _context3.next = 60;
                            return authoriseRequest(ctx);

                        case 60:
                            _user3 = _context3.sent;

                            if (!_user3) {
                                _context3.next = 73;
                                break;
                            }

                            debug('Authorized user:', _user3);
                            _context3.next = 65;
                            return Session.create(store, _user3, sessOpt);

                        case 65:
                            ctx[sessionKey] = _context3.sent;
                            _context3.next = 68;
                            return next();

                        case 68:
                            if (!(ctx[sessionKey] == undefined || ctx[sessionKey] === false)) {
                                _context3.next = 71;
                                break;
                            }

                            _context3.next = 73;
                            break;

                        case 71:
                            _context3.next = 73;
                            return ctx[sessionKey].save(store);

                        case 73:
                            _context3.next = 78;
                            break;

                        case 75:
                            _context3.prev = 75;
                            _context3.t0 = _context3['catch'](0);

                            if (_context3.t0.name !== 'UnauthorizedError' || _context3.t0.name !== 'JsonWebTokenError') {
                                debug(DEBUG_LOG_HEADER, '[ERROR] catch something wrong:', _context3.t0);
                                ctx.status = 500;
                                if (_context3.t0.message && !ctx.body) ctx.body = _context3.t0.message;
                            } else {
                                ctx.status = 401;
                            }

                        case 78:
                        case 'end':
                            return _context3.stop();
                    }
                }
            }, _callee3, this, [[0, 75]]);
        }));

        return function (_x4, _x5) {
            return _ref3.apply(this, arguments);
        };
    }();
}
exports.default = middleware;
exports.createSession = createSession;
exports.authoriseRequest = authoriseRequest;

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
            var _ref4 = (0, _asyncToGenerator3.default)(_regenerator2.default.mark(function _callee4(store) {
                return _regenerator2.default.wrap(function _callee4$(_context4) {
                    while (1) {
                        switch (_context4.prev = _context4.next) {
                            case 0:
                                if (store) {
                                    _context4.next = 2;
                                    break;
                                }

                                return _context4.abrupt('return');

                            case 2:
                                if (!(store.type === 'redis')) {
                                    _context4.next = 5;
                                    break;
                                }

                                _context4.next = 5;
                                return store.set(this._sessionId, this.json);

                            case 5:
                            case 'end':
                                return _context4.stop();
                        }
                    }
                }, _callee4, this);
            }));

            function save(_x6) {
                return _ref4.apply(this, arguments);
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
            var _ref5 = (0, _asyncToGenerator3.default)(_regenerator2.default.mark(function _callee5(store, user, opts) {
                var instance, options, sid, session, _session;

                return _regenerator2.default.wrap(function _callee5$(_context5) {
                    while (1) {
                        switch (_context5.prev = _context5.next) {
                            case 0:
                                instance = user || {};
                                options = opts || {
                                    sidKey: 'sid'
                                };

                                debug('User for creating session:', instance);
                                debug('Session options for creating session:', opts);

                                if (instance[options.sidKey]) {
                                    _context5.next = 24;
                                    break;
                                }

                                debug('Creating session');
                                // Creating
                                sid = Session.generateSessionId(options.sidKey);

                            case 7:
                                _context5.next = 9;
                                return store.exists(sid);

                            case 9:
                                if (!_context5.sent) {
                                    _context5.next = 14;
                                    break;
                                }

                                debug('sid', sid, 'exists');
                                sid = Session.generateSessionId(options.sidKey);
                                _context5.next = 7;
                                break;

                            case 14:
                                debug('new sid:', sid);
                                user[options.sidKey] = sid;
                                instance[options.sidKey] = sid;
                                session = new Session(instance);

                                session._sessionId = sid;
                                _context5.next = 21;
                                return session.save(store);

                            case 21:
                                return _context5.abrupt('return', session);

                            case 24:
                                debug('Loading session, sid:', instance[options.sidKey]);
                                // loading
                                _context5.next = 27;
                                return store.get(instance[options.sidKey]);

                            case 27:
                                instance = _context5.sent;

                                instance._sessionId = instance[options.sidKey];
                                _session = new Session(instance);

                                debug('loaded session:', _session.json);
                                return _context5.abrupt('return', _session);

                            case 32:
                            case 'end':
                                return _context5.stop();
                        }
                    }
                }, _callee5, this);
            }));

            function create(_x7, _x8, _x9) {
                return _ref5.apply(this, arguments);
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
            var _ref6 = (0, _asyncToGenerator3.default)(_regenerator2.default.mark(function _callee9(key) {
                var _this = this;

                var exists, _ret;

                return _regenerator2.default.wrap(function _callee9$(_context9) {
                    while (1) {
                        switch (_context9.prev = _context9.next) {
                            case 0:
                                exists = true;

                                if (!(this.type === 'redis')) {
                                    _context9.next = 8;
                                    break;
                                }

                                return _context9.delegateYield(_regenerator2.default.mark(function _callee8() {
                                    var client, value;
                                    return _regenerator2.default.wrap(function _callee8$(_context8) {
                                        while (1) {
                                            switch (_context8.prev = _context8.next) {
                                                case 0:
                                                    if (!(!key || !_this.client || !_this.client.exists)) {
                                                        _context8.next = 2;
                                                        break;
                                                    }

                                                    return _context8.abrupt('return', {
                                                        v: exists
                                                    });

                                                case 2:
                                                    client = _this.client;
                                                    _context8.prev = 3;
                                                    _context8.next = 6;
                                                    return (0, _co2.default)(_regenerator2.default.mark(function _callee6() {
                                                        return _regenerator2.default.wrap(function _callee6$(_context6) {
                                                            while (1) {
                                                                switch (_context6.prev = _context6.next) {
                                                                    case 0:
                                                                        _context6.next = 2;
                                                                        return client.exists(key);

                                                                    case 2:
                                                                        return _context6.abrupt('return', _context6.sent);

                                                                    case 3:
                                                                    case 'end':
                                                                        return _context6.stop();
                                                                }
                                                            }
                                                        }, _callee6, this);
                                                    }));

                                                case 6:
                                                    _context8.t0 = _context8.sent;
                                                    return _context8.abrupt('return', {
                                                        v: _context8.t0
                                                    });

                                                case 10:
                                                    _context8.prev = 10;
                                                    _context8.t1 = _context8['catch'](3);

                                                    // under some condition, it may not support exists command, wield
                                                    debug('Error when trying invoke "exists" of redis driver:', _context8.t1);
                                                    _context8.next = 15;
                                                    return (0, _co2.default)(_regenerator2.default.mark(function _callee7() {
                                                        return _regenerator2.default.wrap(function _callee7$(_context7) {
                                                            while (1) {
                                                                switch (_context7.prev = _context7.next) {
                                                                    case 0:
                                                                        _context7.next = 2;
                                                                        return client.get(key);

                                                                    case 2:
                                                                        return _context7.abrupt('return', _context7.sent);

                                                                    case 3:
                                                                    case 'end':
                                                                        return _context7.stop();
                                                                }
                                                            }
                                                        }, _callee7, this);
                                                    }));

                                                case 15:
                                                    value = _context8.sent;

                                                    if (!value) {
                                                        _context8.next = 20;
                                                        break;
                                                    }

                                                    return _context8.abrupt('return', {
                                                        v: true
                                                    });

                                                case 20:
                                                    return _context8.abrupt('return', {
                                                        v: false
                                                    });

                                                case 21:
                                                case 'end':
                                                    return _context8.stop();
                                            }
                                        }
                                    }, _callee8, _this, [[3, 10]]);
                                })(), 't0', 3);

                            case 3:
                                _ret = _context9.t0;

                                if (!((typeof _ret === 'undefined' ? 'undefined' : (0, _typeof3.default)(_ret)) === "object")) {
                                    _context9.next = 6;
                                    break;
                                }

                                return _context9.abrupt('return', _ret.v);

                            case 6:
                                _context9.next = 9;
                                break;

                            case 8:
                                return _context9.abrupt('return', exists);

                            case 9:
                            case 'end':
                                return _context9.stop();
                        }
                    }
                }, _callee9, this);
            }));

            function exists(_x10) {
                return _ref6.apply(this, arguments);
            }

            return exists;
        }()
    }, {
        key: 'set',
        value: function () {
            var _ref7 = (0, _asyncToGenerator3.default)(_regenerator2.default.mark(function _callee10(key, value) {
                var storedValue;
                return _regenerator2.default.wrap(function _callee10$(_context10) {
                    while (1) {
                        switch (_context10.prev = _context10.next) {
                            case 0:
                                if (!(this.type === 'redis')) {
                                    _context10.next = 8;
                                    break;
                                }

                                if (!(!key || !this.client || !this.client.set)) {
                                    _context10.next = 3;
                                    break;
                                }

                                return _context10.abrupt('return');

                            case 3:
                                storedValue = (typeof value === 'undefined' ? 'undefined' : (0, _typeof3.default)(value)) === 'object' ? (0, _stringify2.default)(value) : value;
                                _context10.next = 6;
                                return this.client.set(key, storedValue);

                            case 6:
                                _context10.next = 8;
                                return this.client.ttl(key);

                            case 8:
                            case 'end':
                                return _context10.stop();
                        }
                    }
                }, _callee10, this);
            }));

            function set(_x11, _x12) {
                return _ref7.apply(this, arguments);
            }

            return set;
        }()
    }, {
        key: 'get',
        value: function () {
            var _ref8 = (0, _asyncToGenerator3.default)(_regenerator2.default.mark(function _callee13(key) {
                var _this2 = this;

                var _ret2;

                return _regenerator2.default.wrap(function _callee13$(_context13) {
                    while (1) {
                        switch (_context13.prev = _context13.next) {
                            case 0:
                                if (!(this.type === 'redis')) {
                                    _context13.next = 5;
                                    break;
                                }

                                return _context13.delegateYield(_regenerator2.default.mark(function _callee12() {
                                    var client, value;
                                    return _regenerator2.default.wrap(function _callee12$(_context12) {
                                        while (1) {
                                            switch (_context12.prev = _context12.next) {
                                                case 0:
                                                    if (!(!key || !_this2.client || !_this2.client.get)) {
                                                        _context12.next = 2;
                                                        break;
                                                    }

                                                    return _context12.abrupt('return', {
                                                        v: null
                                                    });

                                                case 2:
                                                    client = _this2.client;
                                                    _context12.next = 5;
                                                    return (0, _co2.default)(_regenerator2.default.mark(function _callee11() {
                                                        return _regenerator2.default.wrap(function _callee11$(_context11) {
                                                            while (1) {
                                                                switch (_context11.prev = _context11.next) {
                                                                    case 0:
                                                                        _context11.next = 2;
                                                                        return client.get(key);

                                                                    case 2:
                                                                        return _context11.abrupt('return', _context11.sent);

                                                                    case 3:
                                                                    case 'end':
                                                                        return _context11.stop();
                                                                }
                                                            }
                                                        }, _callee11, this);
                                                    }));

                                                case 5:
                                                    value = _context12.sent;

                                                    if (!(value && typeof value === 'string')) {
                                                        _context12.next = 10;
                                                        break;
                                                    }

                                                    return _context12.abrupt('return', {
                                                        v: JSON.parse(value)
                                                    });

                                                case 10:
                                                    return _context12.abrupt('return', {
                                                        v: value
                                                    });

                                                case 11:
                                                case 'end':
                                                    return _context12.stop();
                                            }
                                        }
                                    }, _callee12, _this2);
                                })(), 't0', 2);

                            case 2:
                                _ret2 = _context13.t0;

                                if (!((typeof _ret2 === 'undefined' ? 'undefined' : (0, _typeof3.default)(_ret2)) === "object")) {
                                    _context13.next = 5;
                                    break;
                                }

                                return _context13.abrupt('return', _ret2.v);

                            case 5:
                            case 'end':
                                return _context13.stop();
                        }
                    }
                }, _callee13, this);
            }));

            function get(_x13) {
                return _ref8.apply(this, arguments);
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
        debug('Redis options:', redisOptions);

        var db = redisOptions.db || 0;
        var ttl = _this3.ttl = redisOptions.ttl || expiresIn || EXPIRES_IN_SECONDS;

        //redis client for session
        _this3.client = new _ioredis2.default(redisOptions);

        var client = _this3.client;

        client.select(db, function () {
            debug('redis changed to db %d', db);
        });

        client.get = (0, _thunkify2.default)(client.get);
        client.exists = (0, _thunkify2.default)(client.exists);
        client.ttl = ttl ? function (key) {
            client.expire(key, ttl);
        } : function () {};

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
        return _this3;
    }

    return RedisStore;
}(Store);