'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});

var _typeof = typeof Symbol === "function" && typeof Symbol.iterator === "symbol" ? function (obj) { return typeof obj; } : function (obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol ? "symbol" : typeof obj; };

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

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

function _possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _asyncToGenerator(fn) { return function () { var gen = fn.apply(this, arguments); return new Promise(function (resolve, reject) { function step(key, arg) { try { var info = gen[key](arg); var value = info.value; } catch (error) { reject(error); return; } if (info.done) { resolve(value); } else { return Promise.resolve(value).then(function (value) { return step("next", value); }, function (err) { return step("throw", err); }); } } return step("next"); }); }; }

var debug = require('debug')('koa-jwt-redis-session');

var DEBUG_LOG_HEADER = '[koa-jwt-redis-session]';
var EXPIRES_IN_SECONDS = 60 * 60;

function middleware(opts) {
    // Options
    var options = opts || {};
    // JWT Options
    var jwtOptions = options.jwt || {};
    var contentType = jwtOptions.contentType || 'application/json';
    var charset = jwtOptions.charset || 'utf-8';
    var secret = jwtOptions.secret || 'koa-jwt-redis-session' + new Date().getTime();
    var authPath = jwtOptions.authPath || '/authorize';
    var registerPath = jwtOptions.registerPath || '/register';
    var expiresIn = jwtOptions.expiresIn || EXPIRES_IN_SECONDS;
    var accountKey = jwtOptions.accountKey || 'account';
    var passwordKey = jwtOptions.passwordKey || 'password';
    var authHandler = jwtOptions.authHandler || function (account, password) {
        if (account && password) return true;else return false;
    };
    var registerHandler = jwtOptions.registerHandler || function (account, password) {
        if (account && password) return true;else return false;
    };
    var jwtOpt = { expiresIn: expiresIn };
    // Session
    var sessionOptions = options.session || {};
    var sessionKey = sessionOptions.sessionKey || 'session';
    var sidKey = sessionOptions.sidKey || 'koa:sess';
    var sessOpt = { sidKey: sidKey };
    // Redis Options
    var redisOptions = options.redis || {};
    var redisStore = new RedisStore(redisOptions);
    var store = redisStore;

    // Utilities
    function sendToken(ctx, token) {
        if (contentType.toLowerCase() === 'application/json') ctx.body = { token: token };else ctx.body = token;
    }

    // Authorization by JWT
    return function () {
        var ref = _asyncToGenerator(regeneratorRuntime.mark(function _callee(ctx, next) {
            var account, password, user, token, _account, _password, _user, _token, authComponents, _user2;

            return regeneratorRuntime.wrap(function _callee$(_context) {
                while (1) {
                    switch (_context.prev = _context.next) {
                        case 0:
                            _context.prev = 0;

                            ctx.type = contentType + ';' + 'charset=' + charset;
                            // SignIn

                            if (!(ctx.path === authPath && ctx.method.toUpperCase() === 'POST' && ctx.request.body[accountKey] && ctx.request.body[passwordKey])) {
                                _context.next = 25;
                                break;
                            }

                            account = ctx.request.body[accountKey];
                            password = ctx.request.body[passwordKey];

                            debug('checking authorization:', account, password);
                            _context.next = 8;
                            return authHandler(account, password);

                        case 8:
                            if (!_context.sent) {
                                _context.next = 22;
                                break;
                            }

                            user = {};

                            user[accountKey] = account;
                            user[passwordKey] = password;
                            _context.next = 14;
                            return Session.create(store, user, sessOpt);

                        case 14:
                            ctx[sessionKey] = _context.sent;
                            _context.next = 17;
                            return _jsonwebtoken2.default.sign(user, secret, jwtOpt);

                        case 17:
                            token = _context.sent;

                            debug('Generated token:', token);
                            sendToken(ctx, token);
                            _context.next = 23;
                            break;

                        case 22:
                            ctx.throw(401, 'Authorization failed');

                        case 23:
                            _context.next = 63;
                            break;

                        case 25:
                            if (!(ctx.path === registerPath && ctx.method.toUpperCase() === 'POST' && ctx.request.body[accountKey] && ctx.request.body[passwordKey])) {
                                _context.next = 47;
                                break;
                            }

                            _account = ctx.request.body[accountKey];
                            _password = ctx.request.body[passwordKey];
                            _context.next = 30;
                            return registerHandler(_account, _password);

                        case 30:
                            if (!_context.sent) {
                                _context.next = 44;
                                break;
                            }

                            _user = {};

                            _user[accountKey] = _account;
                            _user[passwordKey] = _password;
                            _context.next = 36;
                            return Session.create(store, _user, sessOpt);

                        case 36:
                            ctx[sessionKey] = _context.sent;
                            _context.next = 39;
                            return _jsonwebtoken2.default.sign(_user, secret, jwtOpt);

                        case 39:
                            _token = _context.sent;

                            debug('Generated token:', _token);
                            sendToken(ctx, _token);
                            _context.next = 45;
                            break;

                        case 44:
                            ctx.throw(401, 'Register failed');

                        case 45:
                            _context.next = 63;
                            break;

                        case 47:
                            if (!ctx.header.authorization) {
                                _context.next = 63;
                                break;
                            }

                            authComponents = ctx.header.authorization.split(' ');

                            if (!(authComponents.length === 2 && authComponents[0] === 'Bearer')) {
                                _context.next = 63;
                                break;
                            }

                            _user2 = _jsonwebtoken2.default.verify(authComponents[1], secret, jwtOpt);

                            if (!_user2) {
                                _context.next = 63;
                                break;
                            }

                            debug('Authorized user:', _user2);

                            _context.next = 55;
                            return Session.create(store, _user2, sessOpt);

                        case 55:
                            ctx[sessionKey] = _context.sent;
                            _context.next = 58;
                            return next();

                        case 58:
                            if (!(ctx[sessionKey] == undefined || ctx[sessionKey] === false)) {
                                _context.next = 61;
                                break;
                            }

                            _context.next = 63;
                            break;

                        case 61:
                            _context.next = 63;
                            return ctx[sessionKey].save(store);

                        case 63:
                            _context.next = 70;
                            break;

                        case 65:
                            _context.prev = 65;
                            _context.t0 = _context['catch'](0);

                            console.error(DEBUG_LOG_HEADER, '[ERROR] catch something wrong:', _context.t0);
                            ctx.response.status = 401;
                            if (_context.t0.message) ctx.body = _context.t0.message;

                        case 70:
                        case 'end':
                            return _context.stop();
                    }
                }
            }, _callee, this, [[0, 65]]);
        }));

        return function (_x, _x2) {
            return ref.apply(this, arguments);
        };
    }();
}
exports.default = middleware;

// Session Model

var Session = function () {
    function Session(obj) {
        _classCallCheck(this, Session);

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


    _createClass(Session, [{
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

    }, {
        key: 'save',
        value: function () {
            var ref = _asyncToGenerator(regeneratorRuntime.mark(function _callee2(store) {
                return regeneratorRuntime.wrap(function _callee2$(_context2) {
                    while (1) {
                        switch (_context2.prev = _context2.next) {
                            case 0:
                                if (store) {
                                    _context2.next = 2;
                                    break;
                                }

                                return _context2.abrupt('return');

                            case 2:
                                if (!(store.type === 'redis')) {
                                    _context2.next = 5;
                                    break;
                                }

                                _context2.next = 5;
                                return store.set(this._sessionId, this.json);

                            case 5:
                            case 'end':
                                return _context2.stop();
                        }
                    }
                }, _callee2, this);
            }));

            function save(_x3) {
                return ref.apply(this, arguments);
            }

            return save;
        }()
    }, {
        key: 'json',
        get: function get() {
            var self = this;
            var obj = {};

            Object.keys(this).forEach(function (key) {
                if ('isNew' === key) return;
                if ('_' === key[0]) return;
                obj[key] = self[key];
            });

            return obj;
        }
    }, {
        key: 'string',
        get: function get() {
            return this._json || JSON.stringify(this.json);
        }
    }, {
        key: 'length',
        get: function get() {
            return Object.keys(this.toJSON()).length;
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
        value: function generateSessionId() {
            return (0, _uid2.default)(24);
        }

        /**
         * Create a session instance
         * @param store
         * @param user
         */

    }, {
        key: 'create',
        value: function () {
            var ref = _asyncToGenerator(regeneratorRuntime.mark(function _callee3(store, user, opts) {
                var instance, options, sid, session, _session;

                return regeneratorRuntime.wrap(function _callee3$(_context3) {
                    while (1) {
                        switch (_context3.prev = _context3.next) {
                            case 0:
                                instance = user || {};
                                options = opts || {
                                    sidKey: 'sid'
                                };

                                if (instance[options.sidKey]) {
                                    _context3.next = 22;
                                    break;
                                }

                                debug('Creating session');
                                // Creating
                                sid = Session.generateSessionId();

                            case 5:
                                _context3.next = 7;
                                return store.exists(sid);

                            case 7:
                                if (!_context3.sent) {
                                    _context3.next = 12;
                                    break;
                                }

                                debug('sid', sid, 'exists');
                                sid = Session.generateSessionId();
                                _context3.next = 5;
                                break;

                            case 12:
                                debug('new sid:', sid);
                                user[options.sidKey] = sid;
                                instance[options.sidKey] = sid;
                                session = new Session(instance);

                                session._sessionId = sid;
                                _context3.next = 19;
                                return session.save(store);

                            case 19:
                                return _context3.abrupt('return', session);

                            case 22:
                                debug('Loading session, sid:', instance[options.sidKey]);
                                // loading
                                _context3.next = 25;
                                return store.get(instance[options.sidKey]);

                            case 25:
                                instance = _context3.sent;

                                instance._sessionId = instance[options.sidKey];
                                _session = new Session(instance);

                                debug('loaded session:', _session.json);
                                return _context3.abrupt('return', _session);

                            case 30:
                            case 'end':
                                return _context3.stop();
                        }
                    }
                }, _callee3, this);
            }));

            function create(_x4, _x5, _x6) {
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
        _classCallCheck(this, Store);
    }

    _createClass(Store, [{
        key: 'exists',
        value: function () {
            var ref = _asyncToGenerator(regeneratorRuntime.mark(function _callee6(key) {
                var _this = this;

                var exists, _ret;

                return regeneratorRuntime.wrap(function _callee6$(_context6) {
                    while (1) {
                        switch (_context6.prev = _context6.next) {
                            case 0:
                                exists = true;

                                if (!(this.type === 'redis')) {
                                    _context6.next = 8;
                                    break;
                                }

                                return _context6.delegateYield(regeneratorRuntime.mark(function _callee5() {
                                    var client;
                                    return regeneratorRuntime.wrap(function _callee5$(_context5) {
                                        while (1) {
                                            switch (_context5.prev = _context5.next) {
                                                case 0:
                                                    if (!(!key || !_this.client || !_this.client.exists)) {
                                                        _context5.next = 2;
                                                        break;
                                                    }

                                                    return _context5.abrupt('return', {
                                                        v: exists
                                                    });

                                                case 2:
                                                    client = _this.client;
                                                    _context5.next = 5;
                                                    return (0, _co2.default)(regeneratorRuntime.mark(function _callee4() {
                                                        return regeneratorRuntime.wrap(function _callee4$(_context4) {
                                                            while (1) {
                                                                switch (_context4.prev = _context4.next) {
                                                                    case 0:
                                                                        _context4.next = 2;
                                                                        return client.exists(key);

                                                                    case 2:
                                                                        return _context4.abrupt('return', _context4.sent);

                                                                    case 3:
                                                                    case 'end':
                                                                        return _context4.stop();
                                                                }
                                                            }
                                                        }, _callee4, this);
                                                    }));

                                                case 5:
                                                    _context5.t0 = _context5.sent;
                                                    return _context5.abrupt('return', {
                                                        v: _context5.t0
                                                    });

                                                case 7:
                                                case 'end':
                                                    return _context5.stop();
                                            }
                                        }
                                    }, _callee5, _this);
                                })(), 't0', 3);

                            case 3:
                                _ret = _context6.t0;

                                if (!((typeof _ret === 'undefined' ? 'undefined' : _typeof(_ret)) === "object")) {
                                    _context6.next = 6;
                                    break;
                                }

                                return _context6.abrupt('return', _ret.v);

                            case 6:
                                _context6.next = 9;
                                break;

                            case 8:
                                return _context6.abrupt('return', exists);

                            case 9:
                            case 'end':
                                return _context6.stop();
                        }
                    }
                }, _callee6, this);
            }));

            function exists(_x7) {
                return ref.apply(this, arguments);
            }

            return exists;
        }()
    }, {
        key: 'set',
        value: function () {
            var ref = _asyncToGenerator(regeneratorRuntime.mark(function _callee7(key, value) {
                var redisValue;
                return regeneratorRuntime.wrap(function _callee7$(_context7) {
                    while (1) {
                        switch (_context7.prev = _context7.next) {
                            case 0:
                                if (!(this.type === 'redis')) {
                                    _context7.next = 8;
                                    break;
                                }

                                if (!(!key || !this.client || !this.client.set)) {
                                    _context7.next = 3;
                                    break;
                                }

                                return _context7.abrupt('return');

                            case 3:
                                redisValue = (typeof value === 'undefined' ? 'undefined' : _typeof(value)) === 'object' ? JSON.stringify(value) : value;
                                _context7.next = 6;
                                return this.client.set(key, redisValue);

                            case 6:
                                _context7.next = 8;
                                return this.client.ttl(key);

                            case 8:
                            case 'end':
                                return _context7.stop();
                        }
                    }
                }, _callee7, this);
            }));

            function set(_x8, _x9) {
                return ref.apply(this, arguments);
            }

            return set;
        }()
    }, {
        key: 'get',
        value: function () {
            var ref = _asyncToGenerator(regeneratorRuntime.mark(function _callee10(key) {
                var _this2 = this;

                var _ret2;

                return regeneratorRuntime.wrap(function _callee10$(_context10) {
                    while (1) {
                        switch (_context10.prev = _context10.next) {
                            case 0:
                                if (!(this.type === 'redis')) {
                                    _context10.next = 5;
                                    break;
                                }

                                return _context10.delegateYield(regeneratorRuntime.mark(function _callee9() {
                                    var client, redisValue;
                                    return regeneratorRuntime.wrap(function _callee9$(_context9) {
                                        while (1) {
                                            switch (_context9.prev = _context9.next) {
                                                case 0:
                                                    if (!(!key || !_this2.client || !_this2.client.get)) {
                                                        _context9.next = 2;
                                                        break;
                                                    }

                                                    return _context9.abrupt('return', {
                                                        v: null
                                                    });

                                                case 2:
                                                    client = _this2.client;
                                                    _context9.next = 5;
                                                    return (0, _co2.default)(regeneratorRuntime.mark(function _callee8() {
                                                        return regeneratorRuntime.wrap(function _callee8$(_context8) {
                                                            while (1) {
                                                                switch (_context8.prev = _context8.next) {
                                                                    case 0:
                                                                        _context8.next = 2;
                                                                        return client.get(key);

                                                                    case 2:
                                                                        return _context8.abrupt('return', _context8.sent);

                                                                    case 3:
                                                                    case 'end':
                                                                        return _context8.stop();
                                                                }
                                                            }
                                                        }, _callee8, this);
                                                    }));

                                                case 5:
                                                    redisValue = _context9.sent;

                                                    if (!(redisValue && typeof redisValue === 'string')) {
                                                        _context9.next = 10;
                                                        break;
                                                    }

                                                    return _context9.abrupt('return', {
                                                        v: JSON.parse(redisValue)
                                                    });

                                                case 10:
                                                    return _context9.abrupt('return', {
                                                        v: redisValue
                                                    });

                                                case 11:
                                                case 'end':
                                                    return _context9.stop();
                                            }
                                        }
                                    }, _callee9, _this2);
                                })(), 't0', 2);

                            case 2:
                                _ret2 = _context10.t0;

                                if (!((typeof _ret2 === 'undefined' ? 'undefined' : _typeof(_ret2)) === "object")) {
                                    _context10.next = 5;
                                    break;
                                }

                                return _context10.abrupt('return', _ret2.v);

                            case 5:
                            case 'end':
                                return _context10.stop();
                        }
                    }
                }, _callee10, this);
            }));

            function get(_x10) {
                return ref.apply(this, arguments);
            }

            return get;
        }()
    }]);

    return Store;
}();
// Redis store


var RedisStore = function (_Store) {
    _inherits(RedisStore, _Store);

    function RedisStore(opts) {
        _classCallCheck(this, RedisStore);

        var _this3 = _possibleConstructorReturn(this, Object.getPrototypeOf(RedisStore).call(this, opts));

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