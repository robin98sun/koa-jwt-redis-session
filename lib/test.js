'use strict';

require('babel-polyfill');

var _supertestKoaAgent = require('supertest-koa-agent');

var _supertestKoaAgent2 = _interopRequireDefault(_supertestKoaAgent);

var _should = require('should');

var _should2 = _interopRequireDefault(_should);

var _koa = require('koa');

var _koa2 = _interopRequireDefault(_koa);

var _koaConvert = require('koa-convert');

var _koaConvert2 = _interopRequireDefault(_koaConvert);

var _koaBodyparser = require('koa-bodyparser');

var _koaBodyparser2 = _interopRequireDefault(_koaBodyparser);

var _index = require('./index.js');

var _index2 = _interopRequireDefault(_index);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _asyncToGenerator(fn) { return function () { var gen = fn.apply(this, arguments); return new Promise(function (resolve, reject) { function step(key, arg) { try { var info = gen[key](arg); var value = info.value; } catch (error) { reject(error); return; } if (info.done) { resolve(value); } else { return Promise.resolve(value).then(function (value) { return step("next", value); }, function (err) { return step("throw", err); }); } } return step("next"); }); }; }

describe('Testing jwt-redis-session', function () {
    var app = new _koa2.default();
    app.use((0, _koaBodyparser2.default)({
        onerror: function onerror(err, ctx) {
            debug(DEBUG_LOG_HEADER, 'Body parser error:', err);
        }
    }));

    app.use((0, _index2.default)({
        session: {
            sidKey: 'sid'
        }
    }));

    app.use(function () {
        var ref = _asyncToGenerator(regeneratorRuntime.mark(function _callee(ctx, next) {
            return regeneratorRuntime.wrap(function _callee$(_context) {
                while (1) {
                    switch (_context.prev = _context.next) {
                        case 0:
                            if (!(ctx.path === '/test' && ctx.method.toUpperCase() === 'PUT')) {
                                _context.next = 4;
                                break;
                            }

                            if (ctx.session && ctx.session.sid) {
                                ctx.body = { status: 'OK' };
                            } else {
                                ctx.body = { status: 'ERROR' };
                            }
                            _context.next = 6;
                            break;

                        case 4:
                            _context.next = 6;
                            return next();

                        case 6:
                        case 'end':
                            return _context.stop();
                    }
                }
            }, _callee, this);
        }));

        return function (_x, _x2) {
            return ref.apply(this, arguments);
        };
    }());

    var token = null;
    it('Should get authorization token', function (done) {
        (0, _supertestKoaAgent2.default)(app).post('/authorize').send({ account: 'test', password: 'test' }).expect(200).expect(function (res) {
            token = res.body.token;
            res.body.should.have.property('token');
        }).end(done);
    });

    it('Access to protected resource with token should success', function (done) {
        (0, _supertestKoaAgent2.default)(app).put('/test').set('Authorization', 'Bearer ' + token).expect(200).expect(function (res) {
            res.body.should.have.property('status', 'OK');
        }).end(done);
    });
});