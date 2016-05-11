'use strict'
import 'babel-polyfill'
import request from 'supertest-koa-agent'
import should from 'should'
import koa from 'koa'
import convert from 'koa-convert'
import bodyParser from 'koa-bodyparser'
import session from './index.js'
import {createSession} from './index.js'

describe('Testing jwt-redis-session', function(){
    const app = new koa();
    app.use(bodyParser({
        onerror: function(err, ctx){
            debug(DEBUG_LOG_HEADER, 'Body parser error:', err)
        }
    }));

    app.use(session({
        session: {
            sidKey: 'sid'
        }
    }));

    app.use(async function(ctx, next){
        if(ctx.path === '/test' && ctx.method.toUpperCase() === 'PUT'){
            if(ctx.session && ctx.session.sid) {
                ctx.body = {status:'OK'};
            } else {
                ctx.body = {status:'ERROR'};
            }
        }else{
            await next();
        }
    })

    it('Should generate token directly from createSession function', async ()=>{
        let ctxObj = {}, userObj = {account: 'test'};
        let token = await createSession(ctxObj,userObj);
        token.should.have.property('token');
        token.should.have.property('expiresIn');
        ctxObj.should.have.property('user');
        userObj.should.have.property('_sessionId');

    });

    let token = null;
    it('Should get authorization token', function(done){
        request(app).post('/authorize')
            .send({account: 'test', password: 'test'})
            .expect(200)
            .expect(function(res){
                token = res.body.token;
                res.body.should.have.property('token')
            })
            .end(done)
    });

    it('Access to protected resource with token should success', function (done) {
        request(app).put('/test')
            .set('Authorization', 'Bearer ' + token)
            .expect(200)
            .expect(function(res){
                res.body.should.have.property('status', 'OK');
            })
            .end(done)
    });
})
