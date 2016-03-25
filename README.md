# koa-jwt-redis-session
JWT Redis Session for Koa 2
---------------------------

Pure JWT implementation using Redis as session storage for Koa 2, without any cookies

Quick Start
===========

```javascript
const koa = require('koa'),
      bodyParser = require('koa-bodyparser'),
      session = require('koa-jwt-redis-session')
// import session from 'koa-jwt-redis-session'

const app = new koa()
app.use(bodyParser())

app.use(session.default())

// If using import
// app.use(session()) 

app.use(async function(ctx, next){
    let views = ctx.session.views || 0
    ctx.session.views = ++views
    try{
       ctx.body = {views: ctx.session.views}
       await next()
    }catch(ex){
       console.error('something wrong:', ex)
       ctx.status = 500
       ctx.body = 'something wrong'
    }
})

app.listen(3333)
```

Options
=======

When creating session instance, you can pass in an option object 

```javascript
const sessionOptions = {
       // ......
}
app.use(session.default(sessionOptions))

// If using import
app.use(session(sessionOptions))
```

Here is the default option values
---------------------------------

```javascript
{
  jwt: {
    contentType: 'application/json',
    charset: 'utf-8',
    secret: 'koa-jwt-redis-session' + new Date().getTime(),
    authPath: '/authorize',
    registerPath: '/register',
    expiresIn: 3600,
    accountKey: 'account',
    passwordKey: 'password',
    authHandler: function (account, password) {
            if (account && password) return true; else return false;
        },
    registerHandler: function (account, password) {
            if (account && password) return true; else return false;
        }
  },
  session: {
    sessionKey: 'session',
    sidKey: 'koa:sess',
  },
  redis: {
    port: 6379,
    host: '127.0.0.1',
    db: 0,
    ttl: 3600,
    options: {}
  }
}
```

Action flow
===========

1. Anonymous client post JSON user credential information `{ account: "...", password: "..." }` to `/register` to register an account, 
2. or post to `/authorize` to get authorization
3. Client get token in JSON like `{ token: "..." }`, or an `401` error if not authorized
4. From then on, client send every request by the http header: `Authorization: Bearer <token>`,
5. or client would get `401` error if not authorized or *token expired*
6. On the server side, afterward middlewares can operate `ctx.session` as will

Enjoy!
