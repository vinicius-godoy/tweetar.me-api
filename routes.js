import Router from '@koa/router'

export const router = new Router()

router.get('/tweets', ctx => {
  ctx.body = 'tweets'
})
