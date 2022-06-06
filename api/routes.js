import Router from '@koa/router'
import { PrismaClient } from '@prisma/client'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'

import { errorHandler } from '../utils/errorHandler.js'

export const router = new Router()

const prisma = new PrismaClient()

router.post('/signup', async ctx => {
  const SALT_ROUNDS = 10
  const hashedPassword = bcrypt.hashSync(
    ctx.request.body.password,
    SALT_ROUNDS
  )

  try {
    const user = await prisma.user.create({
      data: {
        name: ctx.request.body.name,
        username: ctx.request.body.username,
        email: ctx.request.body.email,
        password: hashedPassword,
      }
    })

    const accessToken = jwt.sign({
      sub: user.id
    }, process.env.JWT_SECRET, { expiresIn: '24h' })

    ctx.body = { ...user, accessToken, password: undefined }
  } catch (error) {
    const [httpCode, payload] = errorHandler(error)
    ctx.status = httpCode
    ctx.body = payload
  }
})

router.get('/login', async ctx => {
  const [, token] = ctx.request.headers.authorization.split(' ')
  const [email, password] = Buffer.from(token, 'base64').toString().split(':')

  const user = await prisma.user.findUnique({
    where: { email }
  })
  if (!user) {
    ctx.status = 404
    ctx.body = { status: 404, message: 'Not Found' }
    return
  }

  const passwordMatch = bcrypt.compareSync(password, user.password)
  if (!passwordMatch) {
    ctx.status = 401
    ctx.body = { status: 401, message: 'Unauthorized' }
    return
  }

  const accessToken = jwt.sign({
    sub: user.id
  }, process.env.JWT_SECRET, { expiresIn: '24h' })

  ctx.body = { ...user, accessToken, password: undefined }
})

router.get('/users', async ctx => {
  try {
    const [, token] = ctx.request.headers?.authorization?.split(' ') ?? []

    const payload = jwt.verify(token, process.env.JWT_SECRET)

    const user = await prisma.user.findUnique({
      where: {
        id: payload.sub,
      }
    })

    ctx.body = { ...user, password: undefined }
  } catch (error) {
    const [httpCode, payload] = errorHandler(error)
    ctx.status = httpCode
    ctx.body = payload
  }
})

router.patch('/users', async ctx => {
  try {
    if (!ctx.request.body) {
      ctx.status = 400
      ctx.body = { status: 400, message: 'Bad Request' }
      return
    }

    const [, token] = ctx.request.headers?.authorization?.split(' ') ?? []

    const payload = jwt.verify(token, process.env.JWT_SECRET)

    const user = await prisma.user.update({
      where: {
        id: payload.sub,
      },
      data: {
        avatar: ctx.request.body?.avatar,
        name: ctx.request.body?.name,
        email: ctx.request.body?.email,
        username: ctx.request.body?.username,
      },
    })

    ctx.body = { ...user, password: undefined }
  } catch (error) {
    const [httpCode, payload] = errorHandler(error)
    ctx.status = httpCode
    ctx.body = payload
  }
})

router.get('/tweets', async ctx => {
  try {
    const [, token] = ctx.request.headers?.authorization?.split(' ') ?? []

    jwt.verify(token, process.env.JWT_SECRET)

    const tweets = ctx.query.id
      ? await prisma.tweet.findUnique({
        where: {
          id: ctx.query.id,
        },
        include: {
          user: true,
          likes: true,
        }
      })
      : await prisma.tweet.findMany({
        orderBy: [{
          created_at: 'desc',
        }],
        include: {
          user: true,
          likes: true,
        }
      })

    ctx.body = tweets
  } catch (error) {
    const [httpCode, payload] = errorHandler(error)
    ctx.status = httpCode
    ctx.body = payload
  }
})

router.post('/tweets', async ctx => {
  try {
    const [, token] = ctx.request.headers?.authorization?.split(' ') ?? []

    const payload = jwt.verify(token, process.env.JWT_SECRET)

    const tweet = await prisma.tweet.create({
      data: {
        userId: payload.sub,
        text: ctx.request.body.text,
      },
    })

    ctx.body = tweet
  } catch (error) {
    const [httpCode, payload] = errorHandler(error)
    ctx.status = httpCode
    ctx.body = payload
  }
})

router.delete('/tweets', async ctx => {
  try {
    if (!ctx.query.id) {
      ctx.status = 400
      ctx.body = { status: 400, message: 'Bad Request', description: 'No tweet id informed.' }
      return
    }

    const [, token] = ctx.request.headers?.authorization?.split(' ') ?? []
    const payload = jwt.verify(token, process.env.JWT_SECRET)
    const tweet = await prisma.tweet.findUnique({
      where: {
        id: ctx.query.id,
      }
    })

    if (tweet.userId === payload.sub) {
      const tweet = await prisma.tweet.delete({
        where: {
          id: ctx.query.id,
        }
      })
      ctx.body = tweet
      return
    }

    ctx.status = 403
    ctx.body = { status: 403, message: 'Forbidden' }
  } catch (error) {
    const [httpCode, payload] = errorHandler(error)
    ctx.status = httpCode
    ctx.body = payload
  }
})

router.get('/likes', async ctx => {
  try {
    if (!ctx.query.tweetId) {
      ctx.status = 400
      ctx.body = { status: 400, message: 'Bad Request', description: 'No tweet id informed.' }
      return
    }

    const [, token] = ctx.request.headers?.authorization?.split(' ') ?? []
    const payload = jwt.verify(token, process.env.JWT_SECRET)

    const like = await prisma.like.findUnique({
      where: {
        userId_tweetId: {
          userId: payload.sub,
          tweetId: ctx.query.tweetId,
        }
      }
    })
    ctx.body = like
  } catch (error) {
    const [httpCode, payload] = errorHandler(error)
    ctx.status = httpCode
    ctx.body = payload
  }
})

router.post('/likes', async ctx => {
  try {
    if (!ctx.query.tweetId) {
      ctx.status = 400
      ctx.body = { status: 400, message: 'Bad Request', description: 'No tweet id informed.' }
      return
    }

    const [, token] = ctx.request.headers?.authorization?.split(' ') ?? []
    const payload = jwt.verify(token, process.env.JWT_SECRET)

    const like = await prisma.like.create({
      data: {
        userId: payload.sub,
        tweetId: ctx.query.tweetId,
      }
    })
    ctx.body = like
  } catch (error) {
    const [httpCode, payload] = errorHandler(error)
    ctx.status = httpCode
    ctx.body = payload
  }
})

router.delete('/likes', async ctx => {
  try {
    if (!ctx.query.tweetId) {
      ctx.status = 400
      ctx.body = { status: 400, message: 'Bad Request', description: 'No tweet id informed.' }
      return
    }

    const [, token] = ctx.request.headers?.authorization?.split(' ') ?? []
    const payload = jwt.verify(token, process.env.JWT_SECRET)

    const like = await prisma.like.delete({
      where: {
        userId_tweetId: {
          userId: payload.sub,
          tweetId: ctx.query.tweetId,
        }
      }
    })
    ctx.body = like
  } catch (error) {
    const [httpCode, payload] = errorHandler(error)
    ctx.status = httpCode
    ctx.body = payload
  }
})

router.get('/bookmarks', async ctx => {
  try {
    const [, token] = ctx.request.headers?.authorization?.split(' ') ?? []
    const payload = jwt.verify(token, process.env.JWT_SECRET)

    const bookmark = ctx.query.tweetId
      ? await prisma.bookmark.findUnique({
        where: {
          userId_tweetId: {
            userId: payload.sub,
            tweetId: ctx.query.tweetId,
          }
        }
      })
      : await prisma.bookmark.findMany({
        where: {
          userId: payload.sub,
        },
        orderBy: [{
          created_at: 'desc',
        }],
        include: {
          tweet: {
            include: {
              user: true,
              likes: true,
            }
          },
        }
      })

    ctx.body = bookmark
  } catch (error) {
    const [httpCode, payload] = errorHandler(error)
    ctx.status = httpCode
    ctx.body = payload
  }
})

router.post('/bookmarks', async ctx => {
  try {
    if (!ctx.query.tweetId) {
      ctx.status = 400
      ctx.body = { status: 400, message: 'Bad Request', description: 'No tweet id informed.' }
      return
    }

    const [, token] = ctx.request.headers?.authorization?.split(' ') ?? []
    const payload = jwt.verify(token, process.env.JWT_SECRET)

    const bookmark = await prisma.bookmark.create({
      data: {
        userId: payload.sub,
        tweetId: ctx.query.tweetId,
      }
    })
    ctx.body = bookmark
  } catch (error) {
    const [httpCode, payload] = errorHandler(error)
    ctx.status = httpCode
    ctx.body = payload
  }
})

router.delete('/bookmarks', async ctx => {
  try {
    if (!ctx.query.tweetId) {
      ctx.status = 400
      ctx.body = { status: 400, message: 'Bad Request', description: 'No tweet id informed.' }
      return
    }

    const [, token] = ctx.request.headers?.authorization?.split(' ') ?? []
    const payload = jwt.verify(token, process.env.JWT_SECRET)

    const bookmark = await prisma.bookmark.delete({
      where: {
        userId_tweetId: {
          userId: payload.sub,
          tweetId: ctx.query.tweetId,
        }
      }
    })
    ctx.body = bookmark
  } catch (error) {
    const [httpCode, payload] = errorHandler(error)
    ctx.status = httpCode
    ctx.body = payload
  }
})
