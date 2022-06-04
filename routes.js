import Router from '@koa/router'
import { PrismaClient } from '@prisma/client'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'

import { errorHandler } from './utils/errorHandler.js'

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

    ctx.body = { ...user, password: undefined }
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

router.get('/tweets', async ctx => {
  try {
    const [, token] = ctx.request.headers?.authorization?.split(' ') ?? []

    jwt.verify(token, process.env.JWT_SECRET)

    const tweets = ctx.query.id
      ? await prisma.tweet.findUnique({
        where: {
          id: ctx.query.id,
        }
      })
      : await prisma.tweet.findMany()

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
  if (!ctx.query.id) {
    ctx.status = 400
    ctx.body = { message: 'Bad Request', description: 'No tweet id informed.' }
    return
  }

  try {
    const tweet = await prisma.tweet.delete({
      where: {
        id: ctx.query.id,
      }
    })
    ctx.body = tweet
  } catch (error) {
    const [httpCode, payload] = errorHandler(error)
    ctx.status = httpCode
    ctx.body = payload
  }
})
