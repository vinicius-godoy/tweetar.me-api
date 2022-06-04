import { Prisma } from '@prisma/client'
import jwt from 'jsonwebtoken'

export const errorHandler = (error) => {
  console.log({ error })
  let status = 500
  let body = { status: 500, message: 'Internal Server Error' }

  if (error instanceof jwt.JsonWebTokenError) {
    switch (error.message) {
      case 'jwt malformed':
        status = 401
        body = {
          status: 401,
          message: 'Unauthorized',
        }
        break
      case 'jwt must be provided':
        status = 401
        body = {
          status: 401,
          message: 'Unauthorized',
        }
        break
      default:
        status = 500
        body = { status: 500, message: 'Internal Server Error' }
        break
    }
  }

  if (error instanceof Prisma.PrismaClientKnownRequestError) {
    switch (error.code) {
      case 'P2002':
        status = 422
        body = {
          status: 422,
          message: 'Unprocessable Entity',
          description: `${error?.meta?.target ?? 'One of the fields'} already exists.`,
        }
        break
      case 'P2025':
        status = 404
        body = {
          status: 404,
          message: 'Not Found',
          description: 'Record to be deleted does not exist.',
        }
        break
      default:
        status = 500
        body = { status: 500, message: 'Internal Server Error' }
        break
    }
  }

  return [status, body]
}
