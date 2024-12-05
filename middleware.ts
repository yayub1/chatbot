import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'
import { auth } from './lib/firebase'

export async function middleware(request: NextRequest) {
  const session = request.cookies.get('session')

  // Return to /login if don't have a session
  if (!session) {
    return NextResponse.redirect(new URL('/login', request.url))
  }

  try {
    // Verify session
    await auth.verifySessionCookie(session.value)
    return NextResponse.next()
  } catch (error) {
    return NextResponse.redirect(new URL('/login', request.url))
  }
}

export const config = {
  matcher: ['/chat/:path*']
}