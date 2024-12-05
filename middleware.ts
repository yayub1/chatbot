import { NextResponse } from 'next/server'
<<<<<<< Tabnine <<<<<<<
import type { NextRequest } from 'next/server'
>>>>>>> Tabnine >>>>>>>// {"conversationId":"fbf09297-9077-4db1-9103-e728064a1ef0","source":"instruct"}
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
