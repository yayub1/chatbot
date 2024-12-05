const fs = require('fs');
const path = require('path');

const files = [
  {
    path: 'app/layout.tsx',
    content: `
import './globals.css'
import { Inter } from 'next/font/google'

const inter = Inter({ subsets: ['latin'] })

export const metadata = {
  title: 'Gemini Chatbot',
  description: 'A chatbot powered by Gemini AI',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body className={inter.className}>{children}</body>
    </html>
  )
}
    `
  },
  {
    path: 'app/page.tsx',
    content: `
import Link from 'next/link'

export default function Home() {
  return (
    <main className="flex min-h-screen flex-col items-center justify-center p-24">
      <h1 className="text-4xl font-bold mb-8">Welcome to Gemini Chatbot</h1>
      <Link href="/login" className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded">
        Login to Chat
      </Link>
    </main>
  )
}
    `
  },
  {
    path: 'app/login/page.tsx',
    content: `
'use client'

import { useState } from 'react'
import { signInWithPopup, GoogleAuthProvider } from 'firebase/auth'
import { auth } from '@/lib/firebase-client'
import { useRouter } from 'next/navigation'

export default function Login() {
  const [error, setError] = useState('')
  const router = useRouter()

  const handleGoogleLogin = async () => {
    try {
      const provider = new GoogleAuthProvider()
      const result = await signInWithPopup(auth, provider)
      const idToken = await result.user.getIdToken()
      
      const response = await fetch('/api/auth', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ token: idToken }),
      })

      if (response.ok) {
        router.push('/chat')
      } else {
        setError('Failed to authenticate')
      }
    } catch (error) {
      setError('An error occurred during login')
    }
  }

  return (
    <div className="flex min-h-screen flex-col items-center justify-center p-24">
      <h1 className="text-4xl font-bold mb-8">Login</h1>
      <button
        onClick={handleGoogleLogin}
        className="bg-red-500 hover:bg-red-700 text-white font-bold py-2 px-4 rounded"
      >
        Login with Google
      </button>
      {error && <p className="text-red-500 mt-4">{error}</p>}
    </div>
  )
}
    `
  },
  {
    path: 'app/chat/page.tsx',
    content: `
'use client'

import { useState, useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { auth } from '@/lib/firebase-client'

export default function Chat() {
  const [messages, setMessages] = useState([])
  const [input, setInput] = useState('')
  const router = useRouter()

  useEffect(() => {
    const unsubscribe = auth.onAuthStateChanged((user) => {
      if (!user) {
        router.push('/login')
      }
    })

    return () => unsubscribe()
  }, [router])

  const sendMessage = async (e) => {
    e.preventDefault()
    if (!input.trim()) return

    setMessages([...messages, { content: input, userId: 'user' }])
    setInput('')

    try {
      const response = await fetch('/api/chat', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ message: input }),
      })

      if (response.ok) {
        const data = await response.json()
        setMessages((prevMessages) => [
          ...prevMessages,
          { content: data.response, userId: 'ai' },
        ])
      } else {
        console.error('Failed to send message')
      }
    } catch (error) {
      console.error('Error sending message:', error)
    }
  }

  return (
    <div className="flex flex-col h-screen">
      <div className="flex-1 overflow-y-auto p-4">
        {messages.map((message, index) => (
          <div
            key={index}
            className={\`mb-4 \${
              message.userId === 'user' ? 'text-right' : 'text-left'
            }\`}
          >
            <span
              className={\`inline-block p-2 rounded-lg \${
                message.userId === 'user'
                  ? 'bg-blue-500 text-white'
                  : 'bg-gray-200 text-black'
              }\`}
            >
              {message.content}
            </span>
          </div>
        ))}
      </div>
      <form onSubmit={sendMessage} className="p-4 border-t">
        <div className="flex">
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            className="flex-1 p-2 border rounded-l-lg"
            placeholder="Type your message..."
          />
          <button
            type="submit"
            className="bg-blue-500 text-white p-2 rounded-r-lg"
          >
            Send
          </button>
        </div>
      </form>
    </div>
  )
}
    `
  },
  {
    path: 'app/api/auth/route.ts',
    content: `
import { auth } from '@/lib/firebase'
import { NextResponse } from 'next/server'

export async function POST(request: Request) {
  try {
    const { token } = await request.json()
    
    // Verify the Firebase ID token
    const decodedToken = await auth.verifyIdToken(token)
    
    // Create session cookie
    const expiresIn = 60 * 60 * 24 * 5 * 1000 // 5 days
    const sessionCookie = await auth.createSessionCookie(token, { expiresIn })
    
    return new NextResponse(JSON.stringify({ success: true }), {
      headers: {
        'Set-Cookie': \`session=\${sessionCookie}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=\${expiresIn}\`,
      },
    })
  } catch (error) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }
}
    `
  },
  {
    path: 'app/api/chat/route.ts',
    content: `
import { auth, db } from '@/lib/firebase'
import { NextResponse } from 'next/server'
import { cookies } from 'next/headers'

export async function POST(request: Request) {
  try {
    // Verify authentication
    const sessionCookie = cookies().get('session')?.value
    if (!sessionCookie) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }
    
    const decodedClaim = await auth.verifySessionCookie(sessionCookie)
    const { message } = await request.json()
    
    // Store message in Firestore
    const chatRef = db.collection('chats').doc(decodedClaim.uid)
    await chatRef.collection('messages').add({
      content: message,
      timestamp: new Date(),
      userId: decodedClaim.uid
    })
    
    // Generate AI response using the Gemini API
    const response = await fetch(
      \`https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash-latest:generateContent?key=\${process.env.GEMINI_API_KEY}\`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          contents: [
            {
              parts: [
                {
                  text: message,
                },
              ],
            },
          ],
        }),
      }
    )
    
    const data = await response.json()
    const aiResponse = data.candidates[0].content.parts[0].text
    
    // Store AI response
    await chatRef.collection('messages').add({
      content: aiResponse,
      timestamp: new Date(),
      userId: 'ai'
    })
    
    return NextResponse.json({ response: aiResponse })
  } catch (error) {
    return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 })
  }
}
    `
  },
  {
    path: 'lib/firebase.ts',
    content: `
import { initializeApp, getApps } from 'firebase-admin/app'
import { getAuth } from 'firebase-admin/auth'
import { getFirestore } from 'firebase-admin/firestore'

if (!getApps().length) {
  initializeApp({
    credential: require('firebase-admin').credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\\n')
    })
  })
}

export const auth = getAuth()
export const db = getFirestore()
    `
  },
  {
    path: 'lib/firebase-client.ts',
    content: `
import { initializeApp, getApps } from 'firebase/app'
import { getAuth } from 'firebase/auth'

const firebaseConfig = {
  apiKey: process.env.NEXT_PUBLIC_FIREBASE_API_KEY,
  authDomain: process.env.NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN,
  projectId: process.env.NEXT_PUBLIC_FIREBASE_PROJECT_ID,
  storageBucket: process.env.NEXT_PUBLIC_FIREBASE_STORAGE_BUCKET,
  messagingSenderId: process.env.NEXT_PUBLIC_FIREBASE_MESSAGING_SENDER_ID,
  appId: process.env.NEXT_PUBLIC_FIREBASE_APP_ID
}

const app = getApps().length ? getApps()[0] : initializeApp(firebaseConfig)
export const auth = getAuth(app)
    `
  },
  {
    path: 'middleware.ts',
    content: `
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
    `
  }
];

files.forEach(file => {
  const filePath = path.join(process.cwd(), file.path);
  const dir = path.dirname(filePath);
  
  if (!fs.existsSync(dir)){
    fs.mkdirSync(dir, { recursive: true });
  }
  
  fs.writeFileSync(filePath, file.content.trim());
  console.log(`Created ${file.path}`);
});

console.log('All files have been created successfully!');