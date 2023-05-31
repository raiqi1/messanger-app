import bcrypt from "bcrypt"

import prisma from "@/app/libs/prismaDb"
import { NextResponse } from "next/server"

export async function POST (request: Request) {
    try {
        // take all request from register form 
    const body = await request.json()
    const { email, password, name } = body
    
    if(!email ||!password || !name) {
        return new NextResponse('Missing Info', {status:400})
    }

    // hashed password 
    const hashedPassword = await bcrypt.hash(password,12)

    // create user 
    const user = await prisma.user.create({
        data: {
            email,
            name,
            hashedPassword
        }
    })

    return NextResponse.json(user)
    } catch(error :any) {
        console.log(error,'REGISTRATION_ERROR')
        return new NextResponse('Internal Error',{status:500})
    }
}