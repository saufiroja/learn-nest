import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}
  async signup(dto: AuthDto) {
    // generate hash password
    const hash = await argon.hash(dto.password);
    // save new user
    try {
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash,
        },
        // select: {
        //   id: true,
        //   email: true,
        //   createdAt: true,
        // },
      });
      delete user.hash; //(select)

      // return new user
      return user;
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        console.log(error);
        if (error.code === 'P2002') {
          throw new ForbiddenException('Credentials taken');
        }
      }
      throw error;
    }
  }

  async login(dto: AuthDto) {
    // find user by email
    const user = await this.prisma.user.findFirst({
      where: {
        email: dto.email,
      },
    });
    // if user does not exists throw exception
    if (!user) {
      throw new ForbiddenException('Credential incorrect email');
    }

    // compare password
    const matches = await argon.verify(user.hash, dto.password);
    // if password incorrect throw exception
    if (!matches) {
      throw new ForbiddenException('Credential incorrect password');
    }

    delete user.hash;

    return user;
  }
}
