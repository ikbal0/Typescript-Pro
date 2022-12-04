import { compare, hash } from "bcryptjs";
import { Int, Resolver } from "type-graphql";
import { Arg, Ctx, Field, Mutation, ObjectType, Query, UseMiddleware } from "type-graphql/dist/decorators";
import { getConnection } from "typeorm";
import { createAccessToken, createRefreshToken } from "./auth";
import { User } from "./entity/User";
import { isAuth } from "./isAuthMiddleware";
import { MyContext } from "./MyContext";
import { sendRefreshToken } from "./sendRefreshToken";

@ObjectType()
class LoginResponse {
    @Field()
    accessToken: string
    refreshToken: string
}

@Resolver()
export class UserResolvers {
    @Query(() => String )
    hello() {
        return 'hi'
    }

    @Query(() => [User] )
    users() {
        return User.find();
    }

    @Query(() => String )
    @UseMiddleware(isAuth)
    async bye( @Ctx() {payload}: MyContext) {
        const user = await User.findOne({
            where: {
                email: payload.email
            }
        })

        if(!user) {
            throw new Error("could not find user")
        }

        return `your user id is: ${payload.userId} ${createRefreshToken(user)}`
    }

    @Mutation(() => Boolean)
    async register(
        @Arg('email') email: string,
        @Arg('password') password: string
    ) {

        const hashedPassword = await hash(password, 12)
        try {
            await User.insert({
                email,
                password: hashedPassword
            });
        } catch (error) {
            console.log(error);
            return false;
        }
        return true
    }

    @Mutation(() => Boolean)
    async revokeRefreshTokenForUser(
        @Arg('userId', () => Int) userId : number
    ){
        await getConnection()
        .getRepository(User)
        .increment({id: userId}, 'tokenVersion', 1);

        return true;
    }

    @Mutation(() => LoginResponse)
    async login(
        @Arg('email') email: string,
        @Arg('password') password: string,
        @Ctx() {res}: MyContext
    ): Promise<LoginResponse> {

        const user = await User.findOne({
            where: {
                email
            }
        })

        if(!user) {
            throw new Error("could not find user")
        }

        const valid = await compare(password, user.password)

        if(!valid) {
            throw new Error("password didn't match")
        } else {
            sendRefreshToken(res, createRefreshToken(user));
    
            return {
                refreshToken: createRefreshToken(user),
                accessToken: createRefreshToken(user)
                // accessToken: createAccessToken(user)
            }
        }
    }
}