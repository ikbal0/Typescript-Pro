import "reflect-metadata";
import express from "express";
import "dotenv/config";
import { ApolloServer } from "apollo-server-express";
import { ApolloServerPluginLandingPageLocalDefault, ApolloServerPluginLandingPageProductionDefault } from "apollo-server-core";
import { UserResolvers } from "./resolvers";
import { buildSchema } from "type-graphql/dist/utils";
import { AppDataSource } from "./data-source";
import cookieParser from "cookie-parser";
import { verify } from "jsonwebtoken";
import { User } from "./entity/User";
import { createAccessToken, createRefreshToken } from "./auth";
import { sendRefreshToken } from "./sendRefreshToken";

( async() => {
    const app = express();
    const port = process.env.PORT;

    app.use(cookieParser())

    app.get('/', (_req, res) => {
        res.send("hello")
    })

    app.post("/refresh_token", async (req, res) => {
        const token = req.cookies.jid
        if (!token) {
            return res.send({ ok: false, accessToken: ''});
        }

        let payload: any = null;
        try {
            payload = verify(token, process.env.REFRESH_TOKEN_SECRET)
        } catch (error) {
            console.log(error);
            return res.send({ ok: false, accessToken: ''});
        }

        const user = await User.findOne({where: {id: payload.userId}});

        if(!user) {
            return res.send({ ok: false, accessToken: ''});
        }

        if(user.tokenVersion !== payload.tokenVersion) {
            return res.send({ ok: false, accessToken: ''});
        } else {
            sendRefreshToken(res, createRefreshToken(user));
    
            return res.send({ ok: true, accessToken: createAccessToken(user)});
        }
    })

    await AppDataSource.initialize()

    const server = new ApolloServer({
        schema: await buildSchema({
            resolvers: [UserResolvers],
        }),
        context:({req, res}) => ({req, res}),
        plugins: [
            process.env.NODE_ENV === "production"
            ? ApolloServerPluginLandingPageProductionDefault({
                embed: true,
                graphRef: "plaid-gufzoj@current"
                })
            : ApolloServerPluginLandingPageLocalDefault({ 
                embed: true 
            })
        ]
    });

    await server.start()

    server.applyMiddleware({ app })

    app.listen(port, () => {
        console.log(`server run on http://localhost:${port}`)
    })
})()


// AppDataSource.initialize().then(async () => {

//     console.log("Inserting a new user into the database...")
//     const user = new User()
//     user.firstName = "Timber"
//     user.lastName = "Saw"
//     user.age = 25
//     await AppDataSource.manager.save(user)
//     console.log("Saved a new user with id: " + user.id)

//     console.log("Loading users from the database...")
//     const users = await AppDataSource.manager.find(User)
//     console.log("Loaded users: ", users)

//     console.log("Here you can setup and run express / fastify / any other framework.")

// }).catch(error => console.log(error))
