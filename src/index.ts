import dotenv from "dotenv"
dotenv.config();

import { Response,Request, NextFunction } from "express";

import express from "express"
import jwt from "jsonwebtoken"
import bcrypt from "bcrypt"
import {z} from "zod"
import { PrismaClient } from "@prisma/client"

const app = express()
const client = new PrismaClient()
const PORT = process.env.PORT
const JWT_SECRET = process.env.JWT_SECRET as string

app.use(express.json())
app.use(express.urlencoded({extended:true}))

type user = {
    username: string;
    email: string;
    password: string;
};

type todo = {
    title:string,
    description: string,
     completed : boolean
};


app.post("/signup",async function(req:Request,res:Response){

    const requiredBody = z.object({
        email:z.string()
          .nonempty({ message: "Email is required" })
        .min(6, { message: "Email must be at least 6 characters long" })
        .max(320, { message: "Email must be less than 320 characters" })
        .email({ message: "Please enter a valid email address" }),


        username:z.string()
                .nonempty({ message: "Username is required" })
        .min(3,{ message: "Username must be at least 3 characters long" })
        .max(30, { message: "Username must be less than 30 characters" }),

        password:z.string()
            .nonempty({ message: "Password is required" })
        .min(5, { message: "Password must be at least 5 characters long"})
        .max(20, { message: "Password must be less than 20 characters" }) 
        .refine(
            (value) => /[A-Z]/.test(value), 
            { message: "Password must contain at least one uppercase letter" }
          )
          .refine(
            (value) => /[a-z]/.test(value), 
            { message: "Password must contain at least one lowercase letter" }
          )
          .refine(
            (value) => /[!@#$%^&*(),.?":{}|<>]/.test(value), 
            { message: "Password must contain at least one special character" }
          )
          .refine((value) => /[0-9]/.test(value), {
            message: "Password must contain at least one number"
        })
    })

    const result = requiredBody.safeParse(req.body)

        if (!result.success) {
         res.send({
            message:"Incorrect Format", 
            error:result.error.issues[0].message
        })
        return
    }
   

    try {
        
         const {username, email, password}:user = result.data 

         const existUser = await client.user.findFirst({
            where:{
                email
            }
         })

         if (existUser) {
             res.status(400).send({
                message: "user  already exists..."
            })
        }

        const hashPassword = await bcrypt.hash(password,10)

        const user = await client.user.create({
            data:{
                username,
                email,
                password:hashPassword

            }
        })

               if (user) {
             res.status(201).send({
                message:"you are signed up..."
            })
        }
        else{
            // else block is optional
             res.status(500).send({
                message:"user was not created"
            })

        }

    } catch (error) {
        
          console.error(error);  // Log the error for debugging

       res.status(500).send({
        message:`Internal server error `,
        // error: error.message
       }) 
    

    }

})


app.post("/signin",async function(req:Request,res:Response){

    const requiredBody = z.object({
        email:z.string()
          .nonempty({ message: "Email is required" })
        .min(6, { message: "Email must be at least 6 characters long" })
        .max(320, { message: "Email must be less than 320 characters" })
        .email({ message: "Please enter a valid email address" }),


        password:z.string()
            .nonempty({ message: "Password is required" })
        .min(5, { message: "Password must be at least 5 characters long"})
        .max(20, { message: "Password must be less than 20 characters" }) 
    })

    const result = requiredBody.safeParse(req.body)

        if (!result.success) {
         res.send({
            message:"Incorrect Format", 
            error:result.error.issues[0].message
        })
        return
    }
   

    try {
        
         const {email, password} = result.data 

         const user = await client.user.findFirst({
            where:{
                email
            }
         })

         if (!user) {
             res.status(400).send({
                message: "user does not exists in our database. you have to signup first..."
            })
            return
        }

      const passwordMatch = await bcrypt.compare(password, user.password)

               if (passwordMatch) {

                const token = jwt.sign({
                    id:user.id
                },JWT_SECRET)

             res.status(201).send({
                message:"you are sign in...",
                user,
                token
            })
        }
        else{
            // else block is optional
             res.status(500).send({
                message:"user was not created"
            })

        }

    } catch (error) {
        
          console.error(error);  // Log the error for debugging

       res.status(500).send({
        message:`Internal server error `,
        // error: error.message
       }) 
    

    }

})


function Auth(req:Request,res:Response,next:NextFunction):void{

    const token = req.headers.token

     if (!token) {
         res.send({
            message:"token is required.."
        })
    }

     try {
        const decodedInformation = jwt.verify(token as string, JWT_SECRET);

          //@ts-ignore
        req.userId = decodedInformation.id; // Attach user ID to the request

        next(); // Proceed to the next middleware/route

    } catch (error) {

         res.send({
            message: "Invalid or expired token",
        
        });
    }
}



app.get("/me",Auth,async function(req,res){

    //@ts-ignore
    const id = req.userId

    try {
        
         const user = await client.user.findFirst({
        where:{
            id
        },
        select:{
            id:true,
            username:true,
            email:true
        }
    })

    if (!user) {
       res.status(404).send({
        message: "User not found",
      });
      return
    }

     res.status(200).send({
      message: "User details fetched successfully",
      user
    });

    } catch (error) {
        
         console.error("Fetch user error:", error);
    res.status(500).send({
      message: "Internal server error",
    });
    }

})



app.get("/allDetail",Auth,async function(req,res){

    //@ts-ignore
    const id = req.userId

    try {
        
         const user = await client.user.findFirst({
        where:{
            id
        },
        select:{
            id:true,
            username:true,
            email:true,
            todos:true
        },
        
    })

    if (!user) {
       res.status(404).send({
        message: "User not found",
      });
      return
    }

     res.status(200).send({
      message: "User details fetched successfully",
      user
    });

    } catch (error) {
        
         console.error("Fetch user error:", error);
    res.status(500).send({
      message: "Internal server error",
    });
    }

})




app.post("/todo",Auth,async function(req:Request,res:Response){

    const parseData = z.object({
        title: z.string().min(3, "Title must be at least 3 characters").max(100, "Title too long"),
        description:z.string().max(1000),
        completed: z.boolean().optional().default(false)
   
    })

    const result = parseData.safeParse(req.body)


    if (!result.success) {
         res.status(400).send({
            message: "Incorrect format",
            // error: result.message
        })
    }

      const {title, description, completed}:todo = req.body

      try {
        
        const todo = await client.todo.create({
            data:{
                title,
                description,
                completed,
                // @ts-ignore
                userId: req.userId
            }
        })

 if (todo) {
             res.status(201).send({ // 201 for successful creation
                message: "todo  created successfylly",
                todo
            })
        }else{
             res.send({
                message: "todo is not created ",
            })
        }

      } catch (error) {
         console.log("Todo creation error :",error);

        res.status(500).send({
            message:"Internal server error",
            error
        })
      }
})


app.get("/todo",Auth, async function(req,res){

    try {
        
        const todos = await client.todo.findMany({
           where:{
            //@ts-ignore
            userId: req.userId
           }
        })

        if (todos.length > 0) {
             res.status(200).send({
                message: "All Todos here",
                todos
            })
        }else{

             res.status(404).send({
                message: "No todos found for this user."
            });
        }

    } catch (error) {
        console.log(error);

        res.status(500).send({
            message: "Internal server error",
            // error: error.message
        })
        
    }
})


app.get("/todo/:id",Auth, async function(req,res){

 const todoId = Number(req.params.id )
    try {
        
        const todo = await client.todo.findFirst({
            where:{
                id:todoId
            }
        })

        if (todo) {
             res.status(200).send({
                message: " Todo retrieved successfully",
                todo
            })
        }else{

             res.status(404).send({
                message: "No todo found for this user."
            });
        }

    } catch (error) {
        console.log(error);

        res.status(500).send({
            message: "Internal server error",
            // error: error.message
        })
        
    }
})



app.put("/todo/:id",Auth, async function(req:Request,res:Response){

    const id = Number(req.params.id )

    const {title,description, completed} = req.body 
    try {
        
    const todo = await client.todo.update({
        where:{
            id
        },
        data:{
           title,
           description,
            completed 
        }
    })

    if (todo) {
        res.status(201).send({
            message: "todo updated successfully",
            todo
        })
    }else{

           res.status(404).send({
           message: "Todo not found or you are not authorized to update it"
        })
    }


    } catch (error) {

        res.status(500).send({
            message:"Internal server error",
            // error: error.message
        })
        
    }

})



app.delete("/todo/:id",Auth,async function(req,res){

    const id = Number(req.params.id )
    try {
        
    const todo = await client.todo.delete({
        where:{
            id 
        }
    })

    if (todo) {
        res.status(201).send({
            message: "todo deleted successfully",
            todo
        })
    }else{

           res.status(404).send({
           message: "Todo not found or you are not authorized to delete it"
        })
    }


    } catch (error) {

        res.status(500).send({
            message:"Internal server error",
            // error: error.message
        })
        
    }

})






app.listen(PORT,function(){
    console.log(`server is running on PORT : ${PORT}.....`);
    
})