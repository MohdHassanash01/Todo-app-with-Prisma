"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const dotenv_1 = __importDefault(require("dotenv"));
dotenv_1.default.config();
const express_1 = __importDefault(require("express"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const bcrypt_1 = __importDefault(require("bcrypt"));
const zod_1 = require("zod");
const client_1 = require("@prisma/client");
const app = (0, express_1.default)();
const client = new client_1.PrismaClient();
const PORT = process.env.PORT;
const JWT_SECRET = process.env.JWT_SECRET;
app.use(express_1.default.json());
app.use(express_1.default.urlencoded({ extended: true }));
app.post("/signup", function (req, res) {
    return __awaiter(this, void 0, void 0, function* () {
        const requiredBody = zod_1.z.object({
            email: zod_1.z.string()
                .nonempty({ message: "Email is required" })
                .min(6, { message: "Email must be at least 6 characters long" })
                .max(320, { message: "Email must be less than 320 characters" })
                .email({ message: "Please enter a valid email address" }),
            username: zod_1.z.string()
                .nonempty({ message: "Username is required" })
                .min(3, { message: "Username must be at least 3 characters long" })
                .max(30, { message: "Username must be less than 30 characters" }),
            password: zod_1.z.string()
                .nonempty({ message: "Password is required" })
                .min(5, { message: "Password must be at least 5 characters long" })
                .max(20, { message: "Password must be less than 20 characters" })
                .refine((value) => /[A-Z]/.test(value), { message: "Password must contain at least one uppercase letter" })
                .refine((value) => /[a-z]/.test(value), { message: "Password must contain at least one lowercase letter" })
                .refine((value) => /[!@#$%^&*(),.?":{}|<>]/.test(value), { message: "Password must contain at least one special character" })
                .refine((value) => /[0-9]/.test(value), {
                message: "Password must contain at least one number"
            })
        });
        const result = requiredBody.safeParse(req.body);
        if (!result.success) {
            res.send({
                message: "Incorrect Format",
                error: result.error.issues[0].message
            });
            return;
        }
        try {
            const { username, email, password } = result.data;
            const existUser = yield client.user.findFirst({
                where: {
                    email
                }
            });
            if (existUser) {
                res.status(400).send({
                    message: "user  already exists..."
                });
            }
            const hashPassword = yield bcrypt_1.default.hash(password, 10);
            const user = yield client.user.create({
                data: {
                    username,
                    email,
                    password: hashPassword
                }
            });
            if (user) {
                res.status(201).send({
                    message: "you are signed up..."
                });
            }
            else {
                // else block is optional
                res.status(500).send({
                    message: "user was not created"
                });
            }
        }
        catch (error) {
            console.error(error); // Log the error for debugging
            res.status(500).send({
                message: `Internal server error `,
                // error: error.message
            });
        }
    });
});
app.post("/signin", function (req, res) {
    return __awaiter(this, void 0, void 0, function* () {
        const requiredBody = zod_1.z.object({
            email: zod_1.z.string()
                .nonempty({ message: "Email is required" })
                .min(6, { message: "Email must be at least 6 characters long" })
                .max(320, { message: "Email must be less than 320 characters" })
                .email({ message: "Please enter a valid email address" }),
            password: zod_1.z.string()
                .nonempty({ message: "Password is required" })
                .min(5, { message: "Password must be at least 5 characters long" })
                .max(20, { message: "Password must be less than 20 characters" })
        });
        const result = requiredBody.safeParse(req.body);
        if (!result.success) {
            res.send({
                message: "Incorrect Format",
                error: result.error.issues[0].message
            });
            return;
        }
        try {
            const { email, password } = result.data;
            const user = yield client.user.findFirst({
                where: {
                    email
                }
            });
            if (!user) {
                res.status(400).send({
                    message: "user does not exists in our database. you have to signup first..."
                });
                return;
            }
            const passwordMatch = yield bcrypt_1.default.compare(password, user.password);
            if (passwordMatch) {
                const token = jsonwebtoken_1.default.sign({
                    id: user.id
                }, JWT_SECRET);
                res.status(201).send({
                    message: "you are sign in...",
                    user,
                    token
                });
            }
            else {
                // else block is optional
                res.status(500).send({
                    message: "user was not created"
                });
            }
        }
        catch (error) {
            console.error(error); // Log the error for debugging
            res.status(500).send({
                message: `Internal server error `,
                // error: error.message
            });
        }
    });
});
function Auth(req, res, next) {
    const token = req.headers.token;
    if (!token) {
        res.send({
            message: "token is required.."
        });
    }
    try {
        const decodedInformation = jsonwebtoken_1.default.verify(token, JWT_SECRET);
        //@ts-ignore
        req.userId = decodedInformation.id; // Attach user ID to the request
        next(); // Proceed to the next middleware/route
    }
    catch (error) {
        res.send({
            message: "Invalid or expired token",
        });
    }
}
app.get("/me", Auth, function (req, res) {
    return __awaiter(this, void 0, void 0, function* () {
        //@ts-ignore
        const id = req.userId;
        try {
            const user = yield client.user.findFirst({
                where: {
                    id
                },
                select: {
                    id: true,
                    username: true,
                    email: true
                }
            });
            if (!user) {
                res.status(404).send({
                    message: "User not found",
                });
                return;
            }
            res.status(200).send({
                message: "User details fetched successfully",
                user
            });
        }
        catch (error) {
            console.error("Fetch user error:", error);
            res.status(500).send({
                message: "Internal server error",
            });
        }
    });
});
app.get("/allDetail", Auth, function (req, res) {
    return __awaiter(this, void 0, void 0, function* () {
        //@ts-ignore
        const id = req.userId;
        try {
            const user = yield client.user.findFirst({
                where: {
                    id
                },
                select: {
                    id: true,
                    username: true,
                    email: true,
                    todos: true
                },
            });
            if (!user) {
                res.status(404).send({
                    message: "User not found",
                });
                return;
            }
            res.status(200).send({
                message: "User details fetched successfully",
                user
            });
        }
        catch (error) {
            console.error("Fetch user error:", error);
            res.status(500).send({
                message: "Internal server error",
            });
        }
    });
});
app.post("/todo", Auth, function (req, res) {
    return __awaiter(this, void 0, void 0, function* () {
        const parseData = zod_1.z.object({
            title: zod_1.z.string().min(3, "Title must be at least 3 characters").max(100, "Title too long"),
            description: zod_1.z.string().max(1000),
            completed: zod_1.z.boolean().optional().default(false)
        });
        const result = parseData.safeParse(req.body);
        if (!result.success) {
            res.status(400).send({
                message: "Incorrect format",
                // error: result.message
            });
        }
        const { title, description, completed } = req.body;
        try {
            const todo = yield client.todo.create({
                data: {
                    title,
                    description,
                    completed,
                    // @ts-ignore
                    userId: req.userId
                }
            });
            if (todo) {
                res.status(201).send({
                    message: "todo  created successfylly",
                    todo
                });
            }
            else {
                res.send({
                    message: "todo is not created ",
                });
            }
        }
        catch (error) {
            console.log("Todo creation error :", error);
            res.status(500).send({
                message: "Internal server error",
                error
            });
        }
    });
});
app.get("/todo", Auth, function (req, res) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const todos = yield client.todo.findMany({
                where: {
                    //@ts-ignore
                    userId: req.userId
                }
            });
            if (todos.length > 0) {
                res.status(200).send({
                    message: "All Todos here",
                    todos
                });
            }
            else {
                res.status(404).send({
                    message: "No todos found for this user."
                });
            }
        }
        catch (error) {
            console.log(error);
            res.status(500).send({
                message: "Internal server error",
                // error: error.message
            });
        }
    });
});
app.get("/todo/:id", Auth, function (req, res) {
    return __awaiter(this, void 0, void 0, function* () {
        const todoId = Number(req.params.id);
        try {
            const todo = yield client.todo.findFirst({
                where: {
                    id: todoId
                }
            });
            if (todo) {
                res.status(200).send({
                    message: " Todo retrieved successfully",
                    todo
                });
            }
            else {
                res.status(404).send({
                    message: "No todo found for this user."
                });
            }
        }
        catch (error) {
            console.log(error);
            res.status(500).send({
                message: "Internal server error",
                // error: error.message
            });
        }
    });
});
app.put("/todo/:id", Auth, function (req, res) {
    return __awaiter(this, void 0, void 0, function* () {
        const id = Number(req.params.id);
        const { title, description, completed } = req.body;
        try {
            const todo = yield client.todo.update({
                where: {
                    id
                },
                data: {
                    title,
                    description,
                    completed
                }
            });
            if (todo) {
                res.status(201).send({
                    message: "todo updated successfully",
                    todo
                });
            }
            else {
                res.status(404).send({
                    message: "Todo not found or you are not authorized to update it"
                });
            }
        }
        catch (error) {
            res.status(500).send({
                message: "Internal server error",
                // error: error.message
            });
        }
    });
});
app.delete("/todo/:id", Auth, function (req, res) {
    return __awaiter(this, void 0, void 0, function* () {
        const id = Number(req.params.id);
        try {
            const todo = yield client.todo.delete({
                where: {
                    id
                }
            });
            if (todo) {
                res.status(201).send({
                    message: "todo deleted successfully",
                    todo
                });
            }
            else {
                res.status(404).send({
                    message: "Todo not found or you are not authorized to delete it"
                });
            }
        }
        catch (error) {
            res.status(500).send({
                message: "Internal server error",
                // error: error.message
            });
        }
    });
});
app.listen(PORT, function () {
    console.log(`server is running on PORT : ${PORT}.....`);
});
