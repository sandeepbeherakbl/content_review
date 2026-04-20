import express from "express";
import cors from "cors";
import authRoutes from "./routes/authRoutes.js";
import userRoutes from "./routes/userRoutes.js";
import contentRoutes from "./routes/contentRoutes.js";
import subContentRoutes from "./routes/subContentRoutes.js";
import reviewRoutes from "./routes/reviewRoutes.js";
import aiRoutes from "./routes/aiRoutes.js";
import swaggerUi from "swagger-ui-express";
import swaggerSpec from "./swagger/swagger.js";

const app = express();

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// routes
app.use("/api/auth", authRoutes);
app.use("/api/users", userRoutes);
app.use("/api/content", contentRoutes);
app.use("/api/sub-content", subContentRoutes);
app.use("/api/review", reviewRoutes);
app.use("/api/ai", aiRoutes);

// swagger
app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerSpec));

export default app;