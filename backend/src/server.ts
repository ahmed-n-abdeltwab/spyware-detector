import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import { router as fileRoutes } from './routes/fileRoutes';
import { errorHandler } from './middleware/errorHandler';
import { logger } from './utils/logger';

dotenv.config();

const app = express();
const port = process.env.NODE_PORT || 3000;

app.use(cors());
app.use(express.json());

// Routes
app.use('/api/files', fileRoutes);

// Error handling
app.use(errorHandler);

app.listen(port, () => {
  logger.info(`Server is running on port ${port}`);
});
