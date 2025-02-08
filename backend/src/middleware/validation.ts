import { Request, Response, NextFunction } from 'express';
import { logger } from '../utils/logger';

export const validateFileUpload = (
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  if (!req.file) {
    logger.error('File upload validation failed: No file provided');
    res.status(400).json({ error: 'No file uploaded' });
    return;
  }

  const maxSize = parseInt(process.env.MAX_FILE_SIZE || '5242880');
  if (req.file.size > maxSize) {
    logger.error(
      `File size ${req.file.size} exceeds maximum allowed size ${maxSize}`
    );
    res.status(400).json({ error: 'File size exceeds limit' });
    return;
  }

  next();
};
