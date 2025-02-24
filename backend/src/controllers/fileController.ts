import { Request, Response, NextFunction } from 'express';
import { logger } from '../utils/logger';
import { ScanResult } from '../types';
import { analyzefile } from '../services/fileAnalyzer';
import { saveScanResult, getScanHistory, filterScanHistory } from '../services/scanStorage';

export const uploadFile = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    if (!req.file) {
      throw new Error('No file uploaded');
    }

    const fileBuffer = req.file.buffer;
    const fileName = req.file.originalname;

    // Analyze the file
    const scanResult = await analyzefile(fileBuffer, fileName);

    // Save scan result
    await saveScanResult(scanResult);

    logger.info(`File scan completed for ${fileName}`, { scanResult });

    res.status(200).json({
      message: 'File analyzed successfully',
      result: scanResult,
    });
  } catch (error) {
    next(error);
  }
};

export const getScanResults = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const history = await getScanHistory();
    res.status(200).json(history);
  } catch (error) {
    next(error);
  }
};

export const getScanResultsByFileId = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const history = await getScanHistory();
    const filteredResults = filterScanHistory(history, Number(req.params.fileId));
    res.status(200).json(filteredResults);
  } catch (error) {
    next(error);
  }
};
