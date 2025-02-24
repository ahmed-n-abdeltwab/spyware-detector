import axios from 'axios';
import { ScanResult } from '../types';
import { logger } from '../utils/logger';

const SCANNER_URL = ( process.env.SCANNER_URL || 'http://localhost:5000' ) + '/scan';
let length = 0;

export const analyzefile = async (
  fileBuffer: Buffer,
  fileName: string
): Promise<ScanResult> => {
  logger.info(`Starting analysis for file: ${fileName}`);

  try {
    // Convert buffer to base64 for transmission
    const fileBase64 = fileBuffer.toString('base64');

    // Send file to scanner service
    const response = await axios.post(
      SCANNER_URL,
      {
        fileName,
        fileContent: fileBase64,
      },
      {
        headers: {
          'Content-Type': 'application/json',
        },
        timeout: 30000, // 30 second timeout
      }
    );

    const scannerResult = response.data;

    // Transform scanner response to our ScanResult format
    const result: ScanResult = {
      fileId: ++length,
      fileName,
      timestamp: new Date().toISOString(),
      fileSize: fileBuffer.length,
      status: scannerResult.status,
      details: scannerResult.details,
      metadata: {
        hash: scannerResult.hash,
        fileType: scannerResult.file_type,
        mimeType: scannerResult.mime_type,
        entropy: scannerResult.entropy,
      },
    };

    logger.info('Analysis completed', { result });
    return result;
  } catch (error) {
    logger.error('Error during file analysis:', error);
    return {
      fileId: ++length,
      fileName,
      timestamp: new Date().toISOString(),
      fileSize: fileBuffer.length,
      status: 'error',
      details: 'Error connecting to scanner service',
      metadata: {
        hash: '',
        fileType: 'unknown',
        mimeType: 'unknown',
        entropy: 0,
      },
    };
  }
};
