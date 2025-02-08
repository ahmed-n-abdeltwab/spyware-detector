import fs from 'fs/promises';
import { ScanResult } from '../types';
import { logger } from '../utils/logger';

const RESULTS_FILE = 'scan_results.json';

export const saveScanResult = async (result: ScanResult): Promise<void> => {
  try {
    let results: ScanResult[] = [];

    try {
      const data = await fs.readFile(RESULTS_FILE, 'utf-8');
      results = JSON.parse(data);
    } catch (error) {
      // File doesn't exist yet, start with empty array
    }

    results.push(result);
    await fs.writeFile(RESULTS_FILE, JSON.stringify(results, null, 2));

    logger.info('Scan result saved successfully');
  } catch (error) {
    logger.error('Error saving scan result:', error);
    throw error;
  }
};

export const getScanHistory = async (): Promise<ScanResult[]> => {
  try {
    const data = await fs.readFile(RESULTS_FILE, 'utf-8');
    return JSON.parse(data);
  } catch (error) {
    logger.error('Error reading scan history:', error);
    return [];
  }
};
