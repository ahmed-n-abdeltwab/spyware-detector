export interface FileMetadata {
  hash: string;
  fileType: string;
  mimeType: string;
  entropy: number;
}

export interface ScanResult {
  fileId: number;
  fileName: string;
  timestamp: string;
  fileSize: number;
  status: 'clean' | 'infected' | 'error';
  details: string;
  metadata: FileMetadata;
}
