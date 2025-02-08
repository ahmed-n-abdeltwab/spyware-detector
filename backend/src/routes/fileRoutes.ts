import { Router } from 'express';
import { uploadFile, getScanResults } from '../controllers/fileController';
import { upload } from '../middleware/uploadMiddleware';
import { validateFileUpload } from '../middleware/validation';

const router = Router();

router.post('/upload', upload.single('file'), validateFileUpload, uploadFile);
router.get('/scan-results', getScanResults);

export { router };
