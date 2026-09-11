const encoder = new TextEncoder();
const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 30;
const MAX_JSON_BODY_BYTES = 900000;
const MAX_INLINE_IMAGE_DATA_URL_LENGTH = 360000;
const RATE_LIMIT_RETENTION_MS = 1000 * 60 * 60 * 24 * 7;

class ApiRequestError extends Error {
    constructor(message, status = 400) {
        super(message);
        this.name = 'ApiRequestError';
        this.status = status;
    }
}

function corsHeaders() {
    return {
        // CORS is additionally enforced at the request boundary below. The
        // wildcard remains here so native/Tauri clients and approved browser
        // origins receive compatible API responses without cookies.
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Authorization, Content-Type, X-Bootstrap-Secret',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
        'Access-Control-Max-Age': '86400',
        'Cache-Control': 'no-store, max-age=0',
        'Pragma': 'no-cache',
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'no-referrer',
        'X-Frame-Options': 'DENY',
        'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
        'Cross-Origin-Resource-Policy': 'same-site',
    };
}

const DEFAULT_ALLOWED_ORIGINS = new Set([
    'http://127.0.0.1:5173',
    'http://localhost:5173',
    'http://tauri.localhost',
    'tauri://localhost',
    'https://tauri.localhost',
]);

function requestOriginAllowed(request, env) {
    const origin = request.headers.get('Origin');

    // Native clients, curl, server-to-server traffic, and some Tauri WebViews
    // do not send Origin. Authentication/authorization still protects them.
    if (!origin || origin === 'null') return true;

    const allowed = new Set(DEFAULT_ALLOWED_ORIGINS);
    const configured = String(env.ALLOWED_ORIGINS ?? '')
        .split(',')
        .map(value => value.trim())
        .filter(Boolean);

    for (const value of configured) allowed.add(value);

    return allowed.has(origin);
}

function forbiddenOriginResponse() {
    return new Response(JSON.stringify({ error: 'Origin not allowed.' }), {
        status: 403,
        headers: {
            'Content-Type': 'application/json; charset=utf-8',
            'Cache-Control': 'no-store, max-age=0',
            'X-Content-Type-Options': 'nosniff',
            'Referrer-Policy': 'no-referrer',
            'X-Frame-Options': 'DENY',
        },
    });
}
function json(body, status = 200) {
    return Response.json(body, {
        status,
        headers: corsHeaders(),
    });
}
function fail(message, status = 400) {
    return json({ error: message }, status);
}
function normalizeUsername(value) {
    return value.trim().toLowerCase();
}
const RESERVED_USERNAMES = new Set([
    'admin',
    'administrator',
    'moderator',
    'staff',
    'support',
    'system',
    'scrounge',
    'spaces',
]);

function validUsername(value) {
    return /^[a-z0-9_]{3,24}$/u.test(value);
}

function validNewUsername(value) {
    return /^[a-z0-9_]{4,24}$/u.test(value);
}

function reservedUsername(value) {
    return RESERVED_USERNAMES.has(value);
}

function randomAlphaNumeric(length = 8) {
    const alphabet = 'abcdefghjkmnpqrstuvwxyz23456789';
    const bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);

    let value = '';

    for (const byte of bytes) {
        value += alphabet[
            byte %
            alphabet.length
        ];
    }

    return value;
}

async function uniqueRandomUsername(env) {
    for (
        let attempt = 0;
        attempt < 12;
        attempt += 1
    ) {
        const candidate =
            `user_${randomAlphaNumeric(7)}`;

        const existing =
            await env.DB.prepare(
                `SELECT id
                 FROM users
                 WHERE username = ?
                 LIMIT 1`
            )
                .bind(candidate)
                .first();

        if (!existing) {
            return candidate;
        }
    }

    return `user_${Date.now()
        .toString(36)
        .slice(-8)}`;
}
function bytesToBase64(bytes) {
    let binary = '';
    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }
    return btoa(binary);
}
function base64ToBytes(value) {
    const binary = atob(value);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) {
        bytes[index] = binary.charCodeAt(index);
    }
    return bytes;
}
function randomToken(byteLength = 32) {
    const bytes = new Uint8Array(byteLength);
    crypto.getRandomValues(bytes);
    return bytesToBase64(bytes)
        .replaceAll('+', '-')
        .replaceAll('/', '_')
        .replaceAll('=', '');
}
async function sha256Base64(value) {
    const digest = await crypto.subtle.digest('SHA-256', encoder.encode(value));
    return bytesToBase64(new Uint8Array(digest));
}

const TOTP_STEP_SECONDS = 30;
const TOTP_DIGITS = 6;
const EMAIL_CODE_TTL_MS = 1000 * 60 * 10;
const TOTP_SETUP_TTL_MS = 1000 * 60 * 15;
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function normalizeEmail(value) {
    return String(value ?? '').trim().toLowerCase();
}

function validEmail(value) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/u.test(value) && value.length <= 254;
}

function base32Encode(bytes) {
    let bits = 0;
    let buffer = 0;
    let output = '';
    for (const byte of bytes) {
        buffer = (buffer << 8) | byte;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            output += BASE32_ALPHABET[(buffer >>> bits) & 31];
        }
    }
    if (bits > 0) output += BASE32_ALPHABET[(buffer << (5 - bits)) & 31];
    return output;
}

function base32Decode(value) {
    const normalized = String(value ?? '').toUpperCase().replace(/[^A-Z2-7]/gu, '');
    let bits = 0;
    let buffer = 0;
    const bytes = [];
    for (const character of normalized) {
        const index = BASE32_ALPHABET.indexOf(character);
        if (index < 0) continue;
        buffer = (buffer << 5) | index;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            bytes.push((buffer >>> bits) & 255);
        }
    }
    return new Uint8Array(bytes);
}

function randomTotpSecret() {
    const bytes = new Uint8Array(20);
    crypto.getRandomValues(bytes);
    return base32Encode(bytes);
}

async function totpCode(secret, timeMs = Date.now()) {
    const counter = Math.floor(timeMs / 1000 / TOTP_STEP_SECONDS);
    const counterBytes = new Uint8Array(8);
    let remaining = BigInt(counter);
    for (let index = 7; index >= 0; index -= 1) {
        counterBytes[index] = Number(remaining & 255n);
        remaining >>= 8n;
    }
    const key = await crypto.subtle.importKey(
        'raw',
        base32Decode(secret),
        { name: 'HMAC', hash: 'SHA-1' },
        false,
        ['sign'],
    );
    const digest = new Uint8Array(await crypto.subtle.sign('HMAC', key, counterBytes));
    const offset = digest[digest.length - 1] & 15;
    const binary =
        ((digest[offset] & 127) << 24) |
        ((digest[offset + 1] & 255) << 16) |
        ((digest[offset + 2] & 255) << 8) |
        (digest[offset + 3] & 255);
    return String(binary % (10 ** TOTP_DIGITS)).padStart(TOTP_DIGITS, '0');
}

async function verifyTotp(secret, candidate) {
    const clean = String(candidate ?? '').replace(/\D/gu, '');
    if (!/^\d{6}$/u.test(clean)) return false;
    const now = Date.now();
    for (const windowOffset of [-1, 0, 1]) {
        const expected = await totpCode(secret, now + windowOffset * TOTP_STEP_SECONDS * 1000);
        if (constantTimeEqual(expected, clean)) return true;
    }
    return false;
}

function randomNumericCode(length = 6) {
    const bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);
    return [...bytes].map(byte => String(byte % 10)).join('');
}

function randomRecoveryCode() {
    const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    const bytes = new Uint8Array(8);
    crypto.getRandomValues(bytes);
    let result = '';
    for (const byte of bytes) result += alphabet[byte % alphabet.length];
    return `${result.slice(0, 4)}-${result.slice(4)}`;
}

async function recoveryCodeHash(userId, code) {
    const normalized = String(code ?? '').toUpperCase().replace(/[^A-Z0-9]/gu, '');
    return sha256Base64(`${userId}:${normalized}`);
}

async function useRecoveryCode(env, userId, code) {
    const hash = await recoveryCodeHash(userId, code);
    const row = await env.DB.prepare(
        `UPDATE account_recovery_codes
         SET used_at = ?
         WHERE user_id = ? AND code_hash = ? AND used_at IS NULL
         RETURNING id`
    ).bind(Date.now(), userId, hash).first();
    return Boolean(row?.id);
}

async function replaceRecoveryCodes(env, userId) {
    const codes = Array.from({ length: 8 }, () => randomRecoveryCode());
    const now = Date.now();
    await env.DB.prepare(`DELETE FROM account_recovery_codes WHERE user_id = ?`).bind(userId).run();
    for (const code of codes) {
        await env.DB.prepare(
            `INSERT INTO account_recovery_codes (id, user_id, code_hash, created_at, used_at)
             VALUES (?, ?, ?, ?, NULL)`
        ).bind(crypto.randomUUID(), userId, await recoveryCodeHash(userId, code), now).run();
    }
    return codes;
}

async function accountSecurityStatus(env, user) {
    const count = await env.DB.prepare(
        `SELECT COUNT(*) AS count FROM account_recovery_codes WHERE user_id = ? AND used_at IS NULL`
    ).bind(user.id).first();
    return {
        email: user.email ?? null,
        emailVerified: Boolean(user.email_verified),
        twoFactorEnabled: Boolean(user.totp_enabled && user.totp_secret),
        recoveryCodesRemaining: Number(count?.count ?? 0),
        emailServiceAvailable: Boolean(env.EMAIL && typeof env.EMAIL.send === 'function'),
        emailSenderConfigured: Boolean(String(env.SPACES_EMAIL_FROM ?? '').trim()),
    };
}

async function rateLimitIdentity(request, scope, subject = '') {
    const connectingIp =
        request.headers.get('CF-Connecting-IP') ||
        request.headers.get('X-Forwarded-For') ||
        'unknown';

    const digest = await sha256Base64(
        `${scope}|${connectingIp}|${subject}`,
    );

    return `${scope}:${digest
        .replaceAll('+', '-')
        .replaceAll('/', '_')
        .replaceAll('=', '')
        .slice(0, 32)}`;
}

async function enforceRateLimit(
    request,
    env,
    scope,
    limit,
    windowMs,
    subject = '',
) {
    const now = Date.now();
    const windowStart =
        Math.floor(now / windowMs) * windowMs;
    const bucketKey =
        await rateLimitIdentity(request, scope, subject);

    const row = await env.DB.prepare(
        `INSERT INTO api_rate_limits
          (bucket_key, window_start, request_count, updated_at)
         VALUES (?, ?, 1, ?)
         ON CONFLICT(bucket_key) DO UPDATE SET
           request_count = CASE
             WHEN api_rate_limits.window_start = excluded.window_start
               THEN api_rate_limits.request_count + 1
             ELSE 1
           END,
           window_start = excluded.window_start,
           updated_at = excluded.updated_at
         RETURNING request_count, window_start`
    )
        .bind(bucketKey, windowStart, now)
        .first();

    if (Number(row?.request_count ?? 1) > limit) {
        throw new ApiRequestError(
            'Too many requests. Try again shortly.',
            429,
        );
    }

    const cleanupProbe = new Uint8Array(1);
    crypto.getRandomValues(cleanupProbe);

    if (cleanupProbe[0] === 0) {
        try {
            await env.DB.prepare(
                `DELETE FROM api_rate_limits
                 WHERE updated_at < ?`
            )
                .bind(now - RATE_LIMIT_RETENTION_MS)
                .run();
        }
        catch (caught) {
            console.warn('Rate-limit cleanup skipped.', caught);
        }
    }
}
const CLIENT_PASSWORD_ITERATIONS = 310000;

const SPACES_HUB_ID = 'spaces-hub';
const SPACES_HUB_CODE = 'HUB';
const SPACES_HUB_NAME = 'Spaces - Hub';
const SPACE_BACKGROUNDS = new Set([
    'graphite', 'midnight', 'slate', 'black',
    'carbon', 'violet-grid', 'deep-space', 'glassline',
    'velvet', 'blue-hour', 'noir-bloom',
    'smoke',
    'ember',
    'forest',
    'ocean',
    'rose-noir',
]);
const SPACE_ICON_DECORATIONS = new Set(['none', 'ring', 'double', 'halo', 'badge']);
const CHAT_ATTACHMENT_MAX_BYTES = 180 * 1024;
const CHAT_ATTACHMENT_TYPES = new Set([
    'image/png', 'image/jpeg', 'image/webp', 'text/plain',
]);

const CHANNEL_PERMISSION_ACTIONS = new Set([
    'view_channel', 'send_messages', 'attach_files',
    'create_notes', 'edit_notes', 'delete_notes',
]);

const CUSTOM_ROLE_PERMISSIONS = new Set([
    'send_messages', 'attach_files', 'mention_everyone', 'edit_notes', 'delete_notes',
    'create_channels', 'manage_channels', 'create_invites', 'manage_members',
    'manage_roles', 'manage_space', 'manage_emojis', 'moderate_messages',
    'moderate_comments', 'view_audit_log',
]);
const EMOJI_IMAGE_MAX_BYTES = 64 * 1024;
const EMOJI_IMAGE_TYPES = new Set([
    'image/png', 'image/jpeg', 'image/webp', 'image/gif',
]);

function normalizeHexColor(value, fallback = '#8b6ca8') {
    const text = String(value ?? '').trim();
    return /^#[0-9a-f]{6}$/iu.test(text) ? text.toLowerCase() : fallback;
}

function normalizeCustomPermissions(value) {
    const items = Array.isArray(value) ? value : [];
    return [...new Set(items
        .map(item => String(item))
        .filter(item => CUSTOM_ROLE_PERMISSIONS.has(item)))];
}

function parsePermissionsJson(value) {
    try {
        return normalizeCustomPermissions(JSON.parse(value || '[]'));
    }
    catch {
        return [];
    }
}

function normalizeChannelPermissionActions(value) {
    const items = Array.isArray(value) ? value : [];
    return [...new Set(items
        .map(item => String(item))
        .filter(item => CHANNEL_PERMISSION_ACTIONS.has(item)))];
}

function parseChannelPermissionJson(value) {
    try {
        return normalizeChannelPermissionActions(JSON.parse(value || '[]'));
    }
    catch {
        return [];
    }
}

function channelPermissionOverwriteFromRow(row) {
    return {
        id: row.id,
        workspaceId: row.space_id,
        channelId: row.channel_id,
        targetType: row.target_type,
        targetId: row.target_id,
        allow: parseChannelPermissionJson(row.allow_json),
        deny: parseChannelPermissionJson(row.deny_json),
        createdAt: Number(row.created_at ?? 0),
        updatedAt: Number(row.updated_at ?? 0),
    };
}

function channelPermissionDecision(access, rows, action) {
    if (access.role === 'owner') return 'allow';

    let everyone = 'neutral';
    let roleAllow = false;
    let roleDeny = false;
    let member = 'neutral';

    for (const row of rows ?? []) {
        const allow = parseChannelPermissionJson(row.allow_json);
        const deny = parseChannelPermissionJson(row.deny_json);
        const state = deny.includes(action) ? 'deny' : allow.includes(action) ? 'allow' : 'neutral';
        if (row.target_type === 'everyone') everyone = state;
        else if (row.target_type === 'role' && access.customRoleIds?.includes(row.target_id)) {
            if (state === 'deny') roleDeny = true;
            if (state === 'allow') roleAllow = true;
        }
        else if (row.target_type === 'member' && row.target_id === access.memberId) member = state;
    }

    let result = everyone;
    if (roleDeny) result = 'deny';
    if (roleAllow) result = 'allow';
    if (member !== 'neutral') result = member;
    return result;
}

function channelPermissionAllowed(access, rows, action, baseAllowed) {
    const decision = channelPermissionDecision(access, rows, action);
    if (decision === 'allow') return true;
    if (decision === 'deny') return false;
    return Boolean(baseAllowed);
}

async function channelPermissionRows(env, workspaceId, channelId) {
    const result = await env.DB.prepare(
        `SELECT * FROM channel_permission_overwrites
         WHERE space_id = ? AND channel_id = ?`
    ).bind(workspaceId, channelId).all();
    return result.results ?? [];
}

function customRoleFromRow(row) {
    return {
        id: row.id,
        workspaceId: row.space_id,
        name: row.name,
        color: normalizeHexColor(row.color),
        permissions: parsePermissionsJson(row.permissions_json),
        position: Number(row.position ?? 0),
        hoist: Boolean(row.hoist),
        mentionable: Boolean(row.mentionable),
        createdAt: Number(row.created_at ?? 0),
        updatedAt: Number(row.updated_at ?? 0),
    };
}

function emojiFromRow(row) {
    return {
        id: row.id,
        workspaceId: row.space_id,
        name: row.name,
        imageType: row.image_type,
        imageData: row.image_data,
        createdBy: row.created_by,
        createdAt: Number(row.created_at ?? 0),
        updatedAt: Number(row.updated_at ?? 0),
    };
}

function noteCommentFromRow(row) {
    return {
        id: row.id,
        workspaceId: row.space_id,
        noteId: row.note_id,
        authorId: row.author_id,
        authorName: row.author_name ?? 'Member',
        authorInitials: String(row.author_name ?? row.author_username ?? 'M').slice(0, 1).toUpperCase(),
        authorAvatarUrl: row.author_avatar_url ?? null,
        body: row.body ?? '',
        createdAt: Number(row.created_at ?? 0),
        editedAt: row.edited_at ?? null,
        deletedAt: row.deleted_at ?? null,
        deletedBy: row.deleted_by ?? null,
    };
}

function roleAssignmentMap(rows) {
    const map = new Map();
    for (const row of rows ?? []) {
        const list = map.get(row.member_id) ?? [];
        list.push(row.role_id);
        map.set(row.member_id, list);
    }
    return map;
}

function parseEmojiInput(body) {
    const name = String(body.name ?? '').trim().toLowerCase();
    const imageType = String(body.imageType ?? '').trim().toLowerCase();
    const imageData = String(body.imageData ?? '');
    if (!/^[a-z0-9_]{2,32}$/u.test(name)) {
        throw new ApiRequestError('Emoji name must use 2-32 letters, numbers, or underscores.');
    }
    if (!EMOJI_IMAGE_TYPES.has(imageType)) {
        throw new ApiRequestError('Use PNG, JPEG, WebP, or GIF for custom emoji.');
    }
    const prefix = `data:${imageType};base64,`;
    if (!imageData.startsWith(prefix)) {
        throw new ApiRequestError('Emoji image data is invalid.');
    }
    const encoded = imageData.slice(prefix.length);
    if (!/^[A-Za-z0-9+/]*={0,2}$/u.test(encoded)) {
        throw new ApiRequestError('Emoji image data is invalid.');
    }
    const padding = encoded.endsWith('==') ? 2 : encoded.endsWith('=') ? 1 : 0;
    const size = Math.floor((encoded.length * 3) / 4) - padding;
    if (size < 1 || size > EMOJI_IMAGE_MAX_BYTES) {
        throw new ApiRequestError('Custom emoji must be 64 KB or smaller.');
    }
    return { name, imageType, imageData };
}

function customPermissionForLegacyRole(role, permission) {
    if (role === 'owner' || role === 'admin') return true;
    if (role === 'contributor') {
        return new Set([
            'send_messages', 'attach_files', 'edit_notes', 'delete_notes',
            'view_audit_log',
        ]).has(permission);
    }
    return permission === 'view_audit_log';
}

function accessHas(access, permission) {
    return customPermissionForLegacyRole(access.role, permission) ||
        access.customPermissions?.has(permission) === true;
}

function hasFullRoleHierarchyAccess(access) {
    return access.role === 'owner' || access.role === 'admin';
}

function canManageCustomRolePosition(access, position) {
    return hasFullRoleHierarchyAccess(access) ||
        Number(access.highestCustomRolePosition ?? -1) > Number(position ?? -1);
}

function normalizeBackgroundPreset(value, fallback = 'graphite') {
    return SPACE_BACKGROUNDS.has(value) ? value : fallback;
}

function normalizeIconDecoration(value, fallback = 'ring') {
    const text = String(value ?? '').trim().toLowerCase();
    return SPACE_ICON_DECORATIONS.has(text) ? text : fallback;
}


function parseChatAttachment(input) {
    if (input === null || input === undefined) return null;
    if (typeof input !== 'object') {
        throw new ApiRequestError('Attachment is invalid.');
    }
    const name = String(input.name ?? '').trim().replace(/[\r\n"]/gu, '_').slice(0, 100);
    const type = String(input.type ?? '').trim().toLowerCase();
    const dataUrl = String(input.dataUrl ?? '');
    if (!name || !CHAT_ATTACHMENT_TYPES.has(type)) {
        throw new ApiRequestError('That file type is not supported.');
    }
    const prefix = `data:${type};base64,`;
    if (!dataUrl.startsWith(prefix)) {
        throw new ApiRequestError('Attachment data is invalid.');
    }
    const encoded = dataUrl.slice(prefix.length);
    if (!/^[A-Za-z0-9+/]*={0,2}$/u.test(encoded)) {
        throw new ApiRequestError('Attachment data is invalid.');
    }
    const padding = encoded.endsWith('==') ? 2 : encoded.endsWith('=') ? 1 : 0;
    const size = Math.floor((encoded.length * 3) / 4) - padding;
    if (size < 1 || size > CHAT_ATTACHMENT_MAX_BYTES) {
        throw new ApiRequestError('Attachments must be 180 KB or smaller.');
    }
    return { name, type, size, dataUrl };
}

function messageAttachmentFromRow(row) {
    if (!row.attachment_name) return null;
    return {
        name: row.attachment_name ?? 'attachment',
        type: row.attachment_type ?? 'application/octet-stream',
        size: Number(row.attachment_size ?? 0),
        downloadPath: `/v1/workspaces/${encodeURIComponent(row.space_id)}/messages/${encodeURIComponent(row.id)}/attachment`,
    };
}


function isBase64Bytes(value, expectedLength) {
    try {
        return atob(value).length === expectedLength;
    }
    catch {
        return false;
    }
}

function parseClientPasswordHash(storedHash) {
    const match = /^client-pbkdf2-sha256\$(\d+)\$(.+)$/u.exec(storedHash);

    if (!match) {
        return null;
    }

    const iterations = Number(match[1]);
    const verifierHash = match[2] ?? '';

    if (!Number.isSafeInteger(iterations) ||
        iterations < 1000 ||
        iterations > 1000000 ||
        !verifierHash) {
        return null;
    }

    return {
        iterations,
        verifierHash,
    };
}

async function hashPasswordVerifier(verifier) {
    return sha256Base64(verifier);
}

async function verifyPasswordVerifier(user, verifier, env) {
    if (!isBase64Bytes(verifier, 32)) {
        return false;
    }

    const parsed = parseClientPasswordHash(user.password_hash);

    if (parsed) {
        const computed = await hashPasswordVerifier(verifier);
        return constantTimeEqual(computed, parsed.verifierHash);
    }

    // Compatibility with an account created by the original Worker:
    // if the verifier matches the old stored PBKDF2 output, migrate it.
    if (!constantTimeEqual(verifier, user.password_hash)) {
        return false;
    }

    const migrated = await hashPasswordVerifier(verifier);

    await env.DB.prepare(
        `UPDATE users
         SET
           password_hash = ?,
           updated_at = ?
         WHERE id = ?`
    )
        .bind(
            `client-pbkdf2-sha256$${CLIENT_PASSWORD_ITERATIONS}$${migrated}`,
            Date.now(),
            user.id,
        )
        .run();

    return true;
}

function constantTimeEqual(left, right) {
    if (left.length === 0 ||
        right.length === 0 ||
        left.length !== right.length) {
        return false;
    }
    let diff = 0;
    for (let index = 0; index < left.length; index += 1) {
        diff |=
            left.charCodeAt(index) ^
                right.charCodeAt(index);
    }
    return diff === 0;
}
async function ensureSpacesHub(env) {
    let creator = await env.DB.prepare(
        `SELECT id
         FROM users
         WHERE platform_role = 'creator'
         ORDER BY created_at ASC
         LIMIT 1`
    )
        .first();

    if (!creator) {
        const firstUsers = await env.DB.prepare(
            `SELECT id
             FROM users
             ORDER BY created_at ASC
             LIMIT 2`
        )
            .all();

        // Fresh install bootstrap: only when exactly one account exists.
        // That immutable first account becomes the Platform Creator.
        if (firstUsers.results.length !== 1) {
            return null;
        }

        const creatorId = firstUsers.results[0]?.id;

        if (!creatorId) {
            return null;
        }

        await env.DB.prepare(
            `UPDATE users
             SET
               platform_role = 'creator',
               public_user_id = '00001',
               updated_at = ?
             WHERE id = ?`
        )
            .bind(
                Date.now(),
                creatorId,
            )
            .run();

        creator = {
            id: creatorId,
        };
    }

    const creatorId = creator.id;
    const now = Date.now();

    await env.DB.prepare(
        `INSERT OR IGNORE INTO spaces
          (
            id,
            name,
            code,
            join_password_salt,
            join_password_hash,
            owner_user_id,
            created_at,
            updated_at
          )
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    )
        .bind(
            SPACES_HUB_ID,
            SPACES_HUB_NAME,
            SPACES_HUB_CODE,
            'platform-managed',
            'platform-managed',
            creatorId,
            now,
            now,
        )
        .run();

    await env.DB.prepare(
        `INSERT OR IGNORE INTO space_members
          (
            id,
            space_id,
            user_id,
            role,
            joined_at
          )
         VALUES (?, ?, ?, 'owner', ?)`
    )
        .bind(
            `hub-member-${creatorId}`,
            SPACES_HUB_ID,
            creatorId,
            now,
        )
        .run();

    const channels = [
        [
            'spaces-hub-updates',
            'updates',
            'Official Spaces updates and release notes.',
            'announcement',
            0,
            'admin',
            'disabled',
        ],
        [
            'spaces-hub-general',
            'general',
            'General discussion for the Spaces community.',
            'chat',
            1,
            'viewer',
            'disabled',
        ],
        [
            'spaces-hub-notes',
            'notes',
            'Shared notes, guides, and reference material.',
            'notes',
            2,
            'disabled',
            'admin',
        ],
    ];

    for (const [
        id,
        name,
        description,
        kind,
        order,
        postMinRole,
        noteMinRole,
    ] of channels) {
        await env.DB.prepare(
            `INSERT OR IGNORE INTO channels
              (
                id,
                space_id,
                name,
                description,
                kind,
                sort_order,
                post_min_role,
                note_min_role,
                created_at
              )
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
            .bind(
                id,
                SPACES_HUB_ID,
                name,
                description,
                kind,
                order,
                postMinRole,
                noteMinRole,
                now,
            )
            .run();
    }

    await env.DB.prepare(
        `INSERT OR IGNORE INTO notes
          (
            id,
            space_id,
            channel_id,
            title,
            body,
            created_by,
            updated_by,
            version,
            created_at,
            updated_at
          )
         VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)`
    )
        .bind(
            'spaces-hub-welcome',
            SPACES_HUB_ID,
            'spaces-hub-notes',
            'Welcome to Spaces - Hub',
            'This is the permanent Spaces Hub. Official updates, shared guides, and community channels live here. More channels can be added as Spaces grows.',
            creatorId,
            creatorId,
            now,
            now,
        )
        .run();

    const updateCount =
        await env.DB.prepare(
            `SELECT COUNT(*) AS count
             FROM platform_updates`
        )
            .first();

    if (
        Number(
            updateCount?.count ??
            0,
        ) === 0
    ) {
        const platformUpdates = [
            {
                version: '0.50',
                title: 'Spaces Live Service',
                changes: [
                    'Connected Spaces accounts to the live Spaces service.',
                    'Added the permanent Spaces - Hub.',
                    'Added platform moderation, roles, reports, and live chat.',
                    'Added profile pictures and mobile-first account controls.',
                ],
            },
            {
                version: '0.49',
                title: 'Spaces Office UI',
                changes: [
                    'Reworked Spaces around a compact glass office interface.',
                    'Added animated navigation, account controls, and mobile layouts.',
                ],
            },
        ];

        for (const update of platformUpdates) {
            await env.DB.prepare(
                `INSERT OR IGNORE INTO platform_updates
                  (
                    version,
                    published_at,
                    title,
                    changes_json,
                    created_by,
                    updated_at
                  )
                 VALUES (?, ?, ?, ?, ?, ?)`
            )
                .bind(
                    update.version,
                    now,
                    update.title,
                    JSON.stringify(
                        update.changes,
                    ),
                    creatorId,
                    now,
                )
                .run();
        }
    }

    await env.DB.prepare(
        `INSERT OR IGNORE INTO audit_logs
          (
            id,
            space_id,
            actor_id,
            action,
            target_type,
            target_id,
            target_label,
            reason,
            metadata_json,
            created_at
          )
         VALUES (?, ?, ?, 'workspace.created', 'workspace', ?, ?, ?, '{}', ?)`
    )
        .bind(
            'spaces-hub-created',
            SPACES_HUB_ID,
            creatorId,
            SPACES_HUB_ID,
            SPACES_HUB_NAME,
            'Permanent platform Space created.',
            now,
        )
        .run();

    return creatorId;
}

async function ensureHubMembership(env, userId) {
    const creatorId = await ensureSpacesHub(env);

    if (!creatorId) {
        return;
    }

    const role =
        userId === creatorId
            ? 'owner'
            : 'viewer';

    await env.DB.prepare(
        `INSERT OR IGNORE INTO space_members
          (
            id,
            space_id,
            user_id,
            role,
            joined_at
          )
         VALUES (?, ?, ?, ?, ?)`
    )
        .bind(
            `hub-member-${userId}`,
            SPACES_HUB_ID,
            userId,
            role,
            Date.now(),
        )
        .run();
}


async function workspaceAccessForUser(env, userId, workspaceId) {
    const membership = await env.DB.prepare(
        `SELECT id, role
         FROM space_members
         WHERE space_id = ? AND user_id = ?
         LIMIT 1`
    ).bind(workspaceId, userId).first();
    if (!membership) return null;

    let customRoleRows = { results: [] };
    try {
        customRoleRows = await env.DB.prepare(
            `SELECT r.id, r.permissions_json, r.position
             FROM space_member_roles mr
             JOIN space_roles r ON r.id = mr.role_id
             WHERE mr.space_id = ? AND mr.member_id = ?
             ORDER BY r.position DESC, r.created_at ASC`
        ).bind(workspaceId, membership.id).all();
    }
    catch (caught) {
        console.warn('Custom role lookup unavailable.', caught);
    }

    const customPermissions = new Set();
    for (const row of customRoleRows.results ?? []) {
        for (const permission of parsePermissionsJson(row.permissions_json)) {
            customPermissions.add(permission);
        }
    }

    return {
        memberId: membership.id,
        role: membership.role,
        customRoleIds: (customRoleRows.results ?? []).map(row => row.id),
        customPermissions,
        highestCustomRolePosition: (customRoleRows.results ?? []).reduce(
            (highest, row) => Math.max(highest, Number(row.position ?? -1)),
            -1,
        ),
    };
}

async function requireWorkspaceMembership(request, env, workspaceId) {
    const auth = await requireUser(request, env);

    if ('response' in auth) {
        return auth;
    }

    const membership = await env.DB.prepare(
        `SELECT id, role
         FROM space_members
         WHERE space_id = ?
           AND user_id = ?
         LIMIT 1`
    )
        .bind(
            workspaceId,
            auth.user.id,
        )
        .first();

    if (!membership) {
        return {
            response:
                fail(
                    'You are not a member of this Space.',
                    403,
                ),
        };
    }

    if (request.method !== 'GET' && request.method !== 'HEAD' &&
        !['creator', 'staff', 'support'].includes(auth.user.platform_role)) {
        try {
            const restriction = await env.DB.prepare(
                `SELECT id FROM space_restrictions
                 WHERE space_id = ? AND active = 1
                   AND (expires_at IS NULL OR expires_at > ?)
                 ORDER BY created_at DESC LIMIT 1`
            ).bind(workspaceId, Date.now()).first();
            if (restriction) {
                return { response: fail('This Space is temporarily restricted to read-only by Spaces Support.', 423) };
            }
        } catch (caught) {
            console.warn('Space restriction lookup unavailable.', caught);
        }
    }

    let customRoleRows = { results: [] };
    try {
        customRoleRows = await env.DB.prepare(
            `SELECT r.id, r.permissions_json, r.position
             FROM space_member_roles mr
             JOIN space_roles r ON r.id = mr.role_id
             WHERE mr.space_id = ? AND mr.member_id = ?
             ORDER BY r.position DESC, r.created_at ASC`
        ).bind(workspaceId, membership.id).all();
    }
    catch (caught) {
        // Allows a rolling deployment before migration 0008 is applied.
        console.warn('Custom role lookup unavailable.', caught);
    }

    const customPermissions = new Set();
    for (const row of customRoleRows.results ?? []) {
        for (const permission of parsePermissionsJson(row.permissions_json)) {
            customPermissions.add(permission);
        }
    }

    const highestCustomRolePosition = (customRoleRows.results ?? []).reduce(
        (highest, row) => Math.max(highest, Number(row.position ?? -1)),
        -1,
    );

    return {
        user: auth.user,
        memberId: membership.id,
        role: membership.role,
        customRoleIds: (customRoleRows.results ?? []).map(row => row.id),
        customPermissions,
        highestCustomRolePosition,
    };
}

async function workspaceBootstrap(request, env, workspaceId) {
    const access = await requireWorkspaceMembership(
        request,
        env,
        workspaceId,
    );

    if ('response' in access) {
        return access.response;
    }

    const workspace = await env.DB.prepare(
        `SELECT
           s.id,
           s.name,
           s.code,
           s.avatar_url,
           s.description,
           s.background_preset,
           s.accent_color,
           s.banner_url,
           s.icon_decoration,
           s.created_at,
           s.owner_user_id,
           sm.role
         FROM spaces s
         JOIN space_members sm
           ON sm.space_id = s.id
          AND sm.user_id = ?
         WHERE s.id = ?
         LIMIT 1`
    )
        .bind(
            access.user.id,
            workspaceId,
        )
        .first();

    if (!workspace) {
        return fail(
            'Space not found.',
            404,
        );
    }

    const channels = await env.DB.prepare(
        `SELECT
           id,
           space_id,
           name,
           description,
           kind,
           sort_order,
           post_min_role,
           note_min_role
         FROM channels
         WHERE space_id = ?
         ORDER BY sort_order ASC, created_at ASC`
    )
        .bind(workspaceId)
        .all();

    const channelOverwriteRows = await env.DB.prepare(
        `SELECT * FROM channel_permission_overwrites WHERE space_id = ?`
    ).bind(workspaceId).all();
    const overwritesByChannel = new Map();
    for (const row of channelOverwriteRows.results ?? []) {
        const list = overwritesByChannel.get(row.channel_id) ?? [];
        list.push(row);
        overwritesByChannel.set(row.channel_id, list);
    }
    const visibleChannels = (channels.results ?? []).filter(channel => {
        if (access.role === 'owner' || accessHas(access, 'manage_channels')) return true;
        return channelPermissionDecision(access, overwritesByChannel.get(channel.id) ?? [], 'view_channel') !== 'deny';
    });
    const visibleChannelIds = new Set(visibleChannels.map(channel => channel.id));

    const members = await env.DB.prepare(
        `SELECT
           sm.id,
           sm.space_id,
           sm.user_id,
           sm.role,
           sm.joined_at,
           u.username,
           u.public_user_id,
           u.display_name,
           u.avatar_url,
           u.banner_url,
           u.profile_accent,
           u.bio,
           u.platform_role
         FROM space_members sm
         JOIN users u
           ON u.id = sm.user_id
         WHERE sm.space_id = ?
         ORDER BY
           CASE sm.role
             WHEN 'owner' THEN 0
             WHEN 'admin' THEN 1
             WHEN 'contributor' THEN 2
             ELSE 3
           END,
           sm.joined_at ASC`
    )
        .bind(workspaceId)
        .all();

    const customRoles = await env.DB.prepare(
        `SELECT *
         FROM space_roles
         WHERE space_id = ?
         ORDER BY position DESC, created_at ASC`
    ).bind(workspaceId).all();

    let baseRoleSettingsResult = { results: [] };
    try {
        baseRoleSettingsResult = await env.DB.prepare(
            `SELECT role, color, hoist, mentionable, updated_at
             FROM space_base_role_settings
             WHERE space_id = ?`
        ).bind(workspaceId).all();
    }
    catch {
        // Allows the frontend to remain compatible during the migration/deploy window.
    }
    const baseRoleSettingsRows = new Map((baseRoleSettingsResult.results ?? []).map(row => [String(row.role), row]));
    const baseRoles = {
        owner: baseRoleSettingFromRow(baseRoleSettingsRows.get('owner'), 'owner'),
        member: baseRoleSettingFromRow(baseRoleSettingsRows.get('member'), 'member'),
    };

    const memberRoleRows = await env.DB.prepare(
        `SELECT member_id, role_id
         FROM space_member_roles
         WHERE space_id = ?`
    ).bind(workspaceId).all();

    const memberRoles = roleAssignmentMap(memberRoleRows.results);

    const emojis = await env.DB.prepare(
        `SELECT *
         FROM space_emojis
         WHERE space_id = ?
         ORDER BY name COLLATE NOCASE ASC`
    ).bind(workspaceId).all();

    const notes = await env.DB.prepare(
        `SELECT *
         FROM notes
         WHERE space_id = ?
         ORDER BY updated_at DESC`
    )
        .bind(workspaceId)
        .all();

    const comments = await env.DB.prepare(
        `SELECT
           c.*,
           u.display_name AS author_name,
           u.username AS author_username,
           u.avatar_url AS author_avatar_url
         FROM note_comments c
         JOIN users u ON u.id = c.author_id
         WHERE c.space_id = ?
         ORDER BY c.created_at ASC`
    ).bind(workspaceId).all();

    const messages = await env.DB.prepare(
        `SELECT
           m.id, m.space_id, m.channel_id, m.author_id, m.body,
           m.created_at, m.edited_at, m.deleted_at, m.deleted_by,
           m.attachment_name, m.attachment_type, m.attachment_size,
           u.display_name AS author_name,
           u.username AS author_username
         FROM messages m
         JOIN users u
           ON u.id = m.author_id
         WHERE m.space_id = ?
         ORDER BY m.created_at DESC
         LIMIT 250`
    )
        .bind(workspaceId)
        .all();

    const logs = await env.DB.prepare(
        `SELECT
           l.*,
           u.display_name AS actor_name
         FROM audit_logs l
         JOIN users u
           ON u.id = l.actor_id
         WHERE l.space_id = ?
         ORDER BY l.created_at DESC
         LIMIT 250`
    )
        .bind(workspaceId)
        .all();

    const updates =
        await env.DB.prepare(
            `SELECT
               version,
               published_at,
               title,
               changes_json
             FROM platform_updates
             ORDER BY published_at DESC, version DESC`
        )
            .all();

    const visibleNoteIds = new Set((notes.results ?? []).filter(note => visibleChannelIds.has(note.channel_id)).map(note => note.id));

    return json({
        workspace: {
            id: workspace.id,
            name: workspace.name,
            code: workspace.code,
            avatarUrl:
                workspace.avatar_url ??
                null,
            description:
                workspace.description ??
                '',
            background:
                normalizeBackgroundPreset(workspace.background_preset),
            accentColor:
                normalizeHexColor(workspace.accent_color),
            bannerUrl:
                workspace.banner_url ?? null,
            iconDecoration:
                normalizeIconDecoration(workspace.icon_decoration),
            initials:
                workspace.name
                    .split(/\s+/u)
                    .filter(Boolean)
                    .slice(0, 2)
                    .map(
                        part =>
                            part
                                .slice(0, 1)
                                .toUpperCase(),
                    )
                    .join('') ||
                'S',
            createdAt: workspace.created_at,
            ownerId: workspace.owner_user_id,
            role: workspace.role,
        },

        channels:
            visibleChannels.map(
                channel => ({
                    id: channel.id,
                    workspaceId: channel.space_id,
                    name: channel.name,
                    description: channel.description,
                    kind: channel.kind,
                    order: channel.sort_order,
                    postMinRole: channel.post_min_role,
                    noteMinRole: channel.note_min_role,
                    effectivePermissions: (() => {
                        const rows = overwritesByChannel.get(channel.id) ?? [];
                        const postRequired = normalizeChannelPermission(channel.post_min_role, channel.kind === 'announcement' ? 'admin' : 'contributor');
                        const noteRequired = normalizeChannelPermission(channel.note_min_role, 'contributor');
                        const baseSend = postRequired !== 'disabled' && (roleMeetsPermission(access.role, postRequired) || accessHas(access, 'send_messages'));
                        const baseAttach = accessHas(access, 'attach_files');
                        const baseNotes = noteRequired !== 'disabled' && (roleMeetsPermission(access.role, noteRequired) || accessHas(access, 'edit_notes'));
                        const baseDeleteNotes = noteRequired !== 'disabled' && (roleMeetsPermission(access.role, noteRequired) || accessHas(access, 'delete_notes'));
                        return {
                            view_channel: true,
                            send_messages: channelPermissionAllowed(access, rows, 'send_messages', baseSend),
                            attach_files: channelPermissionAllowed(access, rows, 'attach_files', baseAttach),
                            create_notes: channelPermissionAllowed(access, rows, 'create_notes', baseNotes),
                            edit_notes: channelPermissionAllowed(access, rows, 'edit_notes', baseNotes),
                            delete_notes: channelPermissionAllowed(access, rows, 'delete_notes', baseDeleteNotes),
                        };
                    })(),
                }),
            ),

        members:
            members.results.map(
                member => ({
                    id: member.id,
                    workspaceId: member.space_id,
                    profileId: member.user_id,
                    publicUserId: member.public_user_id ?? '',
                    username: member.username,
                    displayName: member.display_name,
                    initials:
                        (
                            member.display_name ||
                            member.username ||
                            'S'
                        )
                            .slice(0, 1)
                            .toUpperCase(),
                    avatarUrl: member.avatar_url,
                    bannerUrl: member.banner_url ?? null,
                    profileAccent: normalizeHexColor(member.profile_accent),
                    bio: member.bio ?? '',
                    platformRole: clientPlatformRole(member.platform_role),
                    role: member.role,
                    customRoleIds: memberRoles.get(member.id) ?? [],
                    status:
                        member.user_id ===
                        access.user.id
                            ? 'online'
                            : 'offline',
                    joinedAt: member.joined_at,
                }),
            ),

        notes:
            notes.results.filter(note => visibleChannelIds.has(note.channel_id)).map(
                note => ({
                    id: note.id,
                    workspaceId: note.space_id,
                    channelId: note.channel_id,
                    title: note.title,
                    body: note.body,
                    createdBy: note.created_by,
                    updatedBy: note.updated_by,
                    createdAt: note.created_at,
                    updatedAt: note.updated_at,
                    version: note.version,
                }),
            ),

        messages:
            messages.results.filter(message => visibleChannelIds.has(message.channel_id)).map(
                message => ({
                    id: message.id,
                    workspaceId: message.space_id,
                    channelId: message.channel_id,
                    authorId: message.author_id,
                    authorName: message.author_name,
                    authorInitials:
                        (
                            message.author_name ||
                            message.author_username ||
                            'S'
                        )
                            .slice(0, 1)
                            .toUpperCase(),
                    body: message.body,
                    createdAt: message.created_at,
                    editedAt: message.edited_at,
                    deletedAt: message.deleted_at ?? null,
                    deletedBy: message.deleted_by ?? null,
                    attachment: messageAttachmentFromRow(message),
                }),
            ),

        comments:
            comments.results.filter(comment => visibleNoteIds.has(comment.note_id)).map(noteCommentFromRow),

        roles:
            customRoles.results.map(customRoleFromRow),

        baseRoles,

        emojis:
            emojis.results.map(emojiFromRow),

        logs:
            logs.results.map(
                log => ({
                    id: log.id,
                    workspaceId: log.space_id,
                    actorId: log.actor_id,
                    actorName: log.actor_name,
                    action: log.action,
                    targetLabel: log.target_label,
                    reason: log.reason,
                    createdAt: log.created_at,
                    metadata:
                        (() => {
                            try {
                                return JSON.parse(
                                    log.metadata_json ||
                                    '{}',
                                );
                            }
                            catch {
                                return {};
                            }
                        })(),
                }),
            ),

        updates:
            updates.results.map(
                update => ({
                    version:
                        update.version,
                    publishedAt:
                        update.published_at,
                    title:
                        update.title,
                    changes:
                        (() => {
                            try {
                                const parsed =
                                    JSON.parse(
                                        update.changes_json,
                                    );

                                return Array.isArray(
                                    parsed,
                                )
                                    ? parsed
                                    : [];
                            }
                            catch {
                                return [];
                            }
                        })(),
                }),
            ),
    });
}


async function workspaceSync(
    request,
    env,
    workspaceId,
) {
    const access =
        await requireWorkspaceMembership(
            request,
            env,
            workspaceId,
        );

    if ('response' in access) {
        return access.response;
    }

    const url =
        new URL(
            request.url,
        );

    const rawSince =
        Number(
            url.searchParams.get(
                'since',
            ) ??
            0,
        );

    const since =
        Number.isFinite(
            rawSince,
        )
            ? Math.max(
                0,
                Math.floor(
                    rawSince,
                ),
            )
            : 0;

    const includeStructure =
        url.searchParams.get(
            'structure',
        ) ===
        '1';

    const serverTime =
        Date.now();

    const workspace =
        await env.DB.prepare(
            `SELECT
               s.id,
               s.name,
               s.code,
               s.avatar_url,
               s.description,
               s.background_preset,
               s.accent_color,
               s.banner_url,
               s.icon_decoration,
               s.created_at,
               s.owner_user_id,
               sm.role
             FROM spaces s
             JOIN space_members sm
               ON sm.space_id = s.id
              AND sm.user_id = ?
             WHERE s.id = ?
             LIMIT 1`
        )
            .bind(
                access.user.id,
                workspaceId,
            )
            .first();

    if (!workspace) {
        return fail(
            'Space not found.',
            404,
        );
    }

    const channels =
        includeStructure
            ? await env.DB.prepare(
                `SELECT
                   id,
                   space_id,
                   name,
                   description,
                   kind,
                   sort_order,
                   post_min_role,
                   note_min_role
                 FROM channels
                 WHERE space_id = ?
                 ORDER BY sort_order ASC, created_at ASC`
            )
                .bind(
                    workspaceId,
                )
                .all()
            : null;

    const members =
        includeStructure
            ? await env.DB.prepare(
                `SELECT
                   sm.id,
                   sm.space_id,
                   sm.user_id,
                   sm.role,
                   sm.joined_at,
                   u.username,
                   u.public_user_id,
                   u.display_name,
                   u.avatar_url,
                   u.platform_role
                 FROM space_members sm
                 JOIN users u
                   ON u.id = sm.user_id
                 WHERE sm.space_id = ?
                 ORDER BY
                   CASE sm.role
                     WHEN 'owner' THEN 0
                     WHEN 'admin' THEN 1
                     WHEN 'contributor' THEN 2
                     ELSE 3
                   END,
                   u.display_name COLLATE NOCASE`
            )
                .bind(
                    workspaceId,
                )
                .all()
            : null;

    const customRoles =
        includeStructure
            ? await env.DB.prepare(
                `SELECT * FROM space_roles WHERE space_id = ? ORDER BY position DESC, created_at ASC`
            ).bind(workspaceId).all()
            : null;

    const memberRoleRows =
        includeStructure
            ? await env.DB.prepare(
                `SELECT member_id, role_id FROM space_member_roles WHERE space_id = ?`
            ).bind(workspaceId).all()
            : null;

    const memberRoles = roleAssignmentMap(memberRoleRows?.results ?? []);

    const emojis =
        includeStructure
            ? await env.DB.prepare(
                `SELECT * FROM space_emojis WHERE space_id = ? ORDER BY name COLLATE NOCASE ASC`
            ).bind(workspaceId).all()
            : null;

    const notes =
        await env.DB.prepare(
            `SELECT *
             FROM notes
             WHERE space_id = ?
               AND updated_at > ?
             ORDER BY updated_at DESC`
        )
            .bind(
                workspaceId,
                since,
            )
            .all();

    const comments = await env.DB.prepare(
        `SELECT
           c.*,
           u.display_name AS author_name,
           u.username AS author_username,
           u.avatar_url AS author_avatar_url
         FROM note_comments c
         JOIN users u ON u.id = c.author_id
         WHERE c.space_id = ?
           AND (c.created_at > ? OR COALESCE(c.edited_at, 0) > ? OR COALESCE(c.deleted_at, 0) > ?)
         ORDER BY c.created_at ASC`
    ).bind(workspaceId, since, since, since).all();

    const messages =
        await env.DB.prepare(
            `SELECT
               m.id,
               m.space_id,
               m.channel_id,
               m.author_id,
               m.body,
               m.created_at,
               m.edited_at,
               m.deleted_at,
               m.deleted_by,
               m.attachment_name,
               m.attachment_type,
               m.attachment_size,
               u.display_name AS author_name,
               u.username AS author_username
             FROM messages m
             JOIN users u
               ON u.id = m.author_id
             WHERE m.space_id = ?
               AND (
                 m.created_at > ? OR
                 COALESCE(m.edited_at, 0) > ? OR
                 COALESCE(m.deleted_at, 0) > ?
               )
             ORDER BY m.created_at ASC`
        )
            .bind(
                workspaceId,
                since,
                since,
                since,
            )
            .all();

    const logs =
        await env.DB.prepare(
            `SELECT
               a.id,
               a.space_id,
               a.actor_id,
               a.action,
               a.target_id,
               a.target_label,
               a.reason,
               a.metadata_json,
               a.created_at,
               u.display_name AS actor_name
             FROM audit_logs a
             JOIN users u
               ON u.id = a.actor_id
             WHERE a.space_id = ?
               AND a.created_at > ?
             ORDER BY a.created_at DESC`
        )
            .bind(
                workspaceId,
                since,
            )
            .all();

    return json({
        serverTime,

        workspace:
            workspaceSummaryFromRow(
                workspace,
            ),

        channels:
            channels
                ? channels.results.map(
                    channel => ({
                        id:
                            channel.id,
                        workspaceId:
                            channel.space_id,
                        name:
                            channel.name,
                        description:
                            channel.description,
                        kind:
                            channel.kind,
                        order:
                            channel.sort_order,
                        postMinRole:
                            channel.post_min_role,
                        noteMinRole:
                            channel.note_min_role,
                    }),
                )
                : null,

        members:
            members
                ? members.results.map(
                    member => ({
                        id:
                            member.id,
                        workspaceId:
                            member.space_id,
                        profileId:
                            member.user_id,
                        publicUserId:
                            member.public_user_id ?? '',
                        username:
                            member.username,
                        displayName:
                            member.display_name,
                        initials:
                            (
                                member.display_name ||
                                member.username ||
                                'S'
                            )
                                .slice(
                                    0,
                                    1,
                                )
                                .toUpperCase(),
                        avatarUrl:
                            member.avatar_url,
                        platformRole:
                            clientPlatformRole(member.platform_role),
                        role:
                            member.role,
                        customRoleIds:
                            memberRoles.get(member.id) ?? [],
                        status:
                            member.user_id ===
                            access.user.id
                                ? 'online'
                                : 'offline',
                        joinedAt:
                            member.joined_at,
                    }),
                )
                : null,

        notes:
            notes.results.map(
                note => ({
                    id:
                        note.id,
                    workspaceId:
                        note.space_id,
                    channelId:
                        note.channel_id,
                    title:
                        note.title,
                    body:
                        note.body,
                    createdBy:
                        note.created_by,
                    updatedBy:
                        note.updated_by,
                    version:
                        note.version,
                    createdAt:
                        note.created_at,
                    updatedAt:
                        note.updated_at,
                }),
            ),

        messages:
            messages.results.map(
                message => ({
                    id:
                        message.id,
                    workspaceId:
                        message.space_id,
                    channelId:
                        message.channel_id,
                    authorId:
                        message.author_id,
                    authorName:
                        message.author_name,
                    authorInitials:
                        (
                            message.author_name ||
                            message.author_username ||
                            'S'
                        )
                            .slice(
                                0,
                                1,
                            )
                            .toUpperCase(),
                    body:
                        message.body,
                    createdAt:
                        message.created_at,
                    editedAt:
                        message.edited_at,
                    deletedAt:
                        message.deleted_at ?? null,
                    deletedBy:
                        message.deleted_by ?? null,
                    attachment:
                        messageAttachmentFromRow(message),
                }),
            ),

        comments:
            comments.results.map(noteCommentFromRow),

        roles:
            customRoles ? customRoles.results.map(customRoleFromRow) : null,

        emojis:
            emojis ? emojis.results.map(emojiFromRow) : null,

        logs:
            logs.results.map(
                log => ({
                    id:
                        log.id,
                    workspaceId:
                        log.space_id,
                    actorId:
                        log.actor_id,
                    actorName:
                        log.actor_name,
                    action:
                        log.action,
                    targetLabel:
                        log.target_label,
                    reason:
                        log.reason,
                    createdAt:
                        log.created_at,
                    metadata:
                        (() => {
                            try {
                                return JSON.parse(
                                    log.metadata_json ||
                                    '{}',
                                );
                            }
                            catch {
                                return {};
                            }
                        })(),
                }),
            ),

        deletedNoteIds:
            logs.results
                .filter(
                    log =>
                        log.action ===
                            'note.deleted' &&
                        log.target_id,
                )
                .map(
                    log =>
                        log.target_id,
                ),
    });
}

function clientPlatformRole(value) {
    return value === 'creator' ? 'founder' : value;
}

async function nextPublicUserId(env) {
    const row = await env.DB.prepare(
        `UPDATE platform_counters
         SET value = value + 1
         WHERE key = 'public_user_id'
         RETURNING value - 1 AS public_number`
    ).first();
    const next = Number(row?.public_number ?? 0);
    if (!Number.isFinite(next) || next < 100 || next > 99999) {
        throw new ApiRequestError('Spaces public ID capacity reached.', 503);
    }
    return String(next).padStart(5, '0');
}

function hasPrivateSpacesAccess(user) {
    return (
        user?.platform_role === 'creator' ||
        user?.platform_role === 'staff' ||
        user?.platform_role === 'support' ||
        Number(user?.spaces_access ?? 0) === 1
    );
}

function canEditPlatformUpdates(user) {
    return (
        user.username === 'spagotei' &&
        user.platform_role === 'creator'
    );
}

async function requirePlatformUpdateEditor(request, env) {
    const auth =
        await requireUser(
            request,
            env,
        );

    if ('response' in auth) {
        return auth;
    }

    if (!canEditPlatformUpdates(auth.user)) {
        return {
            response:
                fail(
                    'Only @spagotei can edit platform updates.',
                    403,
                ),
        };
    }

    return {
        user:
            auth.user,
    };
}

async function activePlatformBan(env, userId) {
    const now = Date.now();

    return env.DB.prepare(
        `SELECT
           id,
           reason,
           created_at,
           expires_at
         FROM platform_bans
         WHERE user_id = ?
           AND active = 1
           AND (
             expires_at IS NULL OR
             expires_at > ?
           )
         ORDER BY created_at DESC
         LIMIT 1`
    )
        .bind(
            userId,
            now,
        )
        .first();
}

async function requirePlatformModerator(request, env) {
    const auth = await requireUser(request, env);

    if ('response' in auth) {
        return auth;
    }

    if (
        auth.user.platform_role !== 'creator' &&
        auth.user.platform_role !== 'staff' &&
        auth.user.platform_role !== 'support'
    ) {
        return {
            response:
                fail(
                    'Platform moderation access required.',
                    403,
                ),
        };
    }

    return {
        user:
            auth.user,
    };
}

async function requireSupportConsole(request, env) {
    const auth = await requireUser(request, env);
    if ('response' in auth) return auth;
    if (!['creator', 'staff', 'support'].includes(auth.user.platform_role)) {
        return { response: fail('Support Console access required.', 403) };
    }
    return { user: auth.user };
}

function supportRoleCanActOn(actorRole, targetRole) {
    if (actorRole === 'creator') return targetRole !== 'creator';
    if (actorRole === 'staff') return targetRole !== 'creator' && targetRole !== 'staff';
    if (actorRole === 'support') return !targetRole;
    return false;
}

function publicProfile(user) {
    return {
        id: user.id,
        publicUserId: user.public_user_id ?? '',
        username: user.username,
        displayName: user.display_name,
        initials: user.display_name
            .trim()
            .slice(0, 1)
            .toUpperCase() ||
            user.username
                .slice(0, 1)
                .toUpperCase(),
        avatarUrl: user.avatar_url,
        bannerUrl: user.banner_url ?? null,
        profileAccent: normalizeHexColor(user.profile_accent),
        bio: user.bio,
        platformRole: clientPlatformRole(user.platform_role),
        publicProfile: Boolean(user.public_profile),
        createdAt: user.created_at,
    };
}
async function readJson(request) {
    const declaredLength = Number(
        request.headers.get('Content-Length') ?? 0,
    );

    if (
        Number.isFinite(declaredLength) &&
        declaredLength > MAX_JSON_BODY_BYTES
    ) {
        throw new ApiRequestError(
            'Request body is too large.',
            413,
        );
    }

    const raw = await request.text();

    if (encoder.encode(raw).byteLength > MAX_JSON_BODY_BYTES) {
        throw new ApiRequestError(
            'Request body is too large.',
            413,
        );
    }

    try {
        return raw ? JSON.parse(raw) : {};
    }
    catch {
        throw new ApiRequestError(
            'Invalid JSON body.',
            400,
        );
    }
}
async function createSession(env, user) {
    const now = Date.now();
    const token = randomToken();
    const tokenHash = await sha256Base64(token);
    const sessionId = crypto.randomUUID();
    const expiresAt = now + SESSION_TTL_MS;
    await env.DB.prepare(`INSERT INTO sessions
      (
        id,
        user_id,
        token_hash,
        created_at,
        expires_at,
        last_seen_at
      )
     VALUES (?, ?, ?, ?, ?, ?)`)
        .bind(sessionId, user.id, tokenHash, now, expiresAt, now)
        .run();
    return json({
        token,
        expiresAt,
        profile: publicProfile(user),
    });
}
async function authUser(request, env) {
    const authorization = request.headers.get('Authorization') ?? '';
    if (!authorization.startsWith('Bearer ')) {
        return null;
    }
    const token = authorization.slice(7).trim();
    if (!token) {
        return null;
    }
    const tokenHash = await sha256Base64(token);
    const now = Date.now();
    const row = await env.DB.prepare(`SELECT
         u.*,
         s.id AS session_id,
         s.expires_at
           AS session_expires_at,
         s.last_seen_at
           AS session_last_seen_at
       FROM sessions s
       JOIN users u
         ON u.id = s.user_id
       WHERE s.token_hash = ?
         AND s.expires_at > ?
       LIMIT 1`)
        .bind(tokenHash, now)
        .first();
    if (!row) {
        return null;
    }

    const ban =
        await activePlatformBan(
            env,
            row.id,
        );

    if (ban) {
        await env.DB.prepare(
            `DELETE FROM sessions
             WHERE user_id = ?`
        )
            .bind(row.id)
            .run();

        return null;
    }

    if (now - row.session_last_seen_at >
        60_000) {
        await env.DB.prepare(`UPDATE sessions
       SET last_seen_at = ?
       WHERE id = ?`)
            .bind(now, row.session_id)
            .run();
    }
    return row;
}
async function requireUser(request, env) {
    const user = await authUser(request, env);
    if (!user) {
        return {
            response: fail('Unauthorized.', 401),
        };
    }
    if (!hasPrivateSpacesAccess(user)) {
        return {
            response: fail(
                'Spaces is currently in private development. This account does not have access.',
                403,
            ),
        };
    }
    return { user };
}
async function register(request, env) {
    const body = await readJson(request);
    const username = normalizeUsername(body.username ?? '');

    await enforceRateLimit(
        request,
        env,
        'register',
        8,
        1000 * 60 * 60,
    );

    const displayName = String(body.displayName ?? '')
        .trim();
    const passwordSalt = body.passwordSalt ?? '';
    const passwordVerifier = body.passwordVerifier ?? '';
    const passwordIterations = Number(body.passwordIterations ?? 0);
    if (!validNewUsername(username)) {
        return fail('Username must be 4-24 characters using lowercase letters, numbers, or underscore.');
    }
    if (reservedUsername(username)) {
        return fail('That username is reserved.', 409);
    }
    if (displayName.length < 1 ||
        displayName.length > 40) {
        return fail('Display name must be 1-40 characters.');
    }
    if (passwordIterations !== CLIENT_PASSWORD_ITERATIONS) {
        return fail('Unsupported password verifier settings.');
    }

    if (!isBase64Bytes(passwordSalt, 16) ||
        !isBase64Bytes(passwordVerifier, 32)) {
        return fail('Invalid password verifier.');
    }
    const existing = await env.DB.prepare(`SELECT id
       FROM users
       WHERE username = ?
       LIMIT 1`)
        .bind(username)
        .first();
    if (existing) {
        return fail('That username is already taken.', 409);
    }
    const verifierHash = await hashPasswordVerifier(passwordVerifier);
    const now = Date.now();
    const id = crypto.randomUUID();
    const publicUserId = await nextPublicUserId(env);
    await env.DB.prepare(`INSERT INTO users
      (
        id,
        public_user_id,
        username,
        display_name,
        password_salt,
        password_hash,
        avatar_url,
        bio,
        public_profile,
        platform_role,
        created_at,
        updated_at
      )
     VALUES (
       ?, ?, ?, ?, ?, ?,
       NULL, '', 1, NULL, ?, ?
     )`)
        .bind(
            id,
            publicUserId,
            username,
            displayName,
            passwordSalt,
            `client-pbkdf2-sha256$${passwordIterations}$${verifierHash}`,
            now,
            now,
        )
        .run();
    await ensureHubMembership(
        env,
        id,
    );

    const user = await env.DB.prepare(`SELECT *
       FROM users
       WHERE id = ?
       LIMIT 1`)
        .bind(id)
        .first();
    if (!user) {
        return fail('Account creation failed.', 500);
    }
    return createSession(env, user);
}
async function authChallenge(request, env) {
    const url = new URL(request.url);
    const username = normalizeUsername(url.searchParams.get('username') ?? '');

    await enforceRateLimit(
        request,
        env,
        'auth-challenge',
        40,
        1000 * 60 * 5,
        username,
    );

    if (!validUsername(username)) {
        return fail('Invalid username.', 400);
    }

    const user = await env.DB.prepare(
        `SELECT password_salt, password_hash
         FROM users
         WHERE username = ?
         LIMIT 1`
    )
        .bind(username)
        .first();

    // Return a fake salt for unknown usernames so the client still performs
    // the same KDF work and the endpoint does not directly reveal existence.
    if (!user) {
        const fakeSaltBytes = new Uint8Array(16);
        crypto.getRandomValues(fakeSaltBytes);

        return json({
            salt: bytesToBase64(fakeSaltBytes),
            iterations: CLIENT_PASSWORD_ITERATIONS,
        });
    }

    const parsed = parseClientPasswordHash(user.password_hash);

    return json({
        salt: user.password_salt,
        iterations: parsed?.iterations ?? CLIENT_PASSWORD_ITERATIONS,
    });
}

async function login(request, env) {
    const body = await readJson(request);
    const username = normalizeUsername(body.username ?? '');

    await enforceRateLimit(
        request,
        env,
        'login',
        12,
        1000 * 60 * 10,
        username,
    );

    const passwordVerifier = body.passwordVerifier ?? '';
    const user = await env.DB.prepare(`SELECT *
       FROM users
       WHERE username = ?
       LIMIT 1`)
        .bind(username)
        .first();
    if (!user) {
        return fail('Invalid username or password.', 401);
    }
    const validPassword = await verifyPasswordVerifier(
        user,
        passwordVerifier,
        env,
    );

    if (!validPassword) {
        return fail('Invalid username or password.', 401);
    }
    const ban =
        await activePlatformBan(
            env,
            user.id,
        );

    if (ban) {
        return fail(
            'This Spaces account is banned.',
            403,
        );
    }

    if (!hasPrivateSpacesAccess(user)) {
        return fail(
            'Spaces is currently in private development. This account does not have access.',
            403,
        );
    }

    if (Boolean(user.totp_enabled) && user.totp_secret) {
        const twoFactorCode = String(body.twoFactorCode ?? '').trim();
        if (!twoFactorCode) {
            return json({ requiresTwoFactor: true }, 202);
        }
        await enforceRateLimit(
            request,
            env,
            'login-2fa',
            12,
            1000 * 60 * 10,
            username,
        );
        const validTotp = await verifyTotp(user.totp_secret, twoFactorCode);
        const validRecovery = validTotp ? false : await useRecoveryCode(env, user.id, twoFactorCode);
        if (!validTotp && !validRecovery) {
            return fail('Invalid authenticator or recovery code.', 401);
        }
    }

    return createSession(env, user);
}
async function logout(request, env) {
    const authorization = request.headers.get('Authorization') ?? '';
    if (!authorization.startsWith('Bearer ')) {
        return json({ ok: true });
    }
    const token = authorization.slice(7).trim();
    if (!token) {
        return json({ ok: true });
    }
    const tokenHash = await sha256Base64(token);
    await env.DB.prepare(`DELETE FROM sessions
     WHERE token_hash = ?`)
        .bind(tokenHash)
        .run();
    return json({ ok: true });
}
async function me(request, env) {
    const auth = await requireUser(request, env);
    if ('response' in auth) {
        return auth.response;
    }
    return json(publicProfile(auth.user));
}
async function updateProfile(request, env) {
    const auth = await requireUser(request, env);
    if ('response' in auth) {
        return auth.response;
    }
    const body = await readJson(request);
    const displayName = String(
        body.displayName ?? auth.user.display_name,
    ).trim();
    const bio = String(
        body.bio ?? auth.user.bio ?? '',
    );
    const publicFlag = body.publicProfile ??
        Boolean(auth.user.public_profile);
    const profileAccent = body.profileAccent === undefined
        ? normalizeHexColor(auth.user.profile_accent)
        : normalizeHexColor(body.profileAccent);
    if (displayName.length < 1 ||
        displayName.length > 40) {
        return fail('Display name must be 1-40 characters.');
    }
    if (bio.length > 240) {
        return fail('Bio must be 240 characters or fewer.');
    }
    const now = Date.now();
    await env.DB.prepare(`UPDATE users
     SET
       display_name = ?,
       bio = ?,
       public_profile = ?,
       profile_accent = ?,
       updated_at = ?
     WHERE id = ?`)
        .bind(displayName, bio, publicFlag ? 1 : 0, profileAccent, now, auth.user.id)
        .run();
    const updated = await env.DB.prepare(`SELECT *
       FROM users
       WHERE id = ?
       LIMIT 1`)
        .bind(auth.user.id)
        .first();
    return updated
        ? json(publicProfile(updated))
        : fail('Profile update failed.', 500);
}
async function updateAvatar(request, env) {
    const auth = await requireUser(request, env);
    if ('response' in auth) {
        return auth.response;
    }
    const body = await readJson(request);
    const avatarUrl = body.avatarUrl === null
        ? null
        : (body.avatarUrl ?? '').trim();
    if (avatarUrl) {
        const allowGif = auth.user.platform_role === 'creator';
        if (isGifStoredImage(avatarUrl) && !allowGif) {
            return fail('Animated GIF profile pictures are reserved for the Spaces Founder.', 403);
        }
        if (!validStoredImage(avatarUrl, { allowGif })) {
            return fail('Avatar must be an HTTPS image or a compressed profile image.');
        }
    }
    const now = Date.now();
    await env.DB.prepare(`UPDATE users
     SET
       avatar_url = ?,
       updated_at = ?
     WHERE id = ?`)
        .bind(avatarUrl, now, auth.user.id)
        .run();
    const updated = await env.DB.prepare(`SELECT *
       FROM users
       WHERE id = ?
       LIMIT 1`)
        .bind(auth.user.id)
        .first();
    return updated
        ? json(publicProfile(updated))
        : fail('Avatar update failed.', 500);
}

async function updateBanner(request, env) {
    const auth = await requireUser(request, env);
    if ('response' in auth) {
        return auth.response;
    }
    const body = await readJson(request);
    const bannerUrl = body.bannerUrl === null
        ? null
        : String(body.bannerUrl ?? '').trim();
    const allowGif = auth.user.platform_role === 'creator';
    if (bannerUrl && isGifStoredImage(bannerUrl) && !allowGif) {
        return fail('Animated GIF profile banners are reserved for the Spaces Founder.', 403);
    }
    if (bannerUrl && !validStoredImage(bannerUrl, { allowGif })) {
        return fail('Profile banner must be an HTTPS image or a compressed image.');
    }
    const now = Date.now();
    await env.DB.prepare(`UPDATE users
     SET banner_url = ?, updated_at = ?
     WHERE id = ?`)
        .bind(bannerUrl, now, auth.user.id)
        .run();
    const updated = await env.DB.prepare(`SELECT * FROM users WHERE id = ? LIMIT 1`)
        .bind(auth.user.id)
        .first();
    return updated
        ? json(publicProfile(updated))
        : fail('Banner update failed.', 500);
}

async function changeAccountPassword(
    request,
    env,
) {
    const auth =
        await requireUser(
            request,
            env,
        );

    if ('response' in auth) {
        return auth.response;
    }

    const body =
        await readJson(request);

    const currentVerifier =
        body.currentPasswordVerifier ??
        '';

    const newSalt =
        body.newPasswordSalt ??
        '';

    const newVerifier =
        body.newPasswordVerifier ??
        '';

    const newIterations =
        Number(
            body.newPasswordIterations ??
            0,
        );

    const currentValid =
        await verifyPasswordVerifier(
            auth.user,
            currentVerifier,
            env,
        );

    if (!currentValid) {
        return fail(
            'Current password is incorrect.',
            401,
        );
    }

    if (
        newIterations !==
        CLIENT_PASSWORD_ITERATIONS ||
        !isBase64Bytes(
            newSalt,
            16,
        ) ||
        !isBase64Bytes(
            newVerifier,
            32,
        )
    ) {
        return fail(
            'Invalid new password verifier.',
        );
    }

    const newVerifierHash =
        await hashPasswordVerifier(
            newVerifier,
        );

    const now =
        Date.now();

    await env.DB.prepare(
        `UPDATE users
         SET
           password_salt = ?,
           password_hash = ?,
           updated_at = ?
         WHERE id = ?`
    )
        .bind(
            newSalt,
            `client-pbkdf2-sha256$${newIterations}$${newVerifierHash}`,
            now,
            auth.user.id,
        )
        .run();

    await env.DB.prepare(
        `DELETE FROM sessions
         WHERE user_id = ?
           AND id <> ?`
    )
        .bind(
            auth.user.id,
            auth.user.session_id,
        )
        .run();

    return new Response(
        null,
        {
            status:
                204,
            headers:
                corsHeaders(),
        },
    );
}

async function listAccountSessions(
    request,
    env,
) {
    const auth =
        await requireUser(
            request,
            env,
        );

    if ('response' in auth) {
        return auth.response;
    }

    const result =
        await env.DB.prepare(
            `SELECT
               id,
               created_at,
               expires_at,
               last_seen_at
             FROM sessions
             WHERE user_id = ?
             ORDER BY last_seen_at DESC`
        )
            .bind(
                auth.user.id,
            )
            .all();

    return json(
        result.results.map(
            session => ({
                id:
                    session.id,
                createdAt:
                    session.created_at,
                expiresAt:
                    session.expires_at,
                lastSeenAt:
                    session.last_seen_at,
                current:
                    session.id ===
                    auth.user.session_id,
            }),
        ),
    );
}

async function revokeAccountSession(
    request,
    env,
    sessionId,
) {
    const auth =
        await requireUser(
            request,
            env,
        );

    if ('response' in auth) {
        return auth.response;
    }

    await env.DB.prepare(
        `DELETE FROM sessions
         WHERE id = ?
           AND user_id = ?`
    )
        .bind(
            sessionId,
            auth.user.id,
        )
        .run();

    return new Response(
        null,
        {
            status:
                204,
            headers:
                corsHeaders(),
        },
    );
}


async function getAccountSecurity(request, env) {
    const auth = await requireUser(request, env);
    if ('response' in auth) return auth.response;
    const fresh = await env.DB.prepare(`SELECT * FROM users WHERE id = ? LIMIT 1`)
        .bind(auth.user.id)
        .first();
    if (!fresh) return fail('Account not found.', 404);
    return json(await accountSecurityStatus(env, fresh));
}

async function startAccountEmailVerification(request, env) {
    const auth = await requireUser(request, env);
    if ('response' in auth) return auth.response;

    await enforceRateLimit(request, env, 'email-verify-start', 5, 1000 * 60 * 60, auth.user.id);
    const body = await readJson(request);
    const email = normalizeEmail(body.email);
    if (!validEmail(email)) return fail('Enter a valid email address.');

    const fresh = await env.DB.prepare(`SELECT * FROM users WHERE id = ? LIMIT 1`)
        .bind(auth.user.id)
        .first();
    if (!fresh) return fail('Account not found.', 404);
    const currentEmail = normalizeEmail(fresh.email ?? '');
    const changingVerifiedEmail = Boolean(fresh.email_verified && currentEmail && currentEmail !== email);
    if (changingVerifiedEmail) {
        await enforceRateLimit(request, env, 'email-change-reauth', 12, 1000 * 60 * 60, auth.user.id);
        if (fresh.totp_enabled && fresh.totp_secret) {
            const twoFactorCode = String(body.twoFactorCode ?? '').trim();
            if (!await verifyTotp(fresh.totp_secret, twoFactorCode)) {
                return fail('Enter the current authenticator code to change your verified email.', 401);
            }
        } else {
            const currentPasswordVerifier = String(body.currentPasswordVerifier ?? '');
            if (!await verifyPasswordVerifier(fresh, currentPasswordVerifier, env)) {
                return fail('Current password is incorrect.', 401);
            }
        }
    }
    if (!env.EMAIL || typeof env.EMAIL.send !== 'function') {
        return fail('Cloudflare Email Service is not configured yet.', 503);
    }
    const sender = String(env.SPACES_EMAIL_FROM ?? '').trim();
    if (!sender) return fail('SPACES_EMAIL_FROM is not configured yet.', 503);

    const existing = await env.DB.prepare(
        `SELECT id FROM users WHERE email = ? AND id <> ? LIMIT 1`
    ).bind(email, auth.user.id).first();
    if (existing) return fail('That email is already linked to another account.', 409);

    const id = crypto.randomUUID();
    const code = randomNumericCode(6);
    const codeHash = await sha256Base64(`${id}:${code}`);
    const now = Date.now();
    const expiresAt = now + EMAIL_CODE_TTL_MS;

    await env.DB.prepare(`DELETE FROM account_email_challenges WHERE user_id = ?`).bind(auth.user.id).run();
    await env.DB.prepare(
        `INSERT INTO account_email_challenges
          (id, user_id, email, code_hash, created_at, expires_at, attempts)
         VALUES (?, ?, ?, ?, ?, ?, 0)`
    ).bind(id, auth.user.id, email, codeHash, now, expiresAt).run();

    try {
        await env.EMAIL.send({
            to: email,
            from: { email: sender, name: 'Spaces' },
            replyTo: String(env.SPACES_EMAIL_REPLY_TO ?? '').trim() || sender,
            subject: 'Verify your Spaces email',
            text: `Your Spaces verification code is ${code}. It expires in 10 minutes. If you did not request this, you can ignore this email.`,
            html: `<div style="font-family:Arial,sans-serif;background:#0b0b0f;color:#f4f1f7;padding:28px"><h2 style="margin:0 0 12px">Verify your Spaces email</h2><p style="color:#b7afbf">Enter this code in Spaces. It expires in 10 minutes.</p><div style="font-size:32px;letter-spacing:8px;font-weight:700;padding:18px 0">${code}</div><p style="color:#82798a;font-size:13px">If you did not request this, you can ignore this message.</p></div>`,
        });
    }
    catch (error) {
        console.error('Email verification send failed', error);
        await env.DB.prepare(`DELETE FROM account_email_challenges WHERE id = ?`).bind(id).run();
        return fail('Could not send the verification email.', 502);
    }

    return json({ sent: true, email, expiresAt });
}

async function verifyAccountEmail(request, env) {
    const auth = await requireUser(request, env);
    if ('response' in auth) return auth.response;
    await enforceRateLimit(request, env, 'email-verify-code', 12, 1000 * 60 * 10, auth.user.id);
    const body = await readJson(request);
    const code = String(body.code ?? '').replace(/\D/gu, '').slice(0, 6);
    if (!/^\d{6}$/u.test(code)) return fail('Enter the 6-digit verification code.');

    const challenge = await env.DB.prepare(
        `SELECT * FROM account_email_challenges
         WHERE user_id = ?
         ORDER BY created_at DESC
         LIMIT 1`
    ).bind(auth.user.id).first();
    if (!challenge || Number(challenge.expires_at) <= Date.now()) {
        return fail('That verification code expired. Send a new one.', 410);
    }
    if (Number(challenge.attempts ?? 0) >= 8) return fail('Too many incorrect attempts. Send a new code.', 429);
    const expected = await sha256Base64(`${challenge.id}:${code}`);
    if (!constantTimeEqual(expected, challenge.code_hash)) {
        await env.DB.prepare(`UPDATE account_email_challenges SET attempts = attempts + 1 WHERE id = ?`).bind(challenge.id).run();
        return fail('That verification code is not correct.', 401);
    }

    const duplicate = await env.DB.prepare(`SELECT id FROM users WHERE email = ? AND id <> ? LIMIT 1`)
        .bind(challenge.email, auth.user.id)
        .first();
    if (duplicate) return fail('That email is already linked to another account.', 409);

    const now = Date.now();
    await env.DB.prepare(`UPDATE users SET email = ?, email_verified = 1, updated_at = ? WHERE id = ?`)
        .bind(challenge.email, now, auth.user.id)
        .run();
    await env.DB.prepare(`DELETE FROM account_email_challenges WHERE user_id = ?`).bind(auth.user.id).run();
    const fresh = await env.DB.prepare(`SELECT * FROM users WHERE id = ? LIMIT 1`).bind(auth.user.id).first();
    return json(await accountSecurityStatus(env, fresh));
}

async function beginAccountTwoFactorSetup(request, env) {
    const auth = await requireUser(request, env);
    if ('response' in auth) return auth.response;
    const fresh = await env.DB.prepare(`SELECT * FROM users WHERE id = ? LIMIT 1`).bind(auth.user.id).first();
    if (!fresh) return fail('Account not found.', 404);
    if (Boolean(fresh.totp_enabled) && fresh.totp_secret) return fail('Two-factor authentication is already enabled.', 409);
    await enforceRateLimit(request, env, '2fa-setup', 8, 1000 * 60 * 60, auth.user.id);

    const secret = randomTotpSecret();
    const now = Date.now();
    const expiresAt = now + TOTP_SETUP_TTL_MS;
    await env.DB.prepare(
        `INSERT INTO account_totp_setups (user_id, secret, created_at, expires_at)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(user_id) DO UPDATE SET secret = excluded.secret, created_at = excluded.created_at, expires_at = excluded.expires_at`
    ).bind(auth.user.id, secret, now, expiresAt).run();

    const label = encodeURIComponent(`Spaces:${fresh.username}`);
    const issuer = encodeURIComponent('Spaces');
    const otpauthUri = `otpauth://totp/${label}?secret=${encodeURIComponent(secret)}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`;
    return json({ secret, otpauthUri, expiresAt });
}

async function enableAccountTwoFactor(request, env) {
    const auth = await requireUser(request, env);
    if ('response' in auth) return auth.response;
    await enforceRateLimit(request, env, '2fa-enable', 12, 1000 * 60 * 10, auth.user.id);
    const body = await readJson(request);
    const code = String(body.code ?? '').trim();
    const setup = await env.DB.prepare(`SELECT * FROM account_totp_setups WHERE user_id = ? LIMIT 1`)
        .bind(auth.user.id)
        .first();
    if (!setup || Number(setup.expires_at) <= Date.now()) return fail('2FA setup expired. Start again.', 410);
    if (!await verifyTotp(setup.secret, code)) return fail('That authenticator code is not correct.', 401);

    const now = Date.now();
    await env.DB.prepare(`UPDATE users SET totp_secret = ?, totp_enabled = 1, updated_at = ? WHERE id = ?`)
        .bind(setup.secret, now, auth.user.id)
        .run();
    await env.DB.prepare(`DELETE FROM account_totp_setups WHERE user_id = ?`).bind(auth.user.id).run();
    const recoveryCodes = await replaceRecoveryCodes(env, auth.user.id);
    const fresh = await env.DB.prepare(`SELECT * FROM users WHERE id = ? LIMIT 1`).bind(auth.user.id).first();
    return json({ security: await accountSecurityStatus(env, fresh), recoveryCodes });
}

async function disableAccountTwoFactor(request, env) {
    const auth = await requireUser(request, env);
    if ('response' in auth) return auth.response;
    const fresh = await env.DB.prepare(`SELECT * FROM users WHERE id = ? LIMIT 1`).bind(auth.user.id).first();
    if (!fresh?.totp_enabled || !fresh.totp_secret) return fail('Two-factor authentication is not enabled.', 409);
    await enforceRateLimit(request, env, '2fa-disable', 10, 1000 * 60 * 10, auth.user.id);
    const body = await readJson(request);
    if (!await verifyTotp(fresh.totp_secret, body.code)) return fail('That authenticator code is not correct.', 401);
    await env.DB.prepare(`UPDATE users SET totp_secret = NULL, totp_enabled = 0, updated_at = ? WHERE id = ?`)
        .bind(Date.now(), auth.user.id)
        .run();
    await env.DB.prepare(`DELETE FROM account_recovery_codes WHERE user_id = ?`).bind(auth.user.id).run();
    await env.DB.prepare(`DELETE FROM account_totp_setups WHERE user_id = ?`).bind(auth.user.id).run();
    const updated = await env.DB.prepare(`SELECT * FROM users WHERE id = ? LIMIT 1`).bind(auth.user.id).first();
    return json(await accountSecurityStatus(env, updated));
}

async function regenerateAccountRecoveryCodes(request, env) {
    const auth = await requireUser(request, env);
    if ('response' in auth) return auth.response;
    const fresh = await env.DB.prepare(`SELECT * FROM users WHERE id = ? LIMIT 1`).bind(auth.user.id).first();
    if (!fresh?.totp_enabled || !fresh.totp_secret) return fail('Two-factor authentication is not enabled.', 409);
    await enforceRateLimit(request, env, '2fa-recovery', 6, 1000 * 60 * 60, auth.user.id);
    const body = await readJson(request);
    if (!await verifyTotp(fresh.totp_secret, body.code)) return fail('That authenticator code is not correct.', 401);
    const recoveryCodes = await replaceRecoveryCodes(env, auth.user.id);
    return json({ security: await accountSecurityStatus(env, fresh), recoveryCodes });
}


function directPair(left, right) {
    return String(left) < String(right) ? [String(left), String(right)] : [String(right), String(left)];
}

function directPerson(user) {
    return {
        id: user.id,
        publicUserId: user.public_user_id ?? '',
        username: user.username,
        displayName: user.display_name,
        initials: String(user.display_name ?? user.username ?? '?').trim().slice(0, 1).toUpperCase() || '?',
        avatarUrl: user.avatar_url ?? null,
        profileAccent: normalizeHexColor(user.profile_accent),
        platformRole: clientPlatformRole(user.platform_role),
    };
}

async function directConversationForUser(env, conversationId, userId) {
    return env.DB.prepare(`SELECT * FROM direct_conversations
      WHERE id = ? AND (user_low_id = ? OR user_high_id = ?) LIMIT 1`)
        .bind(conversationId, userId, userId)
        .first();
}

async function directConversationPayload(env, row, currentUserId) {
    const otherUserId = row.user_low_id === currentUserId ? row.user_high_id : row.user_low_id;
    const other = await env.DB.prepare(`SELECT * FROM users WHERE id = ? LIMIT 1`).bind(otherUserId).first();
    if (!other) return null;
    const last = await env.DB.prepare(`SELECT body, created_at FROM direct_messages
      WHERE conversation_id = ? ORDER BY created_at DESC LIMIT 1`).bind(row.id).first();
    return {
        id: row.id,
        status: row.status,
        requestedByMe: row.requested_by === currentUserId,
        sourceWorkspaceId: row.source_space_id ?? null,
        person: directPerson(other),
        createdAt: Number(row.created_at ?? 0),
        updatedAt: Number(row.updated_at ?? 0),
        lastMessage: last?.body ?? null,
        lastMessageAt: last ? Number(last.created_at ?? 0) : null,
    };
}

async function acceptedDirectFriendship(env, leftUserId, rightUserId) {
    const [low, high] = directPair(leftUserId, rightUserId);
    const row = await env.DB.prepare(`SELECT id FROM direct_conversations
      WHERE user_low_id = ? AND user_high_id = ? AND status = 'accepted' LIMIT 1`)
        .bind(low, high)
        .first();
    return Boolean(row);
}

async function directGroupsForUser(env, userId) {
    const result = await env.DB.prepare(`SELECT g.* FROM direct_groups g
      JOIN direct_group_members gm ON gm.group_id = g.id
      WHERE gm.user_id = ?
      ORDER BY g.updated_at DESC LIMIT 100`)
        .bind(userId)
        .all();
    const groups = [];
    for (const row of result.results ?? []) {
        const payload = await directGroupPayload(env, row);
        if (payload) groups.push(payload);
    }
    return groups;
}

async function directGroupForUser(env, groupId, userId) {
    return env.DB.prepare(`SELECT g.* FROM direct_groups g
      JOIN direct_group_members gm ON gm.group_id = g.id
      WHERE g.id = ? AND gm.user_id = ? LIMIT 1`)
        .bind(groupId, userId)
        .first();
}

async function directGroupPayload(env, row) {
    if (!row) return null;
    const membersResult = await env.DB.prepare(`SELECT u.* FROM direct_group_members gm
      JOIN users u ON u.id = gm.user_id
      WHERE gm.group_id = ? ORDER BY gm.joined_at ASC`)
        .bind(row.id)
        .all();
    const members = (membersResult.results ?? []).map(directPerson);
    const last = await env.DB.prepare(`SELECT body, created_at FROM direct_group_messages
      WHERE group_id = ? ORDER BY created_at DESC LIMIT 1`)
        .bind(row.id)
        .first();
    return {
        id: row.id,
        name: row.name,
        ownerUserId: row.owner_user_id,
        members,
        createdAt: Number(row.created_at ?? 0),
        updatedAt: Number(row.updated_at ?? 0),
        lastMessage: last?.body ?? null,
        lastMessageAt: last ? Number(last.created_at ?? 0) : null,
    };
}

async function createDirectGroup(request, env) {
    const auth = await requireUser(request, env);
    if ('response' in auth) return auth.response;
    await enforceRateLimit(request, env, 'direct-group-create', 20, 1000 * 60 * 60 * 24, auth.user.id);
    const body = await readJson(request);
    const name = String(body.name ?? '').trim().slice(0, 48);
    if (name.length < 1) return fail('Enter a group name.');
    const memberUserIds = [...new Set((Array.isArray(body.memberUserIds) ? body.memberUserIds : [])
        .map(value => String(value ?? '').trim())
        .filter(value => value && value !== auth.user.id))];
    if (memberUserIds.length < 1) return fail('Choose at least one friend for the group.');
    if (memberUserIds.length > 9) return fail('Group chats support up to 10 people total during beta.', 400);

    for (const userId of memberUserIds) {
        const target = await env.DB.prepare(`SELECT id FROM users WHERE id = ? LIMIT 1`).bind(userId).first();
        if (!target) return fail('One of those friends could not be found.', 404);
        if (!await acceptedDirectFriendship(env, auth.user.id, userId)) {
            return fail('You can only add people who are already in Your Friends.', 403);
        }
    }

    const id = crypto.randomUUID();
    const now = Date.now();
    try {
        await env.DB.prepare(`INSERT INTO direct_groups (id, name, owner_user_id, created_at, updated_at)
          VALUES (?, ?, ?, ?, ?)`).bind(id, name, auth.user.id, now, now).run();
        await env.DB.prepare(`INSERT INTO direct_group_members (group_id, user_id, joined_at, added_by)
          VALUES (?, ?, ?, ?)`).bind(id, auth.user.id, now, auth.user.id).run();
        for (const userId of memberUserIds) {
            await env.DB.prepare(`INSERT INTO direct_group_members (group_id, user_id, joined_at, added_by)
              VALUES (?, ?, ?, ?)`).bind(id, userId, now, auth.user.id).run();
        }
    } catch (error) {
        console.error('Create direct group failed', error);
        try { await env.DB.prepare(`DELETE FROM direct_group_members WHERE group_id = ?`).bind(id).run(); } catch {}
        try { await env.DB.prepare(`DELETE FROM direct_groups WHERE id = ?`).bind(id).run(); } catch {}
        return fail('Could not create that group chat.', 500);
    }
    const row = await env.DB.prepare(`SELECT * FROM direct_groups WHERE id = ? LIMIT 1`).bind(id).first();
    return json(await directGroupPayload(env, row), 201);
}

async function updateDirectGroup(request, env, groupId) {
    const auth = await requireUser(request, env);
    if ('response' in auth) return auth.response;
    const row = await directGroupForUser(env, groupId, auth.user.id);
    if (!row) return fail('Group chat not found.', 404);
    if (row.owner_user_id !== auth.user.id) return fail('Only the group creator can rename this group during beta.', 403);
    const body = await readJson(request);
    const name = String(body.name ?? '').trim().slice(0, 48);
    if (!name) return fail('Enter a group name.');
    const now = Date.now();
    await env.DB.prepare(`UPDATE direct_groups SET name = ?, updated_at = ? WHERE id = ?`)
        .bind(name, now, groupId)
        .run();
    const updated = await env.DB.prepare(`SELECT * FROM direct_groups WHERE id = ? LIMIT 1`).bind(groupId).first();
    return json(await directGroupPayload(env, updated));
}

async function listDirectGroupMessages(request, env, groupId) {
    const auth = await requireUser(request, env);
    if ('response' in auth) return auth.response;
    const row = await directGroupForUser(env, groupId, auth.user.id);
    if (!row) return fail('Group chat not found.', 404);
    const result = await env.DB.prepare(`SELECT m.id, m.group_id, m.sender_user_id, m.body, m.created_at, u.display_name AS sender_name
      FROM direct_group_messages m JOIN users u ON u.id = m.sender_user_id
      WHERE m.group_id = ? ORDER BY m.created_at ASC LIMIT 500`)
        .bind(groupId)
        .all();
    return json((result.results ?? []).map(message => ({
        id: message.id,
        groupId: message.group_id,
        senderUserId: message.sender_user_id,
        senderName: message.sender_name,
        body: message.body,
        createdAt: Number(message.created_at ?? 0),
    })));
}

async function sendDirectGroupMessage(request, env, groupId) {
    const auth = await requireUser(request, env);
    if ('response' in auth) return auth.response;
    await enforceRateLimit(request, env, 'direct-group-message', 300, 1000 * 60 * 60, auth.user.id);
    const row = await directGroupForUser(env, groupId, auth.user.id);
    if (!row) return fail('Group chat not found.', 404);
    const body = await readJson(request);
    const messageBody = String(body.body ?? '').trim().slice(0, 2000);
    if (!messageBody) return fail('Message cannot be empty.');
    const id = crypto.randomUUID();
    const now = Date.now();
    await env.DB.prepare(`INSERT INTO direct_group_messages (id, group_id, sender_user_id, body, created_at)
      VALUES (?, ?, ?, ?, ?)`).bind(id, groupId, auth.user.id, messageBody, now).run();
    await env.DB.prepare(`UPDATE direct_groups SET updated_at = ? WHERE id = ?`).bind(now, groupId).run();
    return json({ id, groupId, senderUserId: auth.user.id, senderName: auth.user.display_name, body: messageBody, createdAt: now }, 201);
}

async function getDirectCenter(request, env) {
    const auth = await requireUser(request, env);
    if ('response' in auth) return auth.response;
    const result = await env.DB.prepare(`SELECT * FROM direct_conversations
      WHERE user_low_id = ? OR user_high_id = ?
      ORDER BY updated_at DESC LIMIT 200`).bind(auth.user.id, auth.user.id).all();
    const conversations = [];
    const incomingRequests = [];
    const outgoingRequests = [];
    for (const row of result.results ?? []) {
        const item = await directConversationPayload(env, row, auth.user.id);
        if (!item) continue;
        if (item.status === 'accepted') conversations.push(item);
        else if (item.status === 'pending' && item.requestedByMe) outgoingRequests.push(item);
        else if (item.status === 'pending') incomingRequests.push(item);
    }
    const groups = await directGroupsForUser(env, auth.user.id);
    return json({ conversations, incomingRequests, outgoingRequests, groups });
}

async function createDirectRequest(request, env) {
    const auth = await requireUser(request, env);
    if ('response' in auth) return auth.response;
    await enforceRateLimit(request, env, 'direct-request', 40, 1000 * 60 * 60, auth.user.id);
    const body = await readJson(request);
    const sourceWorkspaceId = String(body.sourceWorkspaceId ?? '').trim() || null;
    let target = null;
    if (body.targetUserId) {
        target = await env.DB.prepare(`SELECT * FROM users WHERE id = ? LIMIT 1`).bind(String(body.targetUserId)).first();
    } else {
        const username = normalizeUsername(body.username);
        if (!username) return fail('Enter a username.');
        target = await env.DB.prepare(`SELECT * FROM users WHERE username = ? LIMIT 1`).bind(username).first();
    }
    if (!target) return fail('That Spaces user was not found.', 404);
    if (target.id === auth.user.id) return fail('You cannot add yourself.', 400);

    if (sourceWorkspaceId) {
        const access = await workspaceAccessForUser(env, auth.user.id, sourceWorkspaceId);
        if (!access) return fail('You are not a member of that Space.', 403);
        const targetMember = await env.DB.prepare(`SELECT id FROM space_members WHERE space_id = ? AND user_id = ? LIMIT 1`)
            .bind(sourceWorkspaceId, target.id).first();
        if (!targetMember) return fail('That person is not a member of this Space.', 404);
        const preference = await env.DB.prepare(`SELECT allow_dms FROM account_space_dm_preferences WHERE user_id = ? AND space_id = ? LIMIT 1`)
            .bind(target.id, sourceWorkspaceId).first();
        if (preference && !Boolean(preference.allow_dms)) {
            return fail('This person is not accepting message requests from this Space.', 403);
        }
    }

    const [low, high] = directPair(auth.user.id, target.id);
    const existing = await env.DB.prepare(`SELECT * FROM direct_conversations WHERE user_low_id = ? AND user_high_id = ? LIMIT 1`)
        .bind(low, high).first();
    const now = Date.now();
    if (existing) {
        if (existing.status === 'accepted') return json(await directConversationPayload(env, existing, auth.user.id));
        if (existing.requested_by !== auth.user.id) {
            await env.DB.prepare(`UPDATE direct_conversations SET status = 'accepted', updated_at = ? WHERE id = ?`).bind(now, existing.id).run();
            const accepted = await env.DB.prepare(`SELECT * FROM direct_conversations WHERE id = ? LIMIT 1`).bind(existing.id).first();
            return json(await directConversationPayload(env, accepted, auth.user.id));
        }
        return json(await directConversationPayload(env, existing, auth.user.id));
    }

    const id = crypto.randomUUID();
    await env.DB.prepare(`INSERT INTO direct_conversations
      (id, user_low_id, user_high_id, requested_by, source_space_id, status, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)`)
        .bind(id, low, high, auth.user.id, sourceWorkspaceId, now, now).run();
    const created = await env.DB.prepare(`SELECT * FROM direct_conversations WHERE id = ? LIMIT 1`).bind(id).first();
    return json(await directConversationPayload(env, created, auth.user.id), 201);
}

async function acceptDirectRequest(request, env, conversationId) {
    const auth = await requireUser(request, env);
    if ('response' in auth) return auth.response;
    const row = await directConversationForUser(env, conversationId, auth.user.id);
    if (!row) return fail('Message request not found.', 404);
    if (row.status === 'accepted') return json(await directConversationPayload(env, row, auth.user.id));
    if (row.requested_by === auth.user.id) return fail('The other person must accept this request.', 403);
    await env.DB.prepare(`UPDATE direct_conversations SET status = 'accepted', updated_at = ? WHERE id = ?`).bind(Date.now(), row.id).run();
    const updated = await directConversationForUser(env, row.id, auth.user.id);
    return json(await directConversationPayload(env, updated, auth.user.id));
}

async function declineDirectRequest(request, env, conversationId) {
    const auth = await requireUser(request, env);
    if ('response' in auth) return auth.response;
    const row = await directConversationForUser(env, conversationId, auth.user.id);
    if (!row) return fail('Message request not found.', 404);
    if (row.status === 'accepted') return fail('Accepted conversations cannot be declined here.', 409);
    await env.DB.prepare(`DELETE FROM direct_conversations WHERE id = ?`).bind(row.id).run();
    return new Response(null, { status: 204, headers: corsHeaders() });
}

async function listDirectConversationMessages(request, env, conversationId) {
    const auth = await requireUser(request, env);
    if ('response' in auth) return auth.response;
    const row = await directConversationForUser(env, conversationId, auth.user.id);
    if (!row) return fail('Direct conversation not found.', 404);
    if (row.status !== 'accepted') return fail('Accept the message request before opening the conversation.', 403);
    const result = await env.DB.prepare(`SELECT m.id, m.conversation_id, m.sender_user_id, m.body, m.created_at, u.display_name AS sender_name
      FROM direct_messages m JOIN users u ON u.id = m.sender_user_id
      WHERE m.conversation_id = ? ORDER BY m.created_at ASC LIMIT 500`)
        .bind(conversationId).all();
    return json((result.results ?? []).map(message => ({
        id: message.id,
        conversationId: message.conversation_id,
        senderUserId: message.sender_user_id,
        senderName: message.sender_name,
        body: message.body,
        createdAt: Number(message.created_at ?? 0),
    })));
}

async function sendDirectConversationMessage(request, env, conversationId) {
    const auth = await requireUser(request, env);
    if ('response' in auth) return auth.response;
    await enforceRateLimit(request, env, 'direct-message', 300, 1000 * 60 * 60, auth.user.id);
    const row = await directConversationForUser(env, conversationId, auth.user.id);
    if (!row) return fail('Direct conversation not found.', 404);
    if (row.status !== 'accepted') return fail('Accept the message request before sending direct messages.', 403);
    const body = await readJson(request);
    const messageBody = String(body.body ?? '').trim().slice(0, 2000);
    if (!messageBody) return fail('Message cannot be empty.');
    const id = crypto.randomUUID();
    const now = Date.now();
    await env.DB.prepare(`INSERT INTO direct_messages (id, conversation_id, sender_user_id, body, created_at)
      VALUES (?, ?, ?, ?, ?)`).bind(id, conversationId, auth.user.id, messageBody, now).run();
    await env.DB.prepare(`UPDATE direct_conversations SET updated_at = ? WHERE id = ?`).bind(now, conversationId).run();
    return json({ id, conversationId, senderUserId: auth.user.id, senderName: auth.user.display_name, body: messageBody, createdAt: now }, 201);
}

async function getWorkspaceDmPreference(request, env, workspaceId) {
    const access = await requireWorkspaceMembership(request, env, workspaceId);
    if ('response' in access) return access.response;
    const row = await env.DB.prepare(`SELECT allow_dms, updated_at FROM account_space_dm_preferences WHERE user_id = ? AND space_id = ? LIMIT 1`)
        .bind(access.user.id, workspaceId).first();
    return json({ workspaceId, allowDms: row ? Boolean(row.allow_dms) : true, updatedAt: Number(row?.updated_at ?? 0) });
}

async function updateWorkspaceDmPreference(request, env, workspaceId) {
    const access = await requireWorkspaceMembership(request, env, workspaceId);
    if ('response' in access) return access.response;
    const body = await readJson(request);
    if (typeof body.allowDms !== 'boolean') return fail('allowDms must be true or false.');
    const now = Date.now();
    await env.DB.prepare(`INSERT INTO account_space_dm_preferences (user_id, space_id, allow_dms, updated_at)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(user_id, space_id) DO UPDATE SET allow_dms = excluded.allow_dms, updated_at = excluded.updated_at`)
        .bind(access.user.id, workspaceId, body.allowDms ? 1 : 0, now).run();
    return json({ workspaceId, allowDms: body.allowDms, updatedAt: now });
}

async function setPlatformSupportRole(request, env, userId) {
    const auth = await requireUser(request, env);
    if ('response' in auth) return auth.response;
    if (auth.user.platform_role !== 'creator') return fail('Only the Founder can manage Support access.', 403);
    const body = await readJson(request);
    const role = body.role === 'support' ? 'support' : body.role === null ? null : undefined;
    if (role === undefined) return fail('Platform role must be support or null.');
    if (userId === auth.user.id) return fail('Founder access cannot be changed here.', 400);
    const target = await env.DB.prepare(`SELECT * FROM users WHERE id = ? LIMIT 1`).bind(userId).first();
    if (!target) return fail('Account not found.', 404);
    if (target.platform_role === 'creator') return fail('Founder access cannot be changed.', 403);
    if (target.platform_role === 'staff') return fail('Staff access is managed separately.', 409);
    await env.DB.prepare(`UPDATE users SET platform_role = ?, updated_at = ? WHERE id = ?`)
        .bind(role, Date.now(), userId)
        .run();
    const updated = await env.DB.prepare(`SELECT * FROM users WHERE id = ? LIMIT 1`).bind(userId).first();
    return json(publicProfile(updated));
}

async function getPublicProfile(username, env) {
    const normalized = normalizeUsername(username);
    const user = await env.DB.prepare(`SELECT *
       FROM users
       WHERE username = ?
         AND public_profile = 1
       LIMIT 1`)
        .bind(normalized)
        .first();
    if (!user) {
        return fail('Profile not found.', 404);
    }
    return json(publicProfile(user));
}

function mentionTokenPresent(body, token) {
    const haystack = String(body ?? '').toLowerCase();
    const needle = `@${String(token ?? '').trim().toLowerCase()}`;
    if (needle.length < 2) return false;
    let index = haystack.indexOf(needle);
    while (index >= 0) {
        const before = index === 0 ? '' : haystack[index - 1];
        const after = haystack[index + needle.length] ?? '';
        const beforeOkay = !before || /\s|[([{'".,!?;:]/u.test(before);
        const afterOkay = !after || /\s|[)\]}'".,!?;:]/u.test(after);
        if (beforeOkay && afterOkay) return true;
        index = haystack.indexOf(needle, index + needle.length);
    }
    return false;
}

async function listNotifications(request, env) {
    const auth = await requireUser(request, env);
    if ('response' in auth) return auth.response;
    await ensureHubMembership(env, auth.user.id);

    const url = new URL(request.url);
    const requestedSince = Number(url.searchParams.get('since') ?? 0);
    const since = Math.max(
        Number.isFinite(requestedSince) ? requestedSince : 0,
        Date.now() - 7 * 24 * 60 * 60 * 1000,
    );

    const roleRows = await env.DB.prepare(
        `SELECT sm.space_id, r.name
         FROM space_members sm
         JOIN space_member_roles smr ON smr.member_id = sm.id AND smr.space_id = sm.space_id
         JOIN space_roles r ON r.id = smr.role_id AND r.space_id = sm.space_id
         WHERE sm.user_id = ? AND r.mentionable = 1`
    ).bind(auth.user.id).all();

    const rolesBySpace = new Map();
    for (const row of roleRows.results ?? []) {
        const list = rolesBySpace.get(row.space_id) ?? [];
        list.push(String(row.name ?? ''));
        rolesBySpace.set(row.space_id, list);
    }

    const result = await env.DB.prepare(
        `SELECT
           m.id, m.space_id, m.channel_id, m.author_id, m.body, m.created_at,
           s.name AS workspace_name,
           c.name AS channel_name,
           u.display_name AS author_name,
           CASE
             WHEN author_member.role IN ('owner', 'admin') THEN 1
             WHEN EXISTS (
               SELECT 1
               FROM space_member_roles author_mr
               JOIN space_roles author_role
                 ON author_role.id = author_mr.role_id
                AND author_role.space_id = m.space_id
               WHERE author_mr.space_id = m.space_id
                 AND author_mr.member_id = author_member.id
                 AND author_role.permissions_json LIKE '%"mention_everyone"%'
             ) THEN 1
             ELSE 0
           END AS author_can_mention_everyone
         FROM messages m
         JOIN space_members mine ON mine.space_id = m.space_id AND mine.user_id = ?
         JOIN space_members author_member ON author_member.space_id = m.space_id AND author_member.user_id = m.author_id
         JOIN spaces s ON s.id = m.space_id
         JOIN channels c ON c.id = m.channel_id AND c.space_id = m.space_id
         JOIN users u ON u.id = m.author_id
         WHERE m.created_at > ?
           AND m.author_id <> ?
           AND m.deleted_at IS NULL
         ORDER BY m.created_at DESC
         LIMIT 140`
    ).bind(auth.user.id, since, auth.user.id).all();

    const items = [];
    const accessBySpace = new Map();
    const overwritesBySpace = new Map();

    for (const row of result.results ?? []) {
        if (!accessBySpace.has(row.space_id)) {
            const access = await workspaceAccessForUser(env, auth.user.id, row.space_id);
            accessBySpace.set(row.space_id, access);
            if (access) {
                const allRows = await env.DB.prepare(
                    `SELECT * FROM channel_permission_overwrites WHERE space_id = ?`
                ).bind(row.space_id).all();
                const byChannel = new Map();
                for (const overwrite of allRows.results ?? []) {
                    const list = byChannel.get(overwrite.channel_id) ?? [];
                    list.push(overwrite);
                    byChannel.set(overwrite.channel_id, list);
                }
                overwritesBySpace.set(row.space_id, byChannel);
            }
        }

        const recipientAccess = accessBySpace.get(row.space_id);
        if (!recipientAccess) continue;
        const channelRows = overwritesBySpace.get(row.space_id)?.get(row.channel_id) ?? [];
        if (channelPermissionDecision(recipientAccess, channelRows, 'view_channel') === 'deny') continue;

        const body = String(row.body ?? '');
        const authorCanMentionEveryone = Boolean(row.author_can_mention_everyone);
        let kind = 'message';
        let mentionLabel = 'message';
        if (mentionTokenPresent(body, auth.user.username)) {
            kind = 'mention';
            mentionLabel = `@${auth.user.username}`;
        }
        else if (authorCanMentionEveryone && mentionTokenPresent(body, 'everyone')) {
            kind = 'everyone';
            mentionLabel = '@everyone';
        }
        else if (authorCanMentionEveryone && mentionTokenPresent(body, 'here')) {
            kind = 'here';
            mentionLabel = '@here';
        }
        else {
            const role = (rolesBySpace.get(row.space_id) ?? [])
                .find(name => mentionTokenPresent(body, name));
            if (role) {
                kind = 'role';
                mentionLabel = `@${role}`;
            }
        }
        items.push({
            id: row.id,
            workspaceId: row.space_id,
            workspaceName: row.workspace_name,
            channelId: row.channel_id,
            channelName: row.channel_name,
            authorName: row.author_name,
            preview: body.slice(0, 180),
            createdAt: Number(row.created_at ?? 0),
            kind,
            mentionLabel,
        });
    }

    try {
        const supportRows = await env.DB.prepare(
            `SELECT m.id, m.subject, m.body, m.created_at, sender.display_name AS sender_name
             FROM support_messages m
             JOIN users sender ON sender.id = m.sender_user_id
             WHERE m.recipient_user_id = ? AND m.created_at > ?
             ORDER BY m.created_at DESC LIMIT 80`
        ).bind(auth.user.id, since).all();
        for (const row of supportRows.results ?? []) {
            items.push({
                id: `support-${row.id}`,
                workspaceId: SPACES_HUB_ID,
                workspaceName: 'Spaces Support',
                channelId: 'spaces-hub-updates',
                channelName: 'Support DM',
                authorName: row.sender_name || 'Spaces Support',
                preview: `${row.subject}: ${row.body}`.slice(0, 180),
                createdAt: Number(row.created_at ?? 0),
                kind: 'support',
                mentionLabel: 'Support DM',
            });
        }
    } catch (caught) {
        console.warn('Support DM notifications unavailable.', caught);
    }

    return json(items.sort((a, b) => b.createdAt - a.createdAt));
}

async function listSpaces(request, env) {
    const auth = await requireUser(request, env);
    if ('response' in auth) {
        return auth.response;
    }
    await ensureHubMembership(
        env,
        auth.user.id,
    );
    const result = await env.DB.prepare(`SELECT
         s.id,
         s.name,
         s.code,
         s.avatar_url,
         s.description,
         s.background_preset,
         s.accent_color,
         s.banner_url,
         s.icon_decoration,
         s.created_at,
         s.owner_user_id,
         sm.role
       FROM space_members sm
       JOIN spaces s
         ON s.id = sm.space_id
       WHERE sm.user_id = ?
       ORDER BY
         CASE WHEN s.id = 'spaces-hub' THEN 0 ELSE 1 END,
         s.updated_at DESC`)
        .bind(auth.user.id)
        .all();
    return json(result.results.map(space => ({
        id: space.id,
        name: space.name,
        code: space.code,
        avatarUrl: space.avatar_url,
        description: space.description ?? '',
        background: normalizeBackgroundPreset(space.background_preset),
        accentColor: normalizeHexColor(space.accent_color),
        bannerUrl: space.banner_url ?? null,
        iconDecoration: normalizeIconDecoration(space.icon_decoration),
        initials: space.name
            .split(/\s+/u)
            .filter(Boolean)
            .slice(0, 2)
            .map(part => part
            .slice(0, 1)
            .toUpperCase())
            .join('') || 'S',
        createdAt: space.created_at,
        ownerId: space.owner_user_id,
        role: space.role,
    })));
}

function workspaceInitials(name) {
    return name
        .split(/\s+/u)
        .filter(Boolean)
        .slice(0, 2)
        .map(
            part =>
                part
                    .slice(0, 1)
                    .toUpperCase(),
        )
        .join('') || 'S';
}

function workspaceSummaryFromRow(row) {
    return {
        id:
            row.id,
        name:
            row.name,
        code:
            row.code,
        avatarUrl:
            row.avatar_url ??
            null,
        description:
            row.description ??
            '',
        background:
            normalizeBackgroundPreset(row.background_preset),
        accentColor:
            normalizeHexColor(row.accent_color),
        bannerUrl:
            row.banner_url ?? null,
        iconDecoration:
            normalizeIconDecoration(row.icon_decoration),
        initials:
            workspaceInitials(
                row.name,
            ),
        createdAt:
            row.created_at,
        ownerId:
            row.owner_user_id,
        role:
            row.role,
    };
}

async function uniqueSpaceCode(env) {
    for (
        let attempt = 0;
        attempt < 16;
        attempt += 1
    ) {
        const code =
            randomAlphaNumeric(8)
                .toUpperCase();

        const existing =
            await env.DB.prepare(
                `SELECT id
                 FROM spaces
                 WHERE code = ?
                 LIMIT 1`
            )
                .bind(code)
                .first();

        if (!existing) {
            return code;
        }
    }

    return randomAlphaNumeric(12)
        .toUpperCase();
}

async function uniqueInviteCode(env) {
    for (
        let attempt = 0;
        attempt < 16;
        attempt += 1
    ) {
        const code =
            `INV-${randomAlphaNumeric(10)
                .toUpperCase()}`;

        const existing =
            await env.DB.prepare(
                `SELECT id
                 FROM space_invites
                 WHERE code = ?
                 LIMIT 1`
            )
                .bind(code)
                .first();

        if (!existing) {
            return code;
        }
    }

    return `INV-${randomAlphaNumeric(16)
        .toUpperCase()}`;
}

const CHANNEL_PERMISSION_LEVELS = new Set([
    'viewer',
    'contributor',
    'admin',
    'owner',
    'disabled',
]);

function normalizeChannelPermission(value, fallback = 'contributor') {
    const normalized = String(value ?? fallback);
    return CHANNEL_PERMISSION_LEVELS.has(normalized) ? normalized : fallback;
}

function roleRank(role) {
    switch (role) {
        case 'viewer': return 0;
        case 'contributor': return 1;
        case 'admin': return 2;
        case 'owner': return 3;
        default: return -1;
    }
}

function roleMeetsPermission(role, permission) {
    return permission !== 'disabled' && roleRank(role) >= roleRank(permission);
}

function isGifStoredImage(value) {
    if (!value) return false;
    return /^data:image\/gif;base64,/iu.test(value) || /^https:\/\/[^\s]+\.gif(?:[?#]|$)/iu.test(value);
}

function validStoredImage(value, { allowGif = false } = {}) {
    if (value === null || value === '') return true;
    const remote = /^https:\/\//u.test(value);
    const inlineStatic = /^data:image\/(?:png|jpeg|webp);base64,[A-Za-z0-9+/=]+$/u.test(value);
    const inlineGif = /^data:image\/gif;base64,[A-Za-z0-9+/=]+$/u.test(value);
    if (remote) {
        if (!allowGif && isGifStoredImage(value)) return false;
        return value.length <= 2048;
    }
    if (inlineStatic) return value.length <= MAX_INLINE_IMAGE_DATA_URL_LENGTH;
    if (inlineGif) return allowGif && value.length <= MAX_INLINE_IMAGE_DATA_URL_LENGTH;
    return false;
}

function normalizeChannelName(value) {
    return String(value ?? '')
        .trim()
        .toLowerCase()
        .replace(
            /[^a-z0-9 _-]/gu,
            '',
        )
        .replace(
            /[\s_]+/gu,
            '-',
        )
        .replace(
            /-+/gu,
            '-',
        )
        .replace(
            /^-|-$/gu,
            '',
        )
        .slice(0, 40);
}

async function createWorkspace(
    request,
    env,
) {
    const auth =
        await requireUser(
            request,
            env,
        );

    if ('response' in auth) {
        return auth.response;
    }

    await enforceRateLimit(
        request,
        env,
        'workspace-create',
        10,
        1000 * 60 * 60 * 24,
        auth.user.id,
    );

    const body =
        await readJson(request);

    const name =
        String(
            body.name ??
            '',
        )
            .trim();

    if (
        name.length < 2 ||
        name.length > 64
    ) {
        return fail(
            'Space name must be 2-64 characters.',
        );
    }

    if (
        auth.user.platform_role !==
        'creator'
    ) {
        const owned =
            await env.DB.prepare(
                `SELECT COUNT(*) AS count
                 FROM spaces
                 WHERE owner_user_id = ?
                   AND id <> ?`
            )
                .bind(
                    auth.user.id,
                    SPACES_HUB_ID,
                )
                .first();

        if (
            Number(
                owned?.count ??
                0,
            ) >= 3
        ) {
            return fail(
                'You can own up to 3 Spaces.',
                403,
            );
        }
    }

    const id =
        crypto.randomUUID();

    const code =
        await uniqueSpaceCode(
            env,
        );

    const now =
        Date.now();

    await env.DB.prepare(
        `INSERT INTO spaces
          (
            id,
            name,
            code,
            join_password_salt,
            join_password_hash,
            owner_user_id,
            created_at,
            updated_at
          )
         VALUES (?, ?, ?, 'invite-only-v1', 'invite-only-v1', ?, ?, ?)`
    )
        .bind(
            id,
            name,
            code,
            auth.user.id,
            now,
            now,
        )
        .run();

    const membershipId =
        crypto.randomUUID();

    await env.DB.prepare(
        `INSERT INTO space_members
          (
            id,
            space_id,
            user_id,
            role,
            joined_at
          )
         VALUES (?, ?, ?, 'owner', ?)`
    )
        .bind(
            membershipId,
            id,
            auth.user.id,
            now,
        )
        .run();

    const defaultChannels = [
        {
            id:
                crypto.randomUUID(),
            name:
                'general',
            description:
                'Team conversation.',
            kind:
                'chat',
            postMinRole:
                'contributor',
            noteMinRole:
                'disabled',
            order:
                0,
        },
        {
            id:
                crypto.randomUUID(),
            name:
                'notes',
            description:
                'Shared notes and reference material.',
            kind:
                'notes',
            postMinRole:
                'disabled',
            noteMinRole:
                'contributor',
            order:
                1,
        },
        {
            id:
                crypto.randomUUID(),
            name:
                'announcements',
            description:
                'Owner and Administrator announcements.',
            kind:
                'announcement',
            postMinRole:
                'admin',
            noteMinRole:
                'disabled',
            order:
                2,
        },
    ];

    for (const channel of defaultChannels) {
        await env.DB.prepare(
            `INSERT INTO channels
              (
                id,
                space_id,
                name,
                description,
                kind,
                sort_order,
                post_min_role,
                note_min_role,
                created_at
              )
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
            .bind(
                channel.id,
                id,
                channel.name,
                channel.description,
                channel.kind,
                channel.order,
                channel.postMinRole,
                channel.noteMinRole,
                now,
            )
            .run();
    }

    await env.DB.prepare(
        `INSERT INTO audit_logs
          (
            id,
            space_id,
            actor_id,
            action,
            target_type,
            target_id,
            target_label,
            reason,
            metadata_json,
            created_at
          )
         VALUES (?, ?, ?, 'workspace.created', 'workspace', ?, ?, 'Space created.', '{}', ?)`
    )
        .bind(
            crypto.randomUUID(),
            id,
            auth.user.id,
            id,
            name,
            now,
        )
        .run();

    return json({
        id,
        name,
        code,
        avatarUrl: null,
        description: '',
        background: 'graphite',
        accentColor: '#8b6ca8',
        bannerUrl: null,
        iconDecoration: 'ring',
        initials:
            workspaceInitials(
                name,
            ),
        createdAt:
            now,
        ownerId:
            auth.user.id,
        role:
            'owner',
    }, 201);
}

async function updateWorkspace(
    request,
    env,
    workspaceId,
) {
    const access = await requireWorkspaceMembership(request, env, workspaceId);
    if ('response' in access) return access.response;

    if (!accessHas(access, 'manage_space')) {
        return fail('You do not have permission to edit Space settings.', 403);
    }

    if (workspaceId === SPACES_HUB_ID && access.user.platform_role !== 'creator') {
        return fail('Only the Founder can edit Spaces - Hub.', 403);
    }

    const existing = await env.DB.prepare(
        `SELECT id, name, code, avatar_url, description, background_preset, accent_color, banner_url, icon_decoration, created_at, owner_user_id
         FROM spaces WHERE id = ? LIMIT 1`
    ).bind(workspaceId).first();
    if (!existing) return fail('Space not found.', 404);

    const body = await readJson(request);
    const name = body.name === undefined ? existing.name : String(body.name).trim();
    const description = body.description === undefined
        ? (existing.description ?? '')
        : String(body.description).trim().slice(0, 280);
    const avatarUrl = body.avatarUrl === undefined
        ? (existing.avatar_url ?? null)
        : (body.avatarUrl === null || body.avatarUrl === '' ? null : String(body.avatarUrl));
    const background = body.background === undefined
        ? normalizeBackgroundPreset(existing.background_preset)
        : normalizeBackgroundPreset(String(body.background), 'graphite');
    const accentColor = body.accentColor === undefined
        ? normalizeHexColor(existing.accent_color)
        : normalizeHexColor(body.accentColor);
    const bannerUrl = body.bannerUrl === undefined
        ? (existing.banner_url ?? null)
        : (body.bannerUrl === null || body.bannerUrl === '' ? null : String(body.bannerUrl));
    const bannerChanged = bannerUrl !== (existing.banner_url ?? null);
    const founderOwnsWorkspace =
        access.user.platform_role === 'creator' &&
        (workspaceId === SPACES_HUB_ID || existing.owner_user_id === access.user.id);

    if ((isGifStoredImage(avatarUrl) || isGifStoredImage(bannerUrl)) && !founderOwnsWorkspace) {
        return fail('Animated GIF Space pictures and banners are reserved for Founder-owned Spaces.', 403);
    }
    const iconDecoration = body.iconDecoration === undefined
        ? normalizeIconDecoration(existing.icon_decoration)
        : normalizeIconDecoration(body.iconDecoration);

    if (name.length < 2 || name.length > 64) {
        return fail('Space name must be 2-64 characters.');
    }
    if (!validStoredImage(avatarUrl, { allowGif: founderOwnsWorkspace })) {
        return fail('Space icon must be an HTTPS image or a compressed image.');
    }
    if (!validStoredImage(bannerUrl, { allowGif: founderOwnsWorkspace })) {
        return fail('Space banner must be an HTTPS image or a compressed image.');
    }

    const now = Date.now();
    await env.DB.prepare(
        `UPDATE spaces SET name = ?, description = ?, avatar_url = ?, background_preset = ?, accent_color = ?, banner_url = ?, icon_decoration = ?, updated_at = ? WHERE id = ?`
    ).bind(name, description, avatarUrl, background, accentColor, bannerUrl, iconDecoration, now, workspaceId).run();

    await env.DB.prepare(
        `INSERT INTO audit_logs
          (id, space_id, actor_id, action, target_type, target_id, target_label, reason, metadata_json, created_at)
         VALUES (?, ?, ?, 'settings.changed', 'workspace', ?, ?, 'Space identity updated.', ?, ?)`
    ).bind(
        crypto.randomUUID(), workspaceId, access.user.id, workspaceId, name,
        JSON.stringify({
            descriptionChanged: String(description !== (existing.description ?? '')),
            avatarChanged: String(avatarUrl !== (existing.avatar_url ?? null)),
            backgroundChanged: String(background !== normalizeBackgroundPreset(existing.background_preset)),
            accentChanged: String(accentColor !== normalizeHexColor(existing.accent_color)),
            bannerChanged: String(bannerChanged),
            iconDecorationChanged: String(iconDecoration !== normalizeIconDecoration(existing.icon_decoration)),
        }),
        now,
    ).run();

    return json({
        id: workspaceId,
        name,
        code: existing.code,
        initials: workspaceInitials(name),
        avatarUrl,
        description,
        background,
        accentColor,
        bannerUrl,
        iconDecoration,
        createdAt: existing.created_at,
        ownerId: existing.owner_user_id,
        role: access.role,
    });
}

async function deleteWorkspace(
    request,
    env,
    workspaceId,
) {
    const access =
        await requireWorkspaceMembership(
            request,
            env,
            workspaceId,
        );

    if ('response' in access) {
        return access.response;
    }

    if (
        workspaceId ===
        SPACES_HUB_ID
    ) {
        return fail(
            'Spaces - Hub cannot be deleted.',
            403,
        );
    }

    if (
        access.role !== 'owner'
    ) {
        return fail(
            'Only the Space Owner can delete this Space.',
            403,
        );
    }

    await env.DB.prepare(
        `DELETE FROM spaces
         WHERE id = ?`
    )
        .bind(
            workspaceId,
        )
        .run();

    return new Response(
        null,
        {
            status:
                204,
            headers:
                corsHeaders(),
        },
    );
}

async function listWorkspaceInvites(
    request,
    env,
    workspaceId,
) {
    const access =
        await requireWorkspaceMembership(
            request,
            env,
            workspaceId,
        );

    if ('response' in access) {
        return access.response;
    }

    if (!accessHas(access, 'create_invites')) {
        return fail('You do not have permission to view invites.', 403);
    }

    const result =
        await env.DB.prepare(
            `SELECT
               id,
               space_id,
               code,
               created_by,
               created_at,
               expires_at,
               max_uses,
               uses,
               revoked
             FROM space_invites
             WHERE space_id = ?
             ORDER BY created_at DESC
             LIMIT 100`
        )
            .bind(
                workspaceId,
            )
            .all();

    return json(
        result.results.map(
            invite => ({
                id:
                    invite.id,
                workspaceId:
                    invite.space_id,
                code:
                    invite.code,
                createdBy:
                    invite.created_by,
                createdAt:
                    invite.created_at,
                expiresAt:
                    invite.expires_at,
                maxUses:
                    invite.max_uses,
                uses:
                    invite.uses,
                revoked:
                    Boolean(
                        invite.revoked,
                    ),
            }),
        ),
    );
}

async function createWorkspaceInvite(
    request,
    env,
    workspaceId,
) {
    const access =
        await requireWorkspaceMembership(
            request,
            env,
            workspaceId,
        );

    if ('response' in access) {
        return access.response;
    }

    if (!accessHas(access, 'create_invites')) {
        return fail('You do not have permission to create invites.', 403);
    }

    await enforceRateLimit(
        request,
        env,
        'invite-create',
        30,
        1000 * 60 * 60,
        `${workspaceId}:${access.user.id}`,
    );

    const body =
        await readJson(request);

    if (body.code || body.customCode || body.slug) {
        return fail('Invite codes are generated by Spaces and cannot be customized.');
    }

    const expiresInDays =
        Math.max(
            1,
            Math.min(
                30,
                Number(
                    body.expiresInDays ??
                    7,
                ) ||
                7,
            ),
        );

    const maxUses =
        Math.max(
            1,
            Math.min(
                100,
                Number(
                    body.maxUses ??
                    25,
                ) ||
                25,
            ),
        );

    const now =
        Date.now();

    const invite = {
        id:
            crypto.randomUUID(),
        workspaceId,
        code:
            await uniqueInviteCode(
                env,
            ),
        createdBy:
            access.user.id,
        createdAt:
            now,
        expiresAt:
            now +
            expiresInDays *
            86_400_000,
        maxUses,
        uses:
            0,
        revoked:
            false,
    };

    await env.DB.prepare(
        `INSERT INTO space_invites
          (
            id,
            space_id,
            code,
            created_by,
            created_at,
            expires_at,
            max_uses,
            uses,
            revoked
          )
         VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0)`
    )
        .bind(
            invite.id,
            invite.workspaceId,
            invite.code,
            invite.createdBy,
            invite.createdAt,
            invite.expiresAt,
            invite.maxUses,
        )
        .run();

    return json(
        invite,
        201,
    );
}

async function revokeWorkspaceInvite(
    request,
    env,
    workspaceId,
    inviteId,
) {
    const access =
        await requireWorkspaceMembership(
            request,
            env,
            workspaceId,
        );

    if ('response' in access) {
        return access.response;
    }

    if (!accessHas(access, 'create_invites')) {
        return fail('You do not have permission to revoke invites.', 403);
    }

    await env.DB.prepare(
        `UPDATE space_invites
         SET revoked = 1
         WHERE id = ?
           AND space_id = ?`
    )
        .bind(
            inviteId,
            workspaceId,
        )
        .run();

    return new Response(
        null,
        {
            status:
                204,
            headers:
                corsHeaders(),
        },
    );
}

async function joinWorkspaceInvite(
    request,
    env,
) {
    const auth =
        await requireUser(
            request,
            env,
        );

    if ('response' in auth) {
        return auth.response;
    }

    await enforceRateLimit(
        request,
        env,
        'invite-join',
        30,
        1000 * 60 * 60,
        auth.user.id,
    );

    const body =
        await readJson(request);

    const code =
        String(
            body.code ??
            '',
        )
            .trim()
            .toUpperCase();

    if (
        code.length < 6 ||
        code.length > 32
    ) {
        return fail(
            'Invalid invite code.',
        );
    }

    const now =
        Date.now();

    const invite =
        await env.DB.prepare(
            `SELECT
               i.*,
               s.name,
               s.code AS space_code,
               s.avatar_url AS space_avatar_url,
               s.description AS space_description,
               s.background_preset AS space_background_preset,
               s.accent_color AS space_accent_color,
               s.banner_url AS space_banner_url,
               s.icon_decoration AS space_icon_decoration,
               s.created_at AS space_created_at,
               s.owner_user_id
             FROM space_invites i
             JOIN spaces s
               ON s.id = i.space_id
             WHERE i.code = ?
             LIMIT 1`
        )
            .bind(
                code,
            )
            .first();

    if (
        !invite ||
        invite.revoked ||
        (
            invite.expires_at &&
            invite.expires_at <=
                now
        ) ||
        (
            invite.max_uses &&
            invite.uses >=
                invite.max_uses
        )
    ) {
        return fail(
            'That invite is invalid or expired.',
            404,
        );
    }

    const existing =
        await env.DB.prepare(
            `SELECT id, role
             FROM space_members
             WHERE space_id = ?
               AND user_id = ?
             LIMIT 1`
        )
            .bind(
                invite.space_id,
                auth.user.id,
            )
            .first();

    if (!existing) {
        await env.DB.prepare(
            `INSERT INTO space_members
              (
                id,
                space_id,
                user_id,
                role,
                joined_at
              )
             VALUES (?, ?, ?, 'viewer', ?)`
        )
            .bind(
                crypto.randomUUID(),
                invite.space_id,
                auth.user.id,
                now,
            )
            .run();

        await env.DB.prepare(
            `UPDATE space_invites
             SET uses = uses + 1
             WHERE id = ?`
        )
            .bind(
                invite.id,
            )
            .run();

        await env.DB.prepare(
            `INSERT INTO audit_logs
              (
                id,
                space_id,
                actor_id,
                action,
                target_type,
                target_id,
                target_label,
                reason,
                metadata_json,
                created_at
              )
             VALUES (?, ?, ?, 'member.joined', 'user', ?, ?, 'Joined with invite.', ?, ?)`
        )
            .bind(
                crypto.randomUUID(),
                invite.space_id,
                auth.user.id,
                auth.user.id,
                auth.user.display_name,
                JSON.stringify({
                    inviteId:
                        invite.id,
                }),
                now,
            )
            .run();
    }

    return json({
        id:
            invite.space_id,
        name:
            invite.name,
        code:
            invite.space_code,
        avatarUrl:
            invite.space_avatar_url ?? null,
        description:
            invite.space_description ?? '',
        background:
            normalizeBackgroundPreset(invite.space_background_preset),
        accentColor:
            normalizeHexColor(invite.space_accent_color),
        bannerUrl:
            invite.space_banner_url ?? null,
        iconDecoration:
            normalizeIconDecoration(invite.space_icon_decoration),
        initials:
            workspaceInitials(
                invite.name,
            ),
        createdAt:
            invite.space_created_at,
        ownerId:
            invite.owner_user_id,
        role:
            existing?.role ??
            'viewer',
    });
}


async function leaveWorkspace(
    request,
    env,
    workspaceId,
) {
    const access =
        await requireWorkspaceMembership(
            request,
            env,
            workspaceId,
        );

    if ('response' in access) {
        return access.response;
    }

    if (
        workspaceId ===
        SPACES_HUB_ID
    ) {
        return fail(
            'Spaces - Hub membership is permanent.',
            403,
        );
    }

    if (
        access.role ===
        'owner'
    ) {
        return fail(
            'The Space Owner must delete the Space instead of leaving it.',
            403,
        );
    }

    const membership =
        await env.DB.prepare(
            `SELECT id
             FROM space_members
             WHERE space_id = ?
               AND user_id = ?
             LIMIT 1`
        )
            .bind(
                workspaceId,
                access.user.id,
            )
            .first();

    if (!membership) {
        return fail(
            'Membership not found.',
            404,
        );
    }

    await env.DB.prepare(
        `DELETE FROM space_members
         WHERE id = ?`
    )
        .bind(
            membership.id,
        )
        .run();

    await env.DB.prepare(
        `INSERT INTO audit_logs
          (
            id,
            space_id,
            actor_id,
            action,
            target_type,
            target_id,
            target_label,
            reason,
            metadata_json,
            created_at
          )
         VALUES (?, ?, ?, 'member.removed', 'user', ?, ?, 'Member left the Space.', '{}', ?)`
    )
        .bind(
            crypto.randomUUID(),
            workspaceId,
            access.user.id,
            access.user.id,
            access.user.display_name,
            Date.now(),
        )
        .run();

    return new Response(
        null,
        {
            status:
                204,
            headers:
                corsHeaders(),
        },
    );
}

async function createWorkspaceChannel(
    request,
    env,
    workspaceId,
) {
    const access =
        await requireWorkspaceMembership(
            request,
            env,
            workspaceId,
        );

    if ('response' in access) {
        return access.response;
    }

    if (!accessHas(access, 'create_channels')) {
        return fail('You do not have permission to create channels.', 403);
    }

    await enforceRateLimit(
        request,
        env,
        'channel-create',
        20,
        1000 * 60 * 60,
        `${workspaceId}:${access.user.id}`,
    );

    const body =
        await readJson(request);

    const name =
        normalizeChannelName(
            body.name,
        );

    const description =
        String(
            body.description ??
            '',
        )
            .trim()
            .slice(
                0,
                140,
            );

    const kind =
        String(
            body.kind ??
            'chat',
        );

    if (
        !name ||
        name.length < 2
    ) {
        return fail(
            'Channel name must be at least 2 characters.',
        );
    }

    if (
        kind !== 'chat' &&
        kind !== 'notes' &&
        kind !== 'mixed' &&
        kind !== 'announcement'
    ) {
        return fail(
            'Invalid channel type.',
        );
    }

    const postMinRole = normalizeChannelPermission(
        body.postMinRole,
        kind === 'announcement' ? 'admin' : kind === 'notes' ? 'disabled' : 'contributor',
    );

    const noteMinRole = normalizeChannelPermission(
        body.noteMinRole,
        kind === 'notes' || kind === 'mixed' ? 'contributor' : 'disabled',
    );

    const count =
        await env.DB.prepare(
            `SELECT COUNT(*) AS count
             FROM channels
             WHERE space_id = ?`
        )
            .bind(
                workspaceId,
            )
            .first();

    if (
        Number(
            count?.count ??
            0,
        ) >= 50
    ) {
        return fail(
            'A Space can have up to 50 channels.',
            403,
        );
    }

    const existing =
        await env.DB.prepare(
            `SELECT id
             FROM channels
             WHERE space_id = ?
               AND name = ?
             LIMIT 1`
        )
            .bind(
                workspaceId,
                name,
            )
            .first();

    if (existing) {
        return fail(
            'A channel with that name already exists.',
            409,
        );
    }

    const orderRow =
        await env.DB.prepare(
            `SELECT COALESCE(MAX(sort_order), -1) AS max_order
             FROM channels
             WHERE space_id = ?`
        )
            .bind(
                workspaceId,
            )
            .first();

    const channel = {
        id:
            crypto.randomUUID(),
        workspaceId,
        name,
        description,
        kind,
        postMinRole,
        noteMinRole,
        order:
            Number(
                orderRow?.max_order ??
                -1,
            ) +
            1,
    };

    const now =
        Date.now();

    await env.DB.prepare(
        `INSERT INTO channels
          (
            id,
            space_id,
            name,
            description,
            kind,
            sort_order,
            post_min_role,
            note_min_role,
            created_at
          )
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
        .bind(
            channel.id,
            workspaceId,
            channel.name,
            channel.description,
            channel.kind,
            channel.order,
            channel.postMinRole,
            channel.noteMinRole,
            now,
        )
        .run();

    await env.DB.prepare(
        `INSERT INTO audit_logs
          (
            id,
            space_id,
            actor_id,
            action,
            target_type,
            target_id,
            target_label,
            reason,
            metadata_json,
            created_at
          )
         VALUES (?, ?, ?, 'channel.created', 'channel', ?, ?, 'Channel created.', ?, ?)`
    )
        .bind(
            crypto.randomUUID(),
            workspaceId,
            access.user.id,
            channel.id,
            channel.name,
            JSON.stringify({
                kind:
                    channel.kind,
            }),
            now,
        )
        .run();

    return json(
        channel,
        201,
    );
}

async function removeWorkspaceMember(
    request,
    env,
    workspaceId,
    memberId,
) {
    const access =
        await requireWorkspaceMembership(
            request,
            env,
            workspaceId,
        );

    if ('response' in access) {
        return access.response;
    }

    if (
        workspaceId ===
        SPACES_HUB_ID
    ) {
        return fail(
            'Spaces - Hub membership is managed by the platform.',
            403,
        );
    }

    if (!accessHas(access, 'manage_members')) {
        return fail('You do not have permission to remove members.', 403);
    }

    const target =
        await env.DB.prepare(
            `SELECT
               sm.id,
               sm.user_id,
               sm.role,
               u.display_name
             FROM space_members sm
             JOIN users u
               ON u.id = sm.user_id
             WHERE sm.id = ?
               AND sm.space_id = ?
             LIMIT 1`
        )
            .bind(
                memberId,
                workspaceId,
            )
            .first();

    if (!target) {
        return fail(
            'Member not found.',
            404,
        );
    }

    if (
        target.role ===
        'owner'
    ) {
        return fail(
            'The Space Owner cannot be removed.',
            403,
        );
    }

    if (
        target.user_id ===
        access.user.id
    ) {
        return fail(
            'Use Leave Space for your own membership.',
            400,
        );
    }

    if (
        access.role ===
        'admin' &&
        target.role ===
        'admin'
    ) {
        return fail(
            'Administrators cannot remove another Administrator.',
            403,
        );
    }

    if (access.role !== 'owner' && access.role !== 'admin' && target.role === 'admin') {
        return fail('Custom member managers cannot remove Administrators.', 403);
    }

    await env.DB.prepare(
        `DELETE FROM space_members
         WHERE id = ?`
    )
        .bind(
            memberId,
        )
        .run();

    await env.DB.prepare(
        `INSERT INTO audit_logs
          (
            id,
            space_id,
            actor_id,
            action,
            target_type,
            target_id,
            target_label,
            reason,
            metadata_json,
            created_at
          )
         VALUES (?, ?, ?, 'member.removed', 'user', ?, ?, 'Member removed.', '{}', ?)`
    )
        .bind(
            crypto.randomUUID(),
            workspaceId,
            access.user.id,
            target.user_id,
            target.display_name,
            Date.now(),
        )
        .run();

    return new Response(
        null,
        {
            status:
                204,
            headers:
                corsHeaders(),
        },
    );
}

function normalizeUpdateChanges(value) {
    if (!Array.isArray(value)) {
        return [];
    }

    return value
        .map(
            item =>
                String(item)
                    .trim()
                    .slice(0, 300),
        )
        .filter(Boolean)
        .slice(0, 24);
}

async function listPlatformUpdates(
    request,
    env,
) {
    const auth =
        await requireUser(
            request,
            env,
        );

    if ('response' in auth) {
        return auth.response;
    }

    const result =
        await env.DB.prepare(
            `SELECT
               version,
               published_at,
               title,
               changes_json
             FROM platform_updates
             ORDER BY published_at DESC, version DESC`
        )
            .all();

    return json(
        result.results.map(
            update => ({
                version:
                    update.version,
                publishedAt:
                    update.published_at,
                title:
                    update.title,
                changes:
                    (() => {
                        try {
                            const parsed =
                                JSON.parse(
                                    update.changes_json,
                                );

                            return Array.isArray(parsed)
                                ? parsed
                                : [];
                        }
                        catch {
                            return [];
                        }
                    })(),
            }),
        ),
    );
}

async function createPlatformUpdate(
    request,
    env,
) {
    const editor =
        await requirePlatformUpdateEditor(
            request,
            env,
        );

    if ('response' in editor) {
        return editor.response;
    }

    const body =
        await readJson(request);

    const version =
        String(
            body.version ??
            '',
        )
            .trim();

    const title =
        String(
            body.title ??
            '',
        )
            .trim();

    const changes =
        normalizeUpdateChanges(
            body.changes,
        );

    if (
        !/^[0-9A-Za-z._-]{1,20}$/u
            .test(version)
    ) {
        return fail(
            'Version must be 1-20 letters, numbers, dots, dashes, or underscores.',
        );
    }

    if (
        !title ||
        title.length >
            100
    ) {
        return fail(
            'Update title must be 1-100 characters.',
        );
    }

    if (
        changes.length ===
        0
    ) {
        return fail(
            'Add at least one update item.',
        );
    }

    const existing =
        await env.DB.prepare(
            `SELECT version
             FROM platform_updates
             WHERE version = ?
             LIMIT 1`
        )
            .bind(
                version,
            )
            .first();

    if (existing) {
        return fail(
            'That version already exists.',
            409,
        );
    }

    const now =
        Date.now();

    await env.DB.prepare(
        `INSERT INTO platform_updates
          (
            version,
            published_at,
            title,
            changes_json,
            created_by,
            updated_at
          )
         VALUES (?, ?, ?, ?, ?, ?)`
    )
        .bind(
            version,
            now,
            title,
            JSON.stringify(
                changes,
            ),
            editor.user.id,
            now,
        )
        .run();

    return json({
        version,
        publishedAt:
            now,
        title,
        changes,
    }, 201);
}

async function updatePlatformUpdate(
    request,
    env,
    version,
) {
    const editor =
        await requirePlatformUpdateEditor(
            request,
            env,
        );

    if ('response' in editor) {
        return editor.response;
    }

    const body =
        await readJson(request);

    const title =
        String(
            body.title ??
            '',
        )
            .trim();

    const changes =
        normalizeUpdateChanges(
            body.changes,
        );

    if (
        !title ||
        title.length >
            100
    ) {
        return fail(
            'Update title must be 1-100 characters.',
        );
    }

    if (
        changes.length ===
        0
    ) {
        return fail(
            'Add at least one update item.',
        );
    }

    const existing =
        await env.DB.prepare(
            `SELECT version, published_at
             FROM platform_updates
             WHERE version = ?
             LIMIT 1`
        )
            .bind(
                version,
            )
            .first();

    if (!existing) {
        return fail(
            'Update not found.',
            404,
        );
    }

    await env.DB.prepare(
        `UPDATE platform_updates
         SET
           title = ?,
           changes_json = ?,
           updated_at = ?
         WHERE version = ?`
    )
        .bind(
            title,
            JSON.stringify(
                changes,
            ),
            Date.now(),
            version,
        )
        .run();

    return json({
        version,
        publishedAt:
            existing.published_at,
        title,
        changes,
    });
}

async function deletePlatformUpdate(
    request,
    env,
    version,
) {
    const editor =
        await requirePlatformUpdateEditor(
            request,
            env,
        );

    if ('response' in editor) {
        return editor.response;
    }

    const result =
        await env.DB.prepare(
            `DELETE FROM platform_updates
             WHERE version = ?`
        )
            .bind(
                version,
            )
            .run();

    if (
        !result.meta
            ?.changes
    ) {
        return fail(
            'Update not found.',
            404,
        );
    }

    return new Response(
        null,
        {
            status:
                204,
            headers:
                corsHeaders(),
        },
    );
}

async function saveWorkspaceNote(
    request,
    env,
    workspaceId,
    noteId,
) {
    const access =
        await requireWorkspaceMembership(
            request,
            env,
            workspaceId,
        );

    if ('response' in access) {
        return access.response;
    }

    await enforceRateLimit(
        request,
        env,
        'note-write',
        30,
        1000 * 60,
        `${workspaceId}:${access.user.id}`,
    );

    const body =
        await readJson(request);

    const channelId =
        String(
            body.channelId ??
            '',
        );

    const title =
        String(
            body.title ??
            '',
        )
            .trim();

    const noteBody =
        String(
            body.body ??
            '',
        );

    const reason =
        String(
            body.reason ??
            '',
        )
            .trim()
            .slice(
                0,
                240,
            );

    if (
        !channelId ||
        !title ||
        title.length >
            160 ||
        noteBody.length >
            50000
    ) {
        return fail(
            'Invalid note content.',
        );
    }

    const channel =
        await env.DB.prepare(
            `SELECT id, note_min_role
             FROM channels
             WHERE id = ?
               AND space_id = ?
             LIMIT 1`
        )
            .bind(
                channelId,
                workspaceId,
            )
            .first();

    if (!channel) {
        return fail(
            'Note channel not found.',
            404,
        );
    }

    const requiredRole = normalizeChannelPermission(channel.note_min_role, 'contributor');
    const targetPermissionRows = await channelPermissionRows(env, workspaceId, channelId);
    const targetAction = noteId ? 'edit_notes' : 'create_notes';
    const targetDecision = channelPermissionDecision(access, targetPermissionRows, targetAction);
    const targetBaseAllowed = requiredRole !== 'disabled' &&
        (roleMeetsPermission(access.role, requiredRole) || accessHas(access, 'edit_notes'));
    const targetAllowed = targetDecision === 'allow' || (targetDecision === 'neutral' && targetBaseAllowed);
    if (!targetAllowed) {
        return fail(
            targetDecision === 'deny' || requiredRole === 'disabled'
                ? `You cannot ${noteId ? 'edit' : 'create'} notes in this channel.`
                : `This channel requires ${requiredRole} access to edit notes.`,
            403,
        );
    }

    let existing = null;

    if (noteId) {
        existing = await env.DB.prepare(
            `SELECT *
             FROM notes
             WHERE id = ?
               AND space_id = ?
             LIMIT 1`
        )
            .bind(noteId, workspaceId)
            .first();

        if (!existing) {
            return fail(
                'Note not found.',
                404,
            );
        }

        const sourceChannel = await env.DB.prepare(
            `SELECT id, note_min_role
             FROM channels
             WHERE id = ?
               AND space_id = ?
             LIMIT 1`
        )
            .bind(existing.channel_id, workspaceId)
            .first();

        if (!sourceChannel) {
            return fail(
                'Original note channel not found.',
                404,
            );
        }

        const sourceRequiredRole = normalizeChannelPermission(
            sourceChannel.note_min_role,
            'contributor',
        );

        const sourcePermissionRows = await channelPermissionRows(env, workspaceId, existing.channel_id);
        const sourceDecision = channelPermissionDecision(access, sourcePermissionRows, 'edit_notes');
        const sourceBaseAllowed = sourceRequiredRole !== 'disabled' &&
            (roleMeetsPermission(access.role, sourceRequiredRole) || accessHas(access, 'edit_notes'));
        const sourceAllowed = sourceDecision === 'allow' || (sourceDecision === 'neutral' && sourceBaseAllowed);
        if (!sourceAllowed) {
            return fail(
                sourceDecision === 'deny' || sourceRequiredRole === 'disabled'
                    ? 'You cannot edit notes in the original channel.'
                    : `The original channel requires ${sourceRequiredRole} access to edit this note.`,
                403,
            );
        }
    }

    const now =
        Date.now();

    if (!noteId) {
        const id =
            crypto.randomUUID();

        await env.DB.prepare(
            `INSERT INTO notes
              (
                id,
                space_id,
                channel_id,
                title,
                body,
                created_by,
                updated_by,
                version,
                created_at,
                updated_at
              )
             VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)`
        )
            .bind(
                id,
                workspaceId,
                channelId,
                title,
                noteBody,
                access.user.id,
                access.user.id,
                now,
                now,
            )
            .run();

        await env.DB.prepare(
            `INSERT INTO note_versions
              (
                id,
                note_id,
                version,
                title,
                body,
                reason,
                edited_by,
                created_at
              )
             VALUES (?, ?, 1, ?, ?, ?, ?, ?)`
        )
            .bind(
                crypto.randomUUID(),
                id,
                title,
                noteBody,
                reason ||
                    'Created note',
                access.user.id,
                now,
            )
            .run();

        await env.DB.prepare(
            `INSERT INTO audit_logs
              (
                id,
                space_id,
                actor_id,
                action,
                target_type,
                target_id,
                target_label,
                reason,
                metadata_json,
                created_at
              )
             VALUES (?, ?, ?, 'note.created', 'note', ?, ?, ?, '{}', ?)`
        )
            .bind(
                crypto.randomUUID(),
                workspaceId,
                access.user.id,
                id,
                title,
                reason ||
                    'Created note',
                now,
            )
            .run();

        return json({
            id,
            workspaceId,
            channelId,
            title,
            body:
                noteBody,
            createdBy:
                access.user.id,
            updatedBy:
                access.user.id,
            version:
                1,
            createdAt:
                now,
            updatedAt:
                now,
        }, 201);
    }

    const nextVersion =
        Number(
            existing.version,
        ) +
        1;

    await env.DB.prepare(
        `UPDATE notes
         SET
           channel_id = ?,
           title = ?,
           body = ?,
           updated_by = ?,
           version = ?,
           updated_at = ?
         WHERE id = ?`
    )
        .bind(
            channelId,
            title,
            noteBody,
            access.user.id,
            nextVersion,
            now,
            noteId,
        )
        .run();

    await env.DB.prepare(
        `INSERT INTO note_versions
          (
            id,
            note_id,
            version,
            title,
            body,
            reason,
            edited_by,
            created_at
          )
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    )
        .bind(
            crypto.randomUUID(),
            noteId,
            nextVersion,
            title,
            noteBody,
            reason ||
                'Updated note',
            access.user.id,
            now,
        )
        .run();

    await env.DB.prepare(
        `INSERT INTO audit_logs
          (
            id,
            space_id,
            actor_id,
            action,
            target_type,
            target_id,
            target_label,
            reason,
            metadata_json,
            created_at
          )
         VALUES (?, ?, ?, 'note.edited', 'note', ?, ?, ?, ?, ?)`
    )
        .bind(
            crypto.randomUUID(),
            workspaceId,
            access.user.id,
            noteId,
            title,
            reason ||
                'Updated note',
            JSON.stringify({
                version:
                    String(
                        nextVersion,
                    ),
            }),
            now,
        )
        .run();

    return json({
        id:
            noteId,
        workspaceId,
        channelId,
        title,
        body:
            noteBody,
        createdBy:
            existing.created_by,
        updatedBy:
            access.user.id,
        version:
            nextVersion,
        createdAt:
            existing.created_at,
        updatedAt:
            now,
    });
}


async function listWorkspaceNoteVersions(
    request,
    env,
    workspaceId,
    noteId,
) {
    const access =
        await requireWorkspaceMembership(
            request,
            env,
            workspaceId,
        );

    if ('response' in access) {
        return access.response;
    }

    const note =
        await env.DB.prepare(
            `SELECT id
             FROM notes
             WHERE id = ?
               AND space_id = ?
             LIMIT 1`
        )
            .bind(
                noteId,
                workspaceId,
            )
            .first();

    if (!note) {
        return fail(
            'Note not found.',
            404,
        );
    }

    const result =
        await env.DB.prepare(
            `SELECT
               nv.id,
               nv.note_id,
               nv.version,
               nv.title,
               nv.body,
               nv.reason,
               nv.edited_by,
               nv.created_at,
               COALESCE(u.display_name, 'Former member') AS editor_name
             FROM note_versions nv
             LEFT JOIN users u
               ON u.id = nv.edited_by
             WHERE nv.note_id = ?
             ORDER BY nv.version DESC`
        )
            .bind(
                noteId,
            )
            .all();

    return json(
        result.results.map(
            version => ({
                id:
                    version.id,
                noteId:
                    version.note_id,
                version:
                    version.version,
                title:
                    version.title,
                body:
                    version.body,
                reason:
                    version.reason,
                editedBy:
                    version.edited_by ??
                    '',
                editorName:
                    version.editor_name,
                createdAt:
                    version.created_at,
            }),
        ),
    );
}

async function deleteWorkspaceNote(
    request,
    env,
    workspaceId,
    noteId,
) {
    const access =
        await requireWorkspaceMembership(
            request,
            env,
            workspaceId,
        );

    if ('response' in access) {
        return access.response;
    }

    const note =
        await env.DB.prepare(
            `SELECT
               n.id,
               n.title,
               n.channel_id,
               c.note_min_role
             FROM notes n
             JOIN channels c
               ON c.id = n.channel_id
              AND c.space_id = n.space_id
             WHERE n.id = ?
               AND n.space_id = ?
             LIMIT 1`
        )
            .bind(
                noteId,
                workspaceId,
            )
            .first();

    if (!note) {
        return fail(
            'Note not found.',
            404,
        );
    }

    const requiredRole = normalizeChannelPermission(
        note.note_min_role,
        'contributor',
    );

    const permissionRows = await channelPermissionRows(env, workspaceId, note.channel_id);
    const deleteDecision = channelPermissionDecision(access, permissionRows, 'delete_notes');
    const baseCanDelete = requiredRole !== 'disabled' &&
        (roleMeetsPermission(access.role, requiredRole) || accessHas(access, 'delete_notes'));
    const canDelete = deleteDecision === 'allow' || (deleteDecision === 'neutral' && baseCanDelete);
    if (!canDelete) {
        return fail(
            deleteDecision === 'deny' || requiredRole === 'disabled'
                ? 'You cannot delete notes in this channel.'
                : `This channel requires ${requiredRole} access to delete notes.`,
            403,
        );
    }

    await env.DB.prepare(
        `DELETE FROM notes
         WHERE id = ?`
    )
        .bind(
            noteId,
        )
        .run();

    await env.DB.prepare(
        `INSERT INTO audit_logs
          (
            id,
            space_id,
            actor_id,
            action,
            target_type,
            target_id,
            target_label,
            reason,
            metadata_json,
            created_at
          )
         VALUES (?, ?, ?, 'note.deleted', 'note', ?, ?, 'Note deleted.', '{}', ?)`
    )
        .bind(
            crypto.randomUUID(),
            workspaceId,
            access.user.id,
            noteId,
            note.title,
            Date.now(),
        )
        .run();

    return new Response(
        null,
        {
            status:
                204,
            headers:
                corsHeaders(),
        },
    );
}

async function deleteWorkspaceChannel(
    request,
    env,
    workspaceId,
    channelId,
) {
    const access = await requireWorkspaceMembership(request, env, workspaceId);
    if ('response' in access) return access.response;
    if (!accessHas(access, 'manage_channels')) {
        return fail('You do not have permission to delete channels.', 403);
    }
    if (workspaceId === SPACES_HUB_ID && access.user.platform_role !== 'creator') {
        return fail('Only the Founder can delete channels in Spaces - Hub.', 403);
    }
    if (workspaceId === SPACES_HUB_ID && channelId === 'spaces-hub-updates') {
        return fail('The Spaces - Hub updates channel is permanent.', 403);
    }

    await enforceRateLimit(
        request,
        env,
        'channel-delete',
        30,
        1000 * 60 * 60,
        `${workspaceId}:${access.user.id}`,
    );

    const channel = await env.DB.prepare(
        `SELECT id, name, kind FROM channels WHERE id = ? AND space_id = ? LIMIT 1`
    ).bind(channelId, workspaceId).first();
    if (!channel) {
        return new Response(null, { status: 204, headers: corsHeaders() });
    }

    const now = Date.now();
    const noteRows = await env.DB.prepare(
        `SELECT id FROM notes WHERE space_id = ? AND channel_id = ?`
    ).bind(workspaceId, channelId).all();
    const noteIds = (noteRows.results ?? []).map(row => row.id).filter(Boolean);

    if (noteIds.length) {
        const placeholders = noteIds.map(() => '?').join(',');
        await env.DB.prepare(`DELETE FROM note_comments WHERE note_id IN (${placeholders})`).bind(...noteIds).run();
        await env.DB.prepare(`DELETE FROM note_versions WHERE note_id IN (${placeholders})`).bind(...noteIds).run();
    }

    await env.DB.batch([
        env.DB.prepare(`DELETE FROM messages WHERE space_id = ? AND channel_id = ?`).bind(workspaceId, channelId),
        env.DB.prepare(`DELETE FROM notes WHERE space_id = ? AND channel_id = ?`).bind(workspaceId, channelId),
        env.DB.prepare(`DELETE FROM channel_permission_overwrites WHERE space_id = ? AND channel_id = ?`).bind(workspaceId, channelId),
        env.DB.prepare(`DELETE FROM channels WHERE id = ? AND space_id = ?`).bind(channelId, workspaceId),
        env.DB.prepare(`UPDATE spaces SET updated_at = ? WHERE id = ?`).bind(now, workspaceId),
    ]);

    await env.DB.prepare(
        `INSERT INTO audit_logs
          (id, space_id, actor_id, action, target_type, target_id, target_label, reason, metadata_json, created_at)
         VALUES (?, ?, ?, 'channel.deleted', 'channel', ?, ?, 'Channel deleted.', ?, ?)`
    ).bind(
        crypto.randomUUID(),
        workspaceId,
        access.user.id,
        channelId,
        channel.name,
        JSON.stringify({ kind: channel.kind }),
        now,
    ).run();

    return new Response(null, { status: 204, headers: corsHeaders() });
}


async function listWorkspaceChannelPermissionOverwrites(request, env, workspaceId, channelId) {
    const access = await requireWorkspaceMembership(request, env, workspaceId);
    if ('response' in access) return access.response;
    if (!accessHas(access, 'manage_channels')) {
        return fail('You do not have permission to view channel overrides.', 403);
    }
    const channel = await env.DB.prepare(
        `SELECT id FROM channels WHERE id = ? AND space_id = ? LIMIT 1`
    ).bind(channelId, workspaceId).first();
    if (!channel) return fail('Channel not found.', 404);
    const result = await env.DB.prepare(
        `SELECT * FROM channel_permission_overwrites
         WHERE space_id = ? AND channel_id = ?
         ORDER BY CASE target_type WHEN 'everyone' THEN 0 WHEN 'role' THEN 1 ELSE 2 END, updated_at DESC`
    ).bind(workspaceId, channelId).all();
    return json((result.results ?? []).map(channelPermissionOverwriteFromRow));
}

async function saveWorkspaceChannelPermissionOverwrite(request, env, workspaceId, channelId) {
    const access = await requireWorkspaceMembership(request, env, workspaceId);
    if ('response' in access) return access.response;
    if (!accessHas(access, 'manage_channels')) {
        return fail('You do not have permission to edit channel overrides.', 403);
    }
    const channel = await env.DB.prepare(
        `SELECT id, name FROM channels WHERE id = ? AND space_id = ? LIMIT 1`
    ).bind(channelId, workspaceId).first();
    if (!channel) return fail('Channel not found.', 404);

    const body = await readJson(request);
    const targetType = String(body.targetType ?? '');
    let targetId = String(body.targetId ?? '').trim();
    if (!['everyone', 'role', 'member'].includes(targetType)) return fail('Invalid permission target.');
    if (targetType === 'everyone') targetId = 'everyone';

    if (targetType === 'role') {
        const role = await env.DB.prepare(
            `SELECT id, position FROM space_roles WHERE id = ? AND space_id = ? LIMIT 1`
        ).bind(targetId, workspaceId).first();
        if (!role) return fail('Role not found.', 404);
        if (!canManageCustomRolePosition(access, role.position)) {
            return fail('You cannot edit channel permissions for a role at or above your highest role.', 403);
        }
    }
    else if (targetType === 'member') {
        const member = await env.DB.prepare(
            `SELECT id, role FROM space_members WHERE id = ? AND space_id = ? LIMIT 1`
        ).bind(targetId, workspaceId).first();
        if (!member) return fail('Member not found.', 404);
        if (member.role === 'owner' && access.role !== 'owner') {
            return fail('Only the Owner can edit Owner-targeted permissions.', 403);
        }
    }

    const allow = normalizeChannelPermissionActions(body.allow);
    const deny = normalizeChannelPermissionActions(body.deny).filter(item => !allow.includes(item));
    const existing = await env.DB.prepare(
        `SELECT id, created_at FROM channel_permission_overwrites
         WHERE channel_id = ? AND target_type = ? AND target_id = ? LIMIT 1`
    ).bind(channelId, targetType, targetId).first();
    const now = Date.now();
    const id = existing?.id ?? crypto.randomUUID();
    const createdAt = Number(existing?.created_at ?? now);

    await env.DB.prepare(
        `INSERT INTO channel_permission_overwrites
          (id, space_id, channel_id, target_type, target_id, allow_json, deny_json, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(channel_id, target_type, target_id)
         DO UPDATE SET allow_json = excluded.allow_json, deny_json = excluded.deny_json, updated_at = excluded.updated_at`
    ).bind(id, workspaceId, channelId, targetType, targetId, JSON.stringify(allow), JSON.stringify(deny), createdAt, now).run();

    await env.DB.prepare(
        `INSERT INTO audit_logs
          (id, space_id, actor_id, action, target_type, target_id, target_label, reason, metadata_json, created_at)
         VALUES (?, ?, ?, 'settings.changed', 'channel', ?, ?, 'Channel permission override updated.', ?, ?)`
    ).bind(
        crypto.randomUUID(), workspaceId, access.user.id, channelId, channel.name,
        JSON.stringify({ targetType, targetId, allow, deny }), now,
    ).run();

    return json({ id, workspaceId, channelId, targetType, targetId, allow, deny, createdAt, updatedAt: now });
}

async function deleteWorkspaceChannelPermissionOverwrite(request, env, workspaceId, channelId, targetType, targetId) {
    const access = await requireWorkspaceMembership(request, env, workspaceId);
    if ('response' in access) return access.response;
    if (!accessHas(access, 'manage_channels')) return fail('You do not have permission to edit channel overrides.', 403);
    const normalizedType = String(targetType ?? '');
    const normalizedId = normalizedType === 'everyone' ? 'everyone' : String(targetId ?? '');
    await env.DB.prepare(
        `DELETE FROM channel_permission_overwrites
         WHERE space_id = ? AND channel_id = ? AND target_type = ? AND target_id = ?`
    ).bind(workspaceId, channelId, normalizedType, normalizedId).run();
    return new Response(null, { status: 204, headers: corsHeaders() });
}

async function updateWorkspaceChannelPermissions(
    request,
    env,
    workspaceId,
    channelId,
) {
    const access = await requireWorkspaceMembership(request, env, workspaceId);
    if ('response' in access) return access.response;
    if (!accessHas(access, 'manage_channels')) {
        return fail('You do not have permission to edit channel permissions.', 403);
    }

    await enforceRateLimit(
        request,
        env,
        'channel-permissions',
        60,
        1000 * 60 * 60,
        `${workspaceId}:${access.user.id}`,
    );

    const channel = await env.DB.prepare(
        `SELECT * FROM channels WHERE id = ? AND space_id = ? LIMIT 1`
    ).bind(channelId, workspaceId).first();
    if (!channel) return fail('Channel not found.', 404);

    const body = await readJson(request);
    let postMinRole = normalizeChannelPermission(body.postMinRole, channel.post_min_role ?? 'contributor');
    let noteMinRole = normalizeChannelPermission(body.noteMinRole, channel.note_min_role ?? 'contributor');
    if (channel.kind === 'notes') postMinRole = 'disabled';
    if (channel.kind === 'chat' || channel.kind === 'announcement') noteMinRole = 'disabled';

    await env.DB.prepare(
        `UPDATE channels SET post_min_role = ?, note_min_role = ? WHERE id = ? AND space_id = ?`
    ).bind(postMinRole, noteMinRole, channelId, workspaceId).run();
    const now = Date.now();
    await env.DB.prepare(`UPDATE spaces SET updated_at = ? WHERE id = ?`).bind(now, workspaceId).run();
    await env.DB.prepare(
        `INSERT INTO audit_logs
          (id, space_id, actor_id, action, target_type, target_id, target_label, reason, metadata_json, created_at)
         VALUES (?, ?, ?, 'settings.changed', 'channel', ?, ?, 'Channel permissions updated.', ?, ?)`
    ).bind(
        crypto.randomUUID(), workspaceId, access.user.id, channelId, channel.name,
        JSON.stringify({ postMinRole, noteMinRole }), now,
    ).run();

    return json({
        id: channel.id,
        workspaceId: channel.space_id,
        name: channel.name,
        description: channel.description,
        kind: channel.kind,
        order: channel.sort_order,
        postMinRole,
        noteMinRole,
    });
}

async function sendWorkspaceMessage(
    request,
    env,
    workspaceId,
    channelId,
) {
    const access = await requireWorkspaceMembership(request, env, workspaceId);
    if ('response' in access) return access.response;

    await enforceRateLimit(
        request, env, 'chat-send', 45, 1000 * 60,
        `${workspaceId}:${access.user.id}`,
    );

    const channel = await env.DB.prepare(
        `SELECT id, kind, post_min_role
         FROM channels
         WHERE id = ? AND space_id = ?
         LIMIT 1`
    ).bind(channelId, workspaceId).first();

    if (!channel) return fail('Channel not found.', 404);

    const requiredRole = normalizeChannelPermission(
        channel.post_min_role,
        channel.kind === 'announcement' ? 'admin' : 'contributor',
    );
    const permissionRows = await channelPermissionRows(env, workspaceId, channelId);
    const sendDecision = channelPermissionDecision(access, permissionRows, 'send_messages');
    const baseCanSend = requiredRole !== 'disabled' &&
        (roleMeetsPermission(access.role, requiredRole) || accessHas(access, 'send_messages'));
    const canSend = sendDecision === 'allow' || (sendDecision === 'neutral' && baseCanSend);
    if (!canSend) {
        return fail(
            sendDecision === 'deny' || requiredRole === 'disabled'
                ? 'You cannot send messages in this channel.'
                : `This channel requires ${requiredRole} access to post.`,
            403,
        );
    }

    const body = await readJson(request);
    const messageBody = String(body.body ?? '').trim();
    const attachment = parseChatAttachment(body.attachment);
    if (attachment) {
        const attachDecision = channelPermissionDecision(access, permissionRows, 'attach_files');
        const baseCanAttach = accessHas(access, 'attach_files');
        const canAttach = attachDecision === 'allow' || (attachDecision === 'neutral' && baseCanAttach);
        if (!canAttach) return fail('You cannot attach files in this channel.', 403);
    }

    if (messageBody.length > 2000 || (!messageBody && !attachment)) {
        return fail('Message must contain text or one small attachment (text up to 2000 characters).');
    }

    const id = crypto.randomUUID();
    const now = Date.now();

    await env.DB.prepare(
        `INSERT INTO messages
          (id, space_id, channel_id, author_id, body, created_at, edited_at,
           deleted_at, deleted_by, attachment_name, attachment_type, attachment_size, attachment_data)
         VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, NULL, ?, ?, ?, ?)`
    ).bind(
        id, workspaceId, channelId, access.user.id, messageBody, now,
        attachment?.name ?? null,
        attachment?.type ?? null,
        attachment?.size ?? null,
        attachment?.dataUrl ?? null,
    ).run();

    return json({
        id,
        workspaceId,
        channelId,
        authorId: access.user.id,
        authorName: access.user.display_name,
        authorInitials: (access.user.display_name || access.user.username || 'S').slice(0, 1).toUpperCase(),
        body: messageBody,
        createdAt: now,
        editedAt: null,
        deletedAt: null,
        deletedBy: null,
        attachment: attachment ? {
            name: attachment.name, type: attachment.type, size: attachment.size,
            downloadPath: `/v1/workspaces/${encodeURIComponent(workspaceId)}/messages/${encodeURIComponent(id)}/attachment`,
        } : null,
    });
}

async function getWorkspaceMessageAttachment(request, env, workspaceId, messageId) {
    const access = await requireWorkspaceMembership(request, env, workspaceId);
    if ('response' in access) return access.response;

    const message = await env.DB.prepare(
        `SELECT attachment_name, attachment_type, attachment_data, deleted_at
         FROM messages
         WHERE id = ? AND space_id = ?
         LIMIT 1`
    ).bind(messageId, workspaceId).first();

    if (!message || message.deleted_at || !message.attachment_data) {
        return fail('Attachment not found.', 404);
    }

    const prefix = `data:${message.attachment_type};base64,`;
    if (!String(message.attachment_data).startsWith(prefix)) {
        return fail('Attachment data is unavailable.', 500);
    }

    let bytes;
    try {
        bytes = base64ToBytes(String(message.attachment_data).slice(prefix.length));
    } catch {
        return fail('Attachment data is unavailable.', 500);
    }

    return new Response(bytes, {
        status: 200,
        headers: {
            ...corsHeaders(),
            'Content-Type': message.attachment_type || 'application/octet-stream',
            'Content-Length': String(bytes.byteLength),
            'Content-Disposition': `inline; filename="${String(message.attachment_name ?? 'attachment').replace(/[\r\n"]/gu, '_')}"`,
        },
    });
}

async function editWorkspaceMessage(request, env, workspaceId, messageId) {
    const access = await requireWorkspaceMembership(request, env, workspaceId);
    if ('response' in access) return access.response;

    await enforceRateLimit(
        request, env, 'chat-edit', 60, 1000 * 60,
        `${workspaceId}:${access.user.id}`,
    );

    const message = await env.DB.prepare(
        `SELECT m.*, c.name AS channel_name
         FROM messages m
         JOIN channels c ON c.id = m.channel_id
         WHERE m.id = ? AND m.space_id = ?
         LIMIT 1`
    ).bind(messageId, workspaceId).first();

    if (!message) return fail('Message not found.', 404);
    if (message.deleted_at) return fail('That message has already been removed.', 409);
    if (message.author_id !== access.user.id) {
        return fail('You can only edit your own messages.', 403);
    }

    const body = await readJson(request);
    const messageBody = String(body.body ?? '').trim();
    if (messageBody.length > 2000 || (!messageBody && !message.attachment_data)) {
        return fail('Message must contain text or an attachment.');
    }

    const now = Date.now();
    await env.DB.prepare(
        `UPDATE messages SET body = ?, edited_at = ? WHERE id = ? AND space_id = ?`
    ).bind(messageBody, now, messageId, workspaceId).run();

    await env.DB.prepare(
        `INSERT INTO audit_logs
          (id, space_id, actor_id, action, target_type, target_id, target_label, reason, metadata_json, created_at)
         VALUES (?, ?, ?, 'message.edited', 'message', ?, ?, 'Message edited by its author.', '{}', ?)`
    ).bind(
        crypto.randomUUID(), workspaceId, access.user.id, messageId,
        `#${message.channel_name}`, now,
    ).run();

    return json({
        id: message.id,
        workspaceId: message.space_id,
        channelId: message.channel_id,
        authorId: message.author_id,
        authorName: access.user.display_name,
        authorInitials: (access.user.display_name || access.user.username || 'S').slice(0, 1).toUpperCase(),
        body: messageBody,
        createdAt: message.created_at,
        editedAt: now,
        deletedAt: null,
        deletedBy: null,
        attachment: messageAttachmentFromRow(message),
    });
}

async function deleteWorkspaceMessage(request, env, workspaceId, messageId) {
    const access = await requireWorkspaceMembership(request, env, workspaceId);
    if ('response' in access) return access.response;

    await enforceRateLimit(
        request, env, 'chat-delete', 90, 1000 * 60,
        `${workspaceId}:${access.user.id}`,
    );

    const message = await env.DB.prepare(
        `SELECT m.*, c.name AS channel_name
         FROM messages m
         JOIN channels c ON c.id = m.channel_id
         WHERE m.id = ? AND m.space_id = ?
         LIMIT 1`
    ).bind(messageId, workspaceId).first();

    if (!message) return fail('Message not found.', 404);
    if (message.deleted_at) {
        return new Response(null, { status: 204, headers: corsHeaders() });
    }

    const ownMessage = message.author_id === access.user.id;
    const moderatorDelete = accessHas(access, 'moderate_messages');
    if (!ownMessage && !moderatorDelete) {
        return fail('Only the author, an Administrator, or the Owner can remove this message.', 403);
    }

    const now = Date.now();
    await env.DB.prepare(
        `UPDATE messages
         SET body = '', attachment_name = NULL, attachment_type = NULL,
             attachment_size = NULL, attachment_data = NULL,
             deleted_at = ?, deleted_by = ?, edited_at = ?
         WHERE id = ? AND space_id = ?`
    ).bind(now, access.user.id, now, messageId, workspaceId).run();

    await env.DB.prepare(
        `INSERT INTO audit_logs
          (id, space_id, actor_id, action, target_type, target_id, target_label, reason, metadata_json, created_at)
         VALUES (?, ?, ?, 'message.deleted', 'message', ?, ?, ?, ?, ?)`
    ).bind(
        crypto.randomUUID(), workspaceId, access.user.id, messageId,
        `#${message.channel_name}`,
        ownMessage ? 'Message removed by its author.' : 'Message removed by Space moderation.',
        JSON.stringify({ authorId: message.author_id, moderated: String(!ownMessage) }),
        now,
    ).run();

    return new Response(null, { status: 204, headers: corsHeaders() });
}



// SPACES_V44_BASE_ROLE_PRESENTATION
function defaultBaseRoleSettings(role) {
    return {
        role,
        color: role === 'owner' ? '#b58ad8' : '#8b6ca8',
        hoist: role === 'owner',
        mentionable: false,
        updatedAt: 0,
    };
}

function baseRoleSettingFromRow(row, role) {
    const fallback = defaultBaseRoleSettings(role);
    if (!row) return fallback;
    return {
        role,
        color: normalizeHexColor(row.color, fallback.color),
        hoist: Boolean(row.hoist),
        mentionable: Boolean(row.mentionable),
        updatedAt: Number(row.updated_at ?? 0),
    };
}

async function getWorkspaceBaseRoleSettings(request, env, workspaceId) {
    const access = await requireWorkspaceMembership(request, env, workspaceId);
    if ('response' in access) return access.response;

    const result = await env.DB.prepare(
        `SELECT role, color, hoist, mentionable, updated_at
         FROM space_base_role_settings
         WHERE space_id = ?`
    ).bind(workspaceId).all();

    const rows = new Map((result.results ?? []).map(row => [String(row.role), row]));
    return json({
        owner: baseRoleSettingFromRow(rows.get('owner'), 'owner'),
        member: baseRoleSettingFromRow(rows.get('member'), 'member'),
    });
}

async function updateWorkspaceBaseRoleSetting(request, env, workspaceId, role) {
    const access = await requireWorkspaceMembership(request, env, workspaceId);
    if ('response' in access) return access.response;
    if (access.role !== 'owner') return fail('Only the Space owner can change base role presentation.', 403);
    if (role !== 'owner' && role !== 'member') return fail('Base role not found.', 404);

    const body = await readJson(request);
    const existing = await env.DB.prepare(
        `SELECT role, color, hoist, mentionable, updated_at
         FROM space_base_role_settings
         WHERE space_id = ? AND role = ?
         LIMIT 1`
    ).bind(workspaceId, role).first();

    const fallback = baseRoleSettingFromRow(existing, role);
    const color = body.color === undefined ? fallback.color : normalizeHexColor(body.color, fallback.color);
    const hoist = body.hoist === undefined ? fallback.hoist : Boolean(body.hoist);
    const mentionable = body.mentionable === undefined ? fallback.mentionable : Boolean(body.mentionable);
    const now = Date.now();

    await env.DB.prepare(
        `INSERT INTO space_base_role_settings (space_id, role, color, hoist, mentionable, updated_at)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(space_id, role) DO UPDATE SET
           color = excluded.color,
           hoist = excluded.hoist,
           mentionable = excluded.mentionable,
           updated_at = excluded.updated_at`
    ).bind(workspaceId, role, color, hoist ? 1 : 0, mentionable ? 1 : 0, now).run();

    await env.DB.prepare(
        `INSERT INTO audit_logs
          (id, space_id, actor_id, action, target_type, target_id, target_label, reason, metadata_json, created_at)
         VALUES (?, ?, ?, 'settings.changed', 'role', ?, ?, 'Base role presentation updated.', ?, ?)`
    ).bind(
        crypto.randomUUID(),
        workspaceId,
        access.user.id,
        role,
        role === 'owner' ? 'Owner' : 'Member',
        JSON.stringify({ color, hoist: String(hoist), mentionable: String(mentionable) }),
        now,
    ).run();

    return json({ role, color, hoist, mentionable, updatedAt: now });
}

async function createWorkspaceCustomRole(request, env, workspaceId) {
    const access = await requireWorkspaceMembership(request, env, workspaceId);
    if ('response' in access) return access.response;
    if (!accessHas(access, 'manage_roles')) {
        return fail('You do not have permission to manage custom roles.', 403);
    }

    await enforceRateLimit(request, env, 'role-create', 20, 60_000, `${workspaceId}:${access.user.id}`);
    const body = await readJson(request);
    const name = String(body.name ?? '').trim().slice(0, 32);
    const color = normalizeHexColor(body.color);
    const permissions = normalizeCustomPermissions(body.permissions);
    const hoist = body.hoist ? 1 : 0;
    const mentionable = body.mentionable ? 1 : 0;

    if (name.length < 2) return fail('Role name must be 2-32 characters.');
    const protectedPermissions = ['manage_roles', 'manage_members', 'manage_space'];
    if ((access.role !== 'owner' && access.role !== 'admin') &&
        permissions.some(permission => protectedPermissions.includes(permission))) {
        return fail('Only Owners and Administrators can create management roles.', 403);
    }

    const maxRow = await env.DB.prepare(
        `SELECT COALESCE(MAX(position), 0) AS max_position FROM space_roles WHERE space_id = ?`
    ).bind(workspaceId).first();
    const position = hasFullRoleHierarchyAccess(access)
        ? Number(maxRow?.max_position ?? 0) + 1
        : Math.max(0, Number(access.highestCustomRolePosition ?? 0) - 1);
    const id = crypto.randomUUID();
    const now = Date.now();

    try {
        await env.DB.prepare(
            `INSERT INTO space_roles
              (id, space_id, name, color, permissions_json, position, hoist, mentionable, created_by, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        ).bind(id, workspaceId, name, color, JSON.stringify(permissions), position,
            hoist, mentionable, access.user.id, now, now).run();
    }
    catch (caught) {
        if (String(caught).toLowerCase().includes('unique')) return fail('A role with that name already exists.', 409);
        throw caught;
    }

    await env.DB.prepare(
        `INSERT INTO audit_logs
          (id, space_id, actor_id, action, target_type, target_id, target_label, reason, metadata_json, created_at)
         VALUES (?, ?, ?, 'role.created', 'role', ?, ?, 'Custom role created.', ?, ?)`
    ).bind(crypto.randomUUID(), workspaceId, access.user.id, id, name,
        JSON.stringify({ permissions: permissions.join(',') }), now).run();

    return json({ id, workspaceId, name, color, permissions, position,
        hoist: Boolean(hoist), mentionable: Boolean(mentionable), createdAt: now, updatedAt: now }, 201);
}

async function updateWorkspaceCustomRole(request, env, workspaceId, roleId) {
    const access = await requireWorkspaceMembership(request, env, workspaceId);
    if ('response' in access) return access.response;
    if (!accessHas(access, 'manage_roles')) return fail('You do not have permission to manage custom roles.', 403);

    const existing = await env.DB.prepare(
        `SELECT * FROM space_roles WHERE id = ? AND space_id = ? LIMIT 1`
    ).bind(roleId, workspaceId).first();
    if (!existing) return fail('Role not found.', 404);
    if (!canManageCustomRolePosition(access, existing.position)) {
        return fail('You can only manage roles below your highest role.', 403);
    }

    const body = await readJson(request);
    const name = body.name === undefined ? existing.name : String(body.name).trim().slice(0, 32);
    const color = body.color === undefined ? normalizeHexColor(existing.color) : normalizeHexColor(body.color);
    const permissions = body.permissions === undefined ? parsePermissionsJson(existing.permissions_json) : normalizeCustomPermissions(body.permissions);
    const position = body.position === undefined ? Number(existing.position ?? 0) : Math.max(0, Math.min(1000, Math.floor(Number(body.position) || 0)));
    const hoist = body.hoist === undefined ? Number(existing.hoist ?? 0) : (body.hoist ? 1 : 0);
    const mentionable = body.mentionable === undefined ? Number(existing.mentionable ?? 0) : (body.mentionable ? 1 : 0);

    if (name.length < 2) return fail('Role name must be 2-32 characters.');
    const protectedPermissions = ['manage_roles', 'manage_members', 'manage_space'];
    if ((access.role !== 'owner' && access.role !== 'admin') &&
        permissions.some(permission => protectedPermissions.includes(permission))) {
        return fail('Only Owners and Administrators can edit management roles.', 403);
    }
    if (!hasFullRoleHierarchyAccess(access) &&
        position >= Number(access.highestCustomRolePosition ?? -1)) {
        return fail('You cannot move a role to or above your highest role.', 403);
    }

    const now = Date.now();
    try {
        await env.DB.prepare(
            `UPDATE space_roles
             SET name = ?, color = ?, permissions_json = ?, position = ?, hoist = ?, mentionable = ?, updated_at = ?
             WHERE id = ? AND space_id = ?`
        ).bind(name, color, JSON.stringify(permissions), position, hoist, mentionable, now, roleId, workspaceId).run();
    }
    catch (caught) {
        if (String(caught).toLowerCase().includes('unique')) return fail('A role with that name already exists.', 409);
        throw caught;
    }

    await env.DB.prepare(
        `INSERT INTO audit_logs
          (id, space_id, actor_id, action, target_type, target_id, target_label, reason, metadata_json, created_at)
         VALUES (?, ?, ?, 'role.updated', 'role', ?, ?, 'Custom role updated.', ?, ?)`
    ).bind(crypto.randomUUID(), workspaceId, access.user.id, roleId, name,
        JSON.stringify({ permissions: permissions.join(',') }), now).run();

    return json({ id: roleId, workspaceId, name, color, permissions, position,
        hoist: Boolean(hoist), mentionable: Boolean(mentionable), createdAt: existing.created_at, updatedAt: now });
}

async function deleteWorkspaceCustomRole(request, env, workspaceId, roleId) {
    const access = await requireWorkspaceMembership(request, env, workspaceId);
    if ('response' in access) return access.response;
    if (!accessHas(access, 'manage_roles')) return fail('You do not have permission to manage custom roles.', 403);

    const role = await env.DB.prepare(
        `SELECT * FROM space_roles WHERE id = ? AND space_id = ? LIMIT 1`
    ).bind(roleId, workspaceId).first();
    if (!role) return new Response(null, { status: 204, headers: corsHeaders() });
    if (!canManageCustomRolePosition(access, role.position)) {
        return fail('You can only delete roles below your highest role.', 403);
    }
    const permissions = parsePermissionsJson(role.permissions_json);
    if ((access.role !== 'owner' && access.role !== 'admin') &&
        permissions.some(permission => ['manage_roles','manage_members','manage_space'].includes(permission))) {
        return fail('Only Owners and Administrators can delete management roles.', 403);
    }

    await env.DB.prepare(`DELETE FROM space_roles WHERE id = ? AND space_id = ?`).bind(roleId, workspaceId).run();
    const now = Date.now();
    await env.DB.prepare(
        `INSERT INTO audit_logs
          (id, space_id, actor_id, action, target_type, target_id, target_label, reason, metadata_json, created_at)
         VALUES (?, ?, ?, 'role.deleted', 'role', ?, ?, 'Custom role deleted.', '{}', ?)`
    ).bind(crypto.randomUUID(), workspaceId, access.user.id, roleId, role.name, now).run();
    return new Response(null, { status: 204, headers: corsHeaders() });
}

async function setWorkspaceMemberCustomRoles(request, env, workspaceId, memberId) {
    const access = await requireWorkspaceMembership(request, env, workspaceId);
    if ('response' in access) return access.response;
    if (!accessHas(access, 'manage_roles')) return fail('You do not have permission to assign custom roles.', 403);

    const target = await env.DB.prepare(
        `SELECT sm.id, sm.user_id, sm.role, u.display_name
         FROM space_members sm JOIN users u ON u.id = sm.user_id
         WHERE sm.id = ? AND sm.space_id = ? LIMIT 1`
    ).bind(memberId, workspaceId).first();
    if (!target) return fail('Member not found.', 404);
    if (target.role === 'owner' && access.role !== 'owner') return fail('Only the Owner can manage roles on the Owner account.', 403);
    if (!hasFullRoleHierarchyAccess(access) && (target.role === 'admin' || target.role === 'owner')) {
        return fail('Custom role managers cannot modify Administrator or Owner role assignments.', 403);
    }

    if (!hasFullRoleHierarchyAccess(access)) {
        const targetHighest = await env.DB.prepare(
            `SELECT COALESCE(MAX(r.position), -1) AS highest_position
             FROM space_member_roles mr
             JOIN space_roles r ON r.id = mr.role_id
             WHERE mr.space_id = ? AND mr.member_id = ?`
        ).bind(workspaceId, memberId).first();
        if (Number(targetHighest?.highest_position ?? -1) >= Number(access.highestCustomRolePosition ?? -1)) {
            return fail('You cannot manage custom roles for a member at or above your highest role.', 403);
        }
    }

    const body = await readJson(request);
    const requested = [...new Set((Array.isArray(body.roleIds) ? body.roleIds : []).map(value => String(value)))].slice(0, 24);
    let roles = [];
    if (requested.length) {
        const placeholders = requested.map(() => '?').join(',');
        const result = await env.DB.prepare(
            `SELECT * FROM space_roles WHERE space_id = ? AND id IN (${placeholders})`
        ).bind(workspaceId, ...requested).all();
        roles = result.results;
        if (roles.length !== requested.length) return fail('One or more custom roles are invalid.', 400);
    }

    if (!hasFullRoleHierarchyAccess(access) &&
        roles.some(role => Number(role.position ?? -1) >= Number(access.highestCustomRolePosition ?? -1))) {
        return fail('You can only assign roles below your highest role.', 403);
    }

    if (access.role !== 'owner' && access.role !== 'admin') {
        const protectedPermissions = new Set(['manage_roles','manage_members','manage_space']);
        if (roles.some(role => parsePermissionsJson(role.permissions_json).some(permission => protectedPermissions.has(permission)))) {
            return fail('Only Owners and Administrators can assign management roles.', 403);
        }
    }

    const now = Date.now();
    const statements = [
        env.DB.prepare(`DELETE FROM space_member_roles WHERE space_id = ? AND member_id = ?`).bind(workspaceId, memberId),
        ...requested.map(roleId => env.DB.prepare(
            `INSERT INTO space_member_roles (space_id, member_id, role_id, assigned_by, assigned_at) VALUES (?, ?, ?, ?, ?)`
        ).bind(workspaceId, memberId, roleId, access.user.id, now)),
    ];
    await env.DB.batch(statements);

    await env.DB.prepare(
        `INSERT INTO audit_logs
          (id, space_id, actor_id, action, target_type, target_id, target_label, reason, metadata_json, created_at)
         VALUES (?, ?, ?, 'member.custom_roles_changed', 'member', ?, ?, 'Custom roles updated.', ?, ?)`
    ).bind(crypto.randomUUID(), workspaceId, access.user.id, memberId, target.display_name,
        JSON.stringify({ roleIds: requested.join(',') }), now).run();
    return new Response(null, { status: 204, headers: corsHeaders() });
}

async function createWorkspaceEmoji(request, env, workspaceId) {
    const access = await requireWorkspaceMembership(request, env, workspaceId);
    if ('response' in access) return access.response;
    if (!accessHas(access, 'manage_emojis')) return fail('You do not have permission to manage custom emoji.', 403);
    await enforceRateLimit(request, env, 'emoji-create', 30, 60_000, `${workspaceId}:${access.user.id}`);

    const body = await readJson(request);
    const input = parseEmojiInput(body);
    const count = await env.DB.prepare(`SELECT COUNT(*) AS count FROM space_emojis WHERE space_id = ?`).bind(workspaceId).first();
    if (Number(count?.count ?? 0) >= 100) return fail('This Space already has 100 custom emoji.', 409);
    const id = crypto.randomUUID();
    const now = Date.now();
    try {
        await env.DB.prepare(
            `INSERT INTO space_emojis (id, space_id, name, image_type, image_data, created_by, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
        ).bind(id, workspaceId, input.name, input.imageType, input.imageData, access.user.id, now, now).run();
    }
    catch (caught) {
        if (String(caught).toLowerCase().includes('unique')) return fail('An emoji with that name already exists.', 409);
        throw caught;
    }
    await env.DB.prepare(
        `INSERT INTO audit_logs
          (id, space_id, actor_id, action, target_type, target_id, target_label, reason, metadata_json, created_at)
         VALUES (?, ?, ?, 'emoji.created', 'emoji', ?, ?, 'Custom emoji added.', '{}', ?)`
    ).bind(crypto.randomUUID(), workspaceId, access.user.id, id, `:${input.name}:`, now).run();
    return json({ id, workspaceId, name: input.name, imageType: input.imageType, imageData: input.imageData,
        createdBy: access.user.id, createdAt: now, updatedAt: now }, 201);
}

async function deleteWorkspaceEmoji(request, env, workspaceId, emojiId) {
    const access = await requireWorkspaceMembership(request, env, workspaceId);
    if ('response' in access) return access.response;
    if (!accessHas(access, 'manage_emojis')) return fail('You do not have permission to manage custom emoji.', 403);
    const emoji = await env.DB.prepare(`SELECT * FROM space_emojis WHERE id = ? AND space_id = ? LIMIT 1`).bind(emojiId, workspaceId).first();
    if (!emoji) return new Response(null, { status: 204, headers: corsHeaders() });
    await env.DB.prepare(`DELETE FROM space_emojis WHERE id = ? AND space_id = ?`).bind(emojiId, workspaceId).run();
    const now = Date.now();
    await env.DB.prepare(
        `INSERT INTO audit_logs
          (id, space_id, actor_id, action, target_type, target_id, target_label, reason, metadata_json, created_at)
         VALUES (?, ?, ?, 'emoji.deleted', 'emoji', ?, ?, 'Custom emoji removed.', '{}', ?)`
    ).bind(crypto.randomUUID(), workspaceId, access.user.id, emojiId, `:${emoji.name}:`, now).run();
    return new Response(null, { status: 204, headers: corsHeaders() });
}

async function createNoteComment(request, env, workspaceId, noteId) {
    const access = await requireWorkspaceMembership(request, env, workspaceId);
    if ('response' in access) return access.response;
    await enforceRateLimit(request, env, 'comment-create', 45, 60_000, `${workspaceId}:${access.user.id}`);
    const note = await env.DB.prepare(`SELECT id, title FROM notes WHERE id = ? AND space_id = ? LIMIT 1`).bind(noteId, workspaceId).first();
    if (!note) return fail('Post not found.', 404);
    const body = await readJson(request);
    const commentBody = String(body.body ?? '').trim();
    if (!commentBody || commentBody.length > 1000) return fail('Comment must be 1-1000 characters.');
    const id = crypto.randomUUID();
    const now = Date.now();
    await env.DB.prepare(
        `INSERT INTO note_comments (id, space_id, note_id, author_id, body, created_at, edited_at, deleted_at, deleted_by)
         VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, NULL)`
    ).bind(id, workspaceId, noteId, access.user.id, commentBody, now).run();
    await env.DB.prepare(
        `INSERT INTO audit_logs
          (id, space_id, actor_id, action, target_type, target_id, target_label, reason, metadata_json, created_at)
         VALUES (?, ?, ?, 'comment.created', 'comment', ?, ?, 'Comment added to a shared post.', ?, ?)`
    ).bind(crypto.randomUUID(), workspaceId, access.user.id, id, note.title, JSON.stringify({ noteId }), now).run();
    return json({ id, workspaceId, noteId, authorId: access.user.id,
        authorName: access.user.display_name, authorInitials: String(access.user.display_name || access.user.username || 'M').slice(0,1).toUpperCase(),
        authorAvatarUrl: access.user.avatar_url ?? null, body: commentBody, createdAt: now, editedAt: null, deletedAt: null, deletedBy: null }, 201);
}

async function editNoteComment(request, env, workspaceId, commentId) {
    const access = await requireWorkspaceMembership(request, env, workspaceId);
    if ('response' in access) return access.response;
    const comment = await env.DB.prepare(
        `SELECT c.*, n.title AS note_title FROM note_comments c JOIN notes n ON n.id = c.note_id
         WHERE c.id = ? AND c.space_id = ? LIMIT 1`
    ).bind(commentId, workspaceId).first();
    if (!comment) return fail('Comment not found.', 404);
    if (comment.deleted_at) return fail('That comment has already been removed.', 409);
    if (comment.author_id !== access.user.id) return fail('You can only edit your own comments.', 403);
    const body = await readJson(request);
    const commentBody = String(body.body ?? '').trim();
    if (!commentBody || commentBody.length > 1000) return fail('Comment must be 1-1000 characters.');
    const now = Date.now();
    await env.DB.prepare(`UPDATE note_comments SET body = ?, edited_at = ? WHERE id = ?`).bind(commentBody, now, commentId).run();
    await env.DB.prepare(
        `INSERT INTO audit_logs
          (id, space_id, actor_id, action, target_type, target_id, target_label, reason, metadata_json, created_at)
         VALUES (?, ?, ?, 'comment.edited', 'comment', ?, ?, 'Comment edited by its author.', ?, ?)`
    ).bind(crypto.randomUUID(), workspaceId, access.user.id, commentId, comment.note_title, JSON.stringify({ noteId: comment.note_id }), now).run();
    return json({ id: comment.id, workspaceId, noteId: comment.note_id, authorId: comment.author_id,
        authorName: access.user.display_name, authorInitials: String(access.user.display_name || access.user.username || 'M').slice(0,1).toUpperCase(),
        authorAvatarUrl: access.user.avatar_url ?? null, body: commentBody, createdAt: comment.created_at, editedAt: now, deletedAt: null, deletedBy: null });
}

async function deleteNoteComment(request, env, workspaceId, commentId) {
    const access = await requireWorkspaceMembership(request, env, workspaceId);
    if ('response' in access) return access.response;
    const comment = await env.DB.prepare(
        `SELECT c.*, n.title AS note_title, n.created_by AS post_owner_id
         FROM note_comments c JOIN notes n ON n.id = c.note_id
         WHERE c.id = ? AND c.space_id = ? LIMIT 1`
    ).bind(commentId, workspaceId).first();
    if (!comment) return fail('Comment not found.', 404);
    if (comment.deleted_at) return new Response(null, { status: 204, headers: corsHeaders() });
    const own = comment.author_id === access.user.id;
    const postOwner = comment.post_owner_id === access.user.id;
    const moderator = accessHas(access, 'moderate_comments');
    if (!own && !postOwner && !moderator) {
        return fail('Only the comment author, post owner, or a moderator can remove this comment.', 403);
    }
    const now = Date.now();
    await env.DB.prepare(
        `UPDATE note_comments SET body = '', deleted_at = ?, deleted_by = ?, edited_at = ? WHERE id = ?`
    ).bind(now, access.user.id, now, commentId).run();
    await env.DB.prepare(
        `INSERT INTO audit_logs
          (id, space_id, actor_id, action, target_type, target_id, target_label, reason, metadata_json, created_at)
         VALUES (?, ?, ?, 'comment.deleted', 'comment', ?, ?, ?, ?, ?)`
    ).bind(crypto.randomUUID(), workspaceId, access.user.id, commentId, comment.note_title,
        own ? 'Comment removed by its author.' : postOwner ? 'Comment removed by the post owner.' : 'Comment removed by Space moderation.',
        JSON.stringify({ noteId: comment.note_id, authorId: comment.author_id }), now).run();
    return new Response(null, { status: 204, headers: corsHeaders() });
}

async function changeWorkspaceMemberRole(
    request,
    env,
    workspaceId,
    memberId,
) {
    const access =
        await requireWorkspaceMembership(
            request,
            env,
            workspaceId,
        );

    if ('response' in access) {
        return access.response;
    }

    if (!accessHas(access, 'manage_members')) {
        return fail('You do not have permission to manage member roles.', 403);
    }

    const target =
        await env.DB.prepare(
            `SELECT
               sm.id,
               sm.user_id,
               sm.role,
               u.display_name
             FROM space_members sm
             JOIN users u
               ON u.id = sm.user_id
             WHERE sm.id = ?
               AND sm.space_id = ?
             LIMIT 1`
        )
            .bind(
                memberId,
                workspaceId,
            )
            .first();

    if (!target) {
        return fail(
            'Member not found.',
            404,
        );
    }

    if (
        target.user_id ===
        access.user.id
    ) {
        return fail(
            'You cannot change your own Space role.',
            400,
        );
    }

    if (
        target.role ===
        'owner'
    ) {
        return fail(
            'The Space Owner cannot be changed here.',
            400,
        );
    }

    const body =
        await readJson(request);

    const nextRole =
        body.role;

    const ownerAllowed =
        nextRole === 'admin' ||
        nextRole === 'contributor' ||
        nextRole === 'viewer';

    const adminAllowed =
        nextRole === 'contributor' ||
        nextRole === 'viewer';

    if (
        access.role === 'owner'
            ? !ownerAllowed
            : !adminAllowed
    ) {
        return fail(
            'That role change is not allowed.',
            403,
        );
    }

    if (
        access.role === 'admin' &&
        target.role === 'admin'
    ) {
        return fail(
            'Administrators cannot change another Administrator.',
            403,
        );
    }

    if (access.role !== 'owner' && access.role !== 'admin' && target.role === 'admin') {
        return fail('Custom member managers cannot change Administrator roles.', 403);
    }

    await env.DB.prepare(
        `UPDATE space_members
         SET role = ?
         WHERE id = ?`
    )
        .bind(
            nextRole,
            memberId,
        )
        .run();

    await env.DB.prepare(
        `INSERT INTO audit_logs
          (
            id,
            space_id,
            actor_id,
            action,
            target_type,
            target_id,
            target_label,
            reason,
            metadata_json,
            created_at
          )
         VALUES (?, ?, ?, 'member.role_changed', 'member', ?, ?, ?, ?, ?)`
    )
        .bind(
            crypto.randomUUID(),
            workspaceId,
            access.user.id,
            target.user_id,
            target.display_name,
            `Role changed from ${target.role} to ${nextRole}`,
            JSON.stringify({
                previousRole:
                    target.role,
                nextRole,
            }),
            Date.now(),
        )
        .run();

    return new Response(
        null,
        {
            status:
                204,
            headers:
                corsHeaders(),
        },
    );
}

async function createPlatformReport(
    request,
    env,
) {
    const auth =
        await requireUser(
            request,
            env,
        );

    if ('response' in auth) {
        return auth.response;
    }

    await enforceRateLimit(
        request,
        env,
        'report-create',
        5,
        1000 * 60 * 60,
        auth.user.id,
    );

    const body =
        await readJson(request);

    const reportedUserId =
        String(
            body.reportedUserId ??
            '',
        );

    const workspaceId =
        body.workspaceId
            ? String(
                body.workspaceId,
            )
            : null;

    const reason =
        String(
            body.reason ??
            '',
        )
            .trim();

    const details =
        String(
            body.details ??
            '',
        )
            .trim()
            .slice(
                0,
                1200,
            );

    if (
        !reportedUserId ||
        reportedUserId ===
            auth.user.id
    ) {
        return fail(
            'Choose another account to report.',
        );
    }

    if (
        !reason ||
        reason.length >
            120
    ) {
        return fail(
            'A report reason is required.',
        );
    }

    if (workspaceId) {
        const reportContext = await env.DB.prepare(
            `SELECT
               reporter.id AS reporter_membership,
               reported.id AS reported_membership
             FROM space_members reporter
             LEFT JOIN space_members reported
               ON reported.space_id = reporter.space_id
              AND reported.user_id = ?
             WHERE reporter.space_id = ?
               AND reporter.user_id = ?
             LIMIT 1`
        )
            .bind(reportedUserId, workspaceId, auth.user.id)
            .first();

        if (!reportContext?.reporter_membership ||
            !reportContext?.reported_membership) {
            return fail(
                'That report context is not available.',
                403,
            );
        }
    }

    const reported =
        await env.DB.prepare(
            `SELECT
               id,
               username,
               display_name,
               avatar_url,
               bio,
               platform_role
             FROM users
             WHERE id = ?
             LIMIT 1`
        )
            .bind(
                reportedUserId,
            )
            .first();

    if (!reported) {
        return fail(
            'Reported account not found.',
            404,
        );
    }

    const memberships =
        await env.DB.prepare(
            `SELECT
               s.id AS workspace_id,
               s.name AS workspace_name,
               sm.role
             FROM space_members sm
             JOIN spaces s
               ON s.id = sm.space_id
             WHERE sm.user_id = ?
             ORDER BY sm.joined_at DESC`
        )
            .bind(
                reportedUserId,
            )
            .all();

    const messages =
        await env.DB.prepare(
            `SELECT
               m.body,
               m.created_at,
               s.id AS workspace_id,
               s.name AS workspace_name,
               c.name AS channel_name
             FROM messages m
             JOIN spaces s
               ON s.id = m.space_id
             JOIN channels c
               ON c.id = m.channel_id
             WHERE m.author_id = ?
             ORDER BY m.created_at DESC
             LIMIT 100`
        )
            .bind(
                reportedUserId,
            )
            .all();

    const snapshot = {
        reporter: {
            id:
                auth.user.id,
            username:
                auth.user.username,
            displayName:
                auth.user.display_name,
            avatarUrl:
                auth.user.avatar_url,
            bio:
                auth.user.bio,
            platformRole:
                clientPlatformRole(auth.user.platform_role),
        },

        reported: {
            id:
                reported.id,
            username:
                reported.username,
            displayName:
                reported.display_name,
            avatarUrl:
                reported.avatar_url,
            bio:
                reported.bio,
            platformRole:
                clientPlatformRole(reported.platform_role),
        },

        memberships:
            memberships.results.map(
                membership => ({
                    workspaceId:
                        membership.workspace_id,
                    workspaceName:
                        membership.workspace_name,
                    role:
                        membership.role,
                }),
            ),

        messages:
            messages.results.map(
                message => ({
                    workspaceId:
                        message.workspace_id,
                    workspaceName:
                        message.workspace_name,
                    channelName:
                        message.channel_name,
                    body:
                        message.body,
                    createdAt:
                        message.created_at,
                }),
            ),
    };

    const id =
        crypto.randomUUID();

    const now =
        Date.now();

    await env.DB.prepare(
        `INSERT INTO reports
          (
            id,
            reporter_id,
            reported_user_id,
            workspace_id,
            reason,
            details,
            snapshot_json,
            status,
            created_at,
            reviewed_by,
            reviewed_at
          )
         VALUES (?, ?, ?, ?, ?, ?, ?, 'open', ?, NULL, NULL)`
    )
        .bind(
            id,
            auth.user.id,
            reportedUserId,
            workspaceId,
            reason,
            details,
            JSON.stringify(
                snapshot,
            ),
            now,
        )
        .run();

    if (workspaceId) {
        await env.DB.prepare(
            `INSERT INTO audit_logs
              (
                id,
                space_id,
                actor_id,
                action,
                target_type,
                target_id,
                target_label,
                reason,
                metadata_json,
                created_at
              )
             VALUES (?, ?, ?, 'report.created', 'user', ?, ?, ?, '{}', ?)`
        )
            .bind(
                crypto.randomUUID(),
                workspaceId,
                auth.user.id,
                reportedUserId,
                reported.display_name,
                reason,
                now,
            )
            .run();
    }

    return json({
        id,
    }, 201);
}

async function listModerationReports(
    request,
    env,
) {
    const moderator =
        await requirePlatformModerator(
            request,
            env,
        );

    if ('response' in moderator) {
        return moderator.response;
    }

    const now =
        Date.now();

    const result =
        await env.DB.prepare(
            `SELECT
               r.id,
               r.reporter_id,
               r.reported_user_id,
               r.workspace_id,
               r.reason,
               r.details,
               r.snapshot_json,
               r.status,
               r.created_at,
               r.reviewed_by,
               r.reviewed_at,
               u.username AS current_username,
               u.display_name AS current_display_name,
               u.avatar_url AS current_avatar_url,
               u.bio AS current_bio,
               u.platform_role AS current_platform_role,
               EXISTS(
                 SELECT 1
                 FROM platform_bans pb
                 WHERE pb.user_id = r.reported_user_id
                   AND pb.active = 1
                   AND (
                     pb.expires_at IS NULL OR
                     pb.expires_at > ?
                   )
               ) AS is_banned
             FROM reports r
             LEFT JOIN users u
               ON u.id = r.reported_user_id
             ORDER BY
               CASE r.status
                 WHEN 'open' THEN 0
                 WHEN 'reviewed' THEN 1
                 WHEN 'actioned' THEN 2
                 ELSE 3
               END,
               r.created_at DESC
             LIMIT 150`
        )
            .bind(
                now,
            )
            .all();

    return json(
        result.results.map(
            report => {
                let snapshot;

                try {
                    snapshot =
                        JSON.parse(
                            report.snapshot_json,
                        );
                }
                catch {
                    snapshot = {
                        reporter: {
                            id: '',
                            username: '',
                            displayName: '',
                            avatarUrl: null,
                            bio: '',
                            platformRole: null,
                        },
                        reported: {
                            id: '',
                            username: '',
                            displayName: '',
                            avatarUrl: null,
                            bio: '',
                            platformRole: null,
                        },
                        memberships: [],
                        messages: [],
                    };
                }

                if (
                    snapshot.reported &&
                    report.current_username
                ) {
                    snapshot.reported = {
                        ...snapshot.reported,
                        id:
                            report.reported_user_id,
                        username:
                            report.current_username,
                        displayName:
                            report.current_display_name,
                        avatarUrl:
                            report.current_avatar_url,
                        bio:
                            report.current_bio,
                        platformRole:
                            clientPlatformRole(report.current_platform_role),
                    };
                }

                return {
                    id:
                        report.id,
                    reporterId:
                        report.reporter_id,
                    reportedUserId:
                        report.reported_user_id,
                    workspaceId:
                        report.workspace_id,
                    reason:
                        report.reason,
                    details:
                        report.details,
                    status:
                        report.status,
                    createdAt:
                        report.created_at,
                    reviewedAt:
                        report.reviewed_at,
                    reviewedBy:
                        report.reviewed_by,
                    isBanned:
                        Boolean(
                            report.is_banned,
                        ),
                    snapshot,
                };
            },
        ),
    );
}

async function moderateUserIdentity(
    request,
    env,
    userId,
) {
    const moderator =
        await requirePlatformModerator(
            request,
            env,
        );

    if ('response' in moderator) {
        return moderator.response;
    }

    if (
        userId ===
        moderator.user.id
    ) {
        return fail(
            'You cannot use platform moderation on your own account.',
            400,
        );
    }

    const target =
        await env.DB.prepare(
            `SELECT *
             FROM users
             WHERE id = ?
             LIMIT 1`
        )
            .bind(
                userId,
            )
            .first();

    if (!target) {
        return fail(
            'Account not found.',
            404,
        );
    }

    if (
        target.platform_role ===
        'creator'
    ) {
        return fail(
            'The Founder identity cannot be reset.',
            403,
        );
    }

    if (
        moderator.user.platform_role ===
            'staff' &&
        target.platform_role ===
            'staff'
    ) {
        return fail(
            'Staff accounts can only be moderated by the Founder.',
            403,
        );
    }
    if (!supportRoleCanActOn(moderator.user.platform_role, target.platform_role)) {
        return fail('Your Support role cannot moderate that account.', 403);
    }

    const body =
        await readJson(request);

    const randomizeUsername =
        Boolean(
            body.randomizeUsername,
        );

    const randomizeDisplayName =
        Boolean(
            body.randomizeDisplayName,
        );

    const clearAvatar =
        Boolean(
            body.clearAvatar,
        );

    let username =
        randomizeUsername
            ? await uniqueRandomUsername(
                env,
            )
            : normalizeUsername(
                body.username ??
                target.username,
            );

    let displayName =
        randomizeDisplayName
            ? `User ${randomAlphaNumeric(4)
                .toUpperCase()}`
            : String(
                body.displayName ??
                target.display_name,
            )
                .trim();

    if (!validNewUsername(username)) {
        return fail(
            'Username must be 4-24 characters using lowercase letters, numbers, or underscore.',
        );
    }

    if (
        reservedUsername(
            username,
        ) &&
        username !==
            target.username
    ) {
        return fail(
            'That username is reserved.',
            409,
        );
    }

    if (
        displayName.length < 1 ||
        displayName.length > 40
    ) {
        return fail(
            'Display name must be 1-40 characters.',
        );
    }

    const existing =
        await env.DB.prepare(
            `SELECT id
             FROM users
             WHERE username = ?
               AND id <> ?
             LIMIT 1`
        )
            .bind(
                username,
                userId,
            )
            .first();

    if (existing) {
        if (randomizeUsername) {
            username =
                await uniqueRandomUsername(
                    env,
                );
        }
        else {
            return fail(
                'That username is already taken.',
                409,
            );
        }
    }

    const now =
        Date.now();

    await env.DB.prepare(
        `UPDATE users
         SET
           username = ?,
           display_name = ?,
           avatar_url = CASE
             WHEN ? = 1 THEN NULL
             ELSE avatar_url
           END,
           updated_at = ?
         WHERE id = ?`
    )
        .bind(
            username,
            displayName,
            clearAvatar
                ? 1
                : 0,
            now,
            userId,
        )
        .run();

    await env.DB.prepare(
        `INSERT INTO platform_moderation_actions
          (
            id,
            moderator_id,
            target_user_id,
            action,
            reason,
            metadata_json,
            created_at
          )
         VALUES (?, ?, ?, 'identity.reset', 'Profile moderation', ?, ?)`
    )
        .bind(
            crypto.randomUUID(),
            moderator.user.id,
            userId,
            JSON.stringify({
                previousUsername:
                    target.username,
                username,
                previousDisplayName:
                    target.display_name,
                displayName,
                clearAvatar,
                randomizeUsername,
                randomizeDisplayName,
            }),
            now,
        )
        .run();

    const updated =
        await env.DB.prepare(
            `SELECT *
             FROM users
             WHERE id = ?
             LIMIT 1`
        )
            .bind(
                userId,
            )
            .first();

    return updated
        ? json(
            publicProfile(
                updated,
            ),
        )
        : fail(
            'Moderation update failed.',
            500,
        );
}

async function updateModerationReportStatus(
    request,
    env,
    reportId,
) {
    const moderator =
        await requirePlatformModerator(
            request,
            env,
        );

    if ('response' in moderator) {
        return moderator.response;
    }

    const body =
        await readJson(request);

    const status =
        body.status;

    if (
        status !== 'reviewed' &&
        status !== 'dismissed'
    ) {
        return fail(
            'Invalid report status.',
        );
    }

    const now =
        Date.now();

    const result =
        await env.DB.prepare(
            `UPDATE reports
             SET
               status = ?,
               reviewed_by = ?,
               reviewed_at = ?
             WHERE id = ?`
        )
            .bind(
                status,
                moderator.user.id,
                now,
                reportId,
            )
            .run();

    if (
        !result.meta
            ?.changes
    ) {
        return fail(
            'Report not found.',
            404,
        );
    }

    return new Response(
        null,
        {
            status:
                204,
            headers:
                corsHeaders(),
        },
    );
}

async function banPlatformUser(
    request,
    env,
    userId,
) {
    const moderator =
        await requirePlatformModerator(
            request,
            env,
        );

    if ('response' in moderator) {
        return moderator.response;
    }

    if (
        userId ===
        moderator.user.id
    ) {
        return fail(
            'You cannot ban your own account.',
            400,
        );
    }

    const target =
        await env.DB.prepare(
            `SELECT
               id,
               display_name,
               platform_role
             FROM users
             WHERE id = ?
             LIMIT 1`
        )
            .bind(
                userId,
            )
            .first();

    if (!target) {
        return fail(
            'Account not found.',
            404,
        );
    }

    if (
        target.platform_role ===
        'creator'
    ) {
        return fail(
            'The Founder cannot be banned.',
            403,
        );
    }

    if (
        moderator.user.platform_role ===
            'staff' &&
        target.platform_role ===
            'staff'
    ) {
        return fail(
            'Staff accounts can only be banned by the Founder.',
            403,
        );
    }
    if (!supportRoleCanActOn(moderator.user.platform_role, target.platform_role)) {
        return fail('Your Support role cannot ban or unban that account.', 403);
    }

    if (
        request.method ===
        'DELETE'
    ) {
        await env.DB.prepare(
            `UPDATE platform_bans
             SET active = 0
             WHERE user_id = ?
               AND active = 1`
        )
            .bind(
                userId,
            )
            .run();

        return new Response(
            null,
            {
                status:
                    204,
                headers:
                    corsHeaders(),
            },
        );
    }

    const body =
        await readJson(request);

    const reason =
        String(
            body.reason ??
            'Platform moderation action',
        )
            .trim()
            .slice(
                0,
                1200,
            );

    const reportId =
        body.reportId
            ? String(
                body.reportId,
            )
            : null;

    const now =
        Date.now();

    await env.DB.prepare(
        `UPDATE platform_bans
         SET active = 0
         WHERE user_id = ?
           AND active = 1`
    )
        .bind(
            userId,
        )
        .run();

    await env.DB.prepare(
        `INSERT INTO platform_bans
          (
            id,
            user_id,
            banned_by,
            reason,
            created_at,
            expires_at,
            active
          )
         VALUES (?, ?, ?, ?, ?, NULL, 1)`
    )
        .bind(
            crypto.randomUUID(),
            userId,
            moderator.user.id,
            reason,
            now,
        )
        .run();

    await env.DB.prepare(
        `DELETE FROM sessions
         WHERE user_id = ?`
    )
        .bind(
            userId,
        )
        .run();

    if (reportId) {
        await env.DB.prepare(
            `UPDATE reports
             SET
               status = 'actioned',
               reviewed_by = ?,
               reviewed_at = ?
             WHERE id = ?`
        )
            .bind(
                moderator.user.id,
                now,
                reportId,
            )
            .run();
    }

    return new Response(
        null,
        {
            status:
                204,
            headers:
                corsHeaders(),
        },
    );
}


async function createSupportCase(request, env) {
    const auth = await requireUser(request, env);
    if ('response' in auth) return auth.response;
    await enforceRateLimit(request, env, 'support-case-create', 12, 1000 * 60 * 60, auth.user.id);
    const body = await readJson(request);
    const kind = body.kind === 'space' ? 'space' : body.kind === 'bug' ? 'bug' : '';
    if (!kind) return fail('Support case type must be bug or space.');
    const subject = String(body.subject ?? '').trim().slice(0, 120);
    const details = String(body.details ?? '').trim().slice(0, 3000);
    const priority = ['low','normal','high','urgent'].includes(body.priority) ? body.priority : 'normal';
    const workspaceId = kind === 'space' && body.workspaceId ? String(body.workspaceId) : null;
    if (subject.length < 3) return fail('Please add a short subject.');
    if (details.length < 3) return fail('Please describe the issue.');
    if (kind === 'space') {
        if (!workspaceId || workspaceId === SPACES_HUB_ID) return fail('Choose a reportable Space.');
        const member = await env.DB.prepare(`SELECT id FROM space_members WHERE space_id = ? AND user_id = ? LIMIT 1`)
            .bind(workspaceId, auth.user.id).first();
        if (!member) return fail('You can only report a Space you belong to.', 403);
    }
    const id = crypto.randomUUID();
    const now = Date.now();
    await env.DB.prepare(`INSERT INTO support_cases
      (id, kind, reporter_id, target_workspace_id, subject, details, status, priority, assigned_to, created_at, updated_at, resolved_at)
      VALUES (?, ?, ?, ?, ?, ?, 'open', ?, NULL, ?, ?, NULL)`)
      .bind(id, kind, auth.user.id, workspaceId, subject, details, priority, now, now).run();
    return getSupportCaseById(env, id);
}

async function getSupportCaseById(env, caseId) {
    const row = await env.DB.prepare(`SELECT
        c.*, reporter.display_name AS reporter_name, reporter.username AS reporter_username,
        s.name AS workspace_name, s.owner_user_id AS workspace_owner_id,
        owner.display_name AS workspace_owner_name,
        assignee.display_name AS assigned_to_name,
        CASE WHEN EXISTS (
          SELECT 1 FROM space_restrictions sr
          WHERE sr.space_id = c.target_workspace_id AND sr.active = 1
            AND (sr.expires_at IS NULL OR sr.expires_at > ?)
        ) THEN 1 ELSE 0 END AS restricted
      FROM support_cases c
      JOIN users reporter ON reporter.id = c.reporter_id
      LEFT JOIN spaces s ON s.id = c.target_workspace_id
      LEFT JOIN users owner ON owner.id = s.owner_user_id
      LEFT JOIN users assignee ON assignee.id = c.assigned_to
      WHERE c.id = ? LIMIT 1`).bind(Date.now(), caseId).first();
    if (!row) return fail('Support case not found.', 404);
    return json({
      id: row.id, kind: row.kind,
      reporterId: row.reporter_id, reporterName: row.reporter_name, reporterUsername: row.reporter_username,
      targetWorkspaceId: row.target_workspace_id ?? null, targetWorkspaceName: row.workspace_name ?? null,
      targetWorkspaceOwnerId: row.workspace_owner_id ?? null, targetWorkspaceOwnerName: row.workspace_owner_name ?? null,
      subject: row.subject, details: row.details, status: row.status, priority: row.priority,
      assignedTo: row.assigned_to ?? null, assignedToName: row.assigned_to_name ?? null,
      restricted: Boolean(row.restricted),
      createdAt: Number(row.created_at), updatedAt: Number(row.updated_at), resolvedAt: row.resolved_at ? Number(row.resolved_at) : null,
    });
}

async function listSupportCases(request, env) {
    const support = await requireSupportConsole(request, env);
    if ('response' in support) return support.response;
    const rows = await env.DB.prepare(`SELECT
        c.*, reporter.display_name AS reporter_name, reporter.username AS reporter_username,
        s.name AS workspace_name, s.owner_user_id AS workspace_owner_id,
        owner.display_name AS workspace_owner_name,
        assignee.display_name AS assigned_to_name,
        CASE WHEN EXISTS (
          SELECT 1 FROM space_restrictions sr
          WHERE sr.space_id = c.target_workspace_id AND sr.active = 1
            AND (sr.expires_at IS NULL OR sr.expires_at > ?)
        ) THEN 1 ELSE 0 END AS restricted
      FROM support_cases c
      JOIN users reporter ON reporter.id = c.reporter_id
      LEFT JOIN spaces s ON s.id = c.target_workspace_id
      LEFT JOIN users owner ON owner.id = s.owner_user_id
      LEFT JOIN users assignee ON assignee.id = c.assigned_to
      ORDER BY CASE c.priority WHEN 'urgent' THEN 0 WHEN 'high' THEN 1 WHEN 'normal' THEN 2 ELSE 3 END,
               CASE c.status WHEN 'open' THEN 0 WHEN 'reviewed' THEN 1 ELSE 2 END,
               c.created_at DESC LIMIT 300`).bind(Date.now()).all();
    return json((rows.results ?? []).map(row => ({
      id: row.id, kind: row.kind,
      reporterId: row.reporter_id, reporterName: row.reporter_name, reporterUsername: row.reporter_username,
      targetWorkspaceId: row.target_workspace_id ?? null, targetWorkspaceName: row.workspace_name ?? null,
      targetWorkspaceOwnerId: row.workspace_owner_id ?? null, targetWorkspaceOwnerName: row.workspace_owner_name ?? null,
      subject: row.subject, details: row.details, status: row.status, priority: row.priority,
      assignedTo: row.assigned_to ?? null, assignedToName: row.assigned_to_name ?? null,
      restricted: Boolean(row.restricted),
      createdAt: Number(row.created_at), updatedAt: Number(row.updated_at), resolvedAt: row.resolved_at ? Number(row.resolved_at) : null,
    })));
}

async function updateSupportCase(request, env, caseId) {
    const support = await requireSupportConsole(request, env);
    if ('response' in support) return support.response;
    const body = await readJson(request);
    const status = body.status;
    const priority = body.priority;
    if (status !== undefined && !['open','reviewed','actioned','resolved','dismissed'].includes(status)) return fail('Invalid support case status.');
    if (priority !== undefined && !['low','normal','high','urgent'].includes(priority)) return fail('Invalid support priority.');
    const existing = await env.DB.prepare(`SELECT * FROM support_cases WHERE id = ? LIMIT 1`).bind(caseId).first();
    if (!existing) return fail('Support case not found.', 404);
    const nextStatus = status ?? existing.status;
    const nextPriority = priority ?? existing.priority;
    const assignedTo = body.assignToMe === true ? support.user.id : body.assignToMe === false ? null : existing.assigned_to;
    const now = Date.now();
    await env.DB.prepare(`UPDATE support_cases SET status = ?, priority = ?, assigned_to = ?, updated_at = ?, resolved_at = ? WHERE id = ?`)
      .bind(nextStatus, nextPriority, assignedTo, now, ['resolved','dismissed','actioned'].includes(nextStatus) ? now : null, caseId).run();
    return getSupportCaseById(env, caseId);
}

async function listSupportMessages(request, env) {
    const support = await requireSupportConsole(request, env);
    if ('response' in support) return support.response;
    const result = await env.DB.prepare(`SELECT m.*, recipient.display_name AS recipient_name, sender.display_name AS sender_name
      FROM support_messages m
      JOIN users recipient ON recipient.id = m.recipient_user_id
      JOIN users sender ON sender.id = m.sender_user_id
      ORDER BY m.created_at DESC LIMIT 300`).all();
    return json((result.results ?? []).map(row => ({
      id: row.id, recipientUserId: row.recipient_user_id, recipientName: row.recipient_name,
      senderUserId: row.sender_user_id, senderName: row.sender_name, caseId: row.case_id ?? null,
      subject: row.subject, body: row.body, createdAt: Number(row.created_at),
    })));
}

async function sendSupportMessage(request, env) {
    const support = await requireSupportConsole(request, env);
    if ('response' in support) return support.response;
    const body = await readJson(request);
    const recipientUserId = String(body.recipientUserId ?? '');
    const subject = String(body.subject ?? '').trim().slice(0, 120);
    const messageBody = String(body.body ?? '').trim().slice(0, 2400);
    const caseId = body.caseId ? String(body.caseId) : null;
    if (!recipientUserId || subject.length < 2 || messageBody.length < 2) return fail('Recipient, subject and message are required.');
    const recipient = await env.DB.prepare(`SELECT id, display_name FROM users WHERE id = ? LIMIT 1`).bind(recipientUserId).first();
    if (!recipient) return fail('Recipient account not found.', 404);
    const id = crypto.randomUUID(); const now = Date.now();
    await env.DB.prepare(`INSERT INTO support_messages (id, recipient_user_id, sender_user_id, case_id, subject, body, created_at, read_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, NULL)`).bind(id, recipientUserId, support.user.id, caseId, subject, messageBody, now).run();
    await env.DB.prepare(`INSERT INTO platform_moderation_actions (id, moderator_id, target_user_id, action, reason, metadata_json, created_at)
      VALUES (?, ?, ?, 'support.dm', ?, ?, ?)`).bind(crypto.randomUUID(), support.user.id, recipientUserId, subject, JSON.stringify({caseId, body: messageBody}), now).run();
    return json({ id, recipientUserId, recipientName: recipient.display_name, senderUserId: support.user.id, senderName: support.user.display_name, caseId, subject, body: messageBody, createdAt: now });
}


async function searchSupportUsers(request, env) {
    const support = await requireSupportConsole(request, env);
    if ('response' in support) return support.response;
    const url = new URL(request.url);
    const query = String(url.searchParams.get('q') ?? '').trim().slice(0, 80);
    if (!query) return json([]);
    const plainQuery = query.replace(/^[#@]/, '');
    const like = `%${plainQuery.replace(/[%_]/g, '')}%`;
    const now = Date.now();
    const result = await env.DB.prepare(`SELECT
        u.id,
        u.public_user_id,
        u.username,
        u.display_name,
        u.avatar_url,
        u.platform_role,
        u.created_at,
        (SELECT COUNT(*) FROM space_members sm WHERE sm.user_id = u.id) AS space_count,
        CASE WHEN EXISTS (
          SELECT 1 FROM platform_bans pb
          WHERE pb.user_id = u.id
            AND pb.active = 1
            AND (pb.expires_at IS NULL OR pb.expires_at > ?)
        ) THEN 1 ELSE 0 END AS banned
      FROM users u
      WHERE u.public_user_id = ?
         OR u.username LIKE ? COLLATE NOCASE
         OR u.display_name LIKE ? COLLATE NOCASE
      ORDER BY CASE WHEN u.public_user_id = ? THEN 0 WHEN u.username = ? COLLATE NOCASE THEN 1 ELSE 2 END,
               u.created_at DESC
      LIMIT 30`)
      .bind(now, plainQuery, like, like, plainQuery, plainQuery).all();
    return json((result.results ?? []).map(row => ({
      id: row.id,
      publicUserId: row.public_user_id ?? '',
      username: row.username,
      displayName: row.display_name,
      avatarUrl: row.avatar_url ?? null,
      platformRole: clientPlatformRole(row.platform_role),
      banned: Boolean(row.banned),
      spaceCount: Number(row.space_count ?? 0),
      createdAt: Number(row.created_at),
    })));
}

async function listSupportStaffMessages(request, env) {
    const support = await requireSupportConsole(request, env);
    if ('response' in support) return support.response;
    const result = await env.DB.prepare(`SELECT
        m.id,
        m.sender_user_id,
        m.body,
        m.created_at,
        u.public_user_id,
        u.display_name,
        u.username,
        u.platform_role
      FROM support_staff_messages m
      JOIN users u ON u.id = m.sender_user_id
      ORDER BY m.created_at DESC
      LIMIT 200`).all();
    return json((result.results ?? []).reverse().map(row => ({
      id: row.id,
      senderUserId: row.sender_user_id,
      senderPublicUserId: row.public_user_id ?? '',
      senderName: row.display_name,
      senderUsername: row.username,
      senderPlatformRole: clientPlatformRole(row.platform_role),
      body: row.body,
      createdAt: Number(row.created_at),
    })));
}

async function sendSupportStaffMessage(request, env) {
    const support = await requireSupportConsole(request, env);
    if ('response' in support) return support.response;
    await enforceRateLimit(request, env, 'support-staff-chat', 120, 1000 * 60 * 60, support.user.id);
    const body = await readJson(request);
    const messageBody = String(body.body ?? '').trim().slice(0, 1600);
    if (messageBody.length < 1) return fail('Write a message first.');
    const id = crypto.randomUUID();
    const now = Date.now();
    await env.DB.prepare(`INSERT INTO support_staff_messages (id, sender_user_id, body, created_at)
      VALUES (?, ?, ?, ?)`).bind(id, support.user.id, messageBody, now).run();
    return json({
      id,
      senderUserId: support.user.id,
      senderPublicUserId: support.user.public_user_id ?? '',
      senderName: support.user.display_name,
      senderUsername: support.user.username,
      senderPlatformRole: clientPlatformRole(support.user.platform_role),
      body: messageBody,
      createdAt: now,
    }, 201);
}

async function supportSpaceRestriction(request, env, workspaceId) {
    const support = await requireSupportConsole(request, env);
    if ('response' in support) return support.response;
    if (workspaceId === SPACES_HUB_ID) return fail('Spaces - Hub cannot be restricted.', 403);
    const space = await env.DB.prepare(`SELECT s.id, s.name, s.owner_user_id, u.platform_role AS owner_platform_role
      FROM spaces s JOIN users u ON u.id = s.owner_user_id WHERE s.id = ? LIMIT 1`).bind(workspaceId).first();
    if (!space) return fail('Space not found.', 404);
    if (!supportRoleCanActOn(support.user.platform_role, space.owner_platform_role)) return fail('Your Support role cannot restrict a Space owned by that platform role.', 403);
    if (request.method === 'DELETE') {
      await env.DB.prepare(`UPDATE space_restrictions SET active = 0 WHERE space_id = ? AND active = 1`).bind(workspaceId).run();
      return new Response(null, {status: 204, headers: corsHeaders()});
    }
    const body = await readJson(request);
    const reason = String(body.reason ?? 'Support review').trim().slice(0, 1200);
    const now = Date.now();
    await env.DB.prepare(`UPDATE space_restrictions SET active = 0 WHERE space_id = ? AND active = 1`).bind(workspaceId).run();
    await env.DB.prepare(`INSERT INTO space_restrictions (id, space_id, restricted_by, reason, created_at, expires_at, active)
      VALUES (?, ?, ?, ?, ?, NULL, 1)`).bind(crypto.randomUUID(), workspaceId, support.user.id, reason, now).run();
    return new Response(null, {status: 204, headers: corsHeaders()});
}

async function supportDeleteSpace(request, env, workspaceId) {
    const support = await requireSupportConsole(request, env);
    if ('response' in support) return support.response;
    if (workspaceId === SPACES_HUB_ID) return fail('Spaces - Hub cannot be deleted.', 403);
    const body = await readJson(request);
    const space = await env.DB.prepare(`SELECT s.id, s.name, s.owner_user_id, u.platform_role AS owner_platform_role
      FROM spaces s JOIN users u ON u.id = s.owner_user_id WHERE s.id = ? LIMIT 1`).bind(workspaceId).first();
    if (!space) return fail('Space not found.', 404);
    if (!supportRoleCanActOn(support.user.platform_role, space.owner_platform_role)) return fail('Your Support role cannot delete a Space owned by that platform role.', 403);
    if (String(body.confirmation ?? '') !== String(space.name)) return fail('Type the exact Space name to confirm deletion.');
    const reason = String(body.reason ?? 'Support deletion').trim().slice(0, 1200);
    const now = Date.now();
    await env.DB.prepare(`INSERT INTO platform_moderation_actions (id, moderator_id, target_user_id, action, reason, metadata_json, created_at)
      VALUES (?, ?, ?, 'space.deleted', ?, ?, ?)`).bind(crypto.randomUUID(), support.user.id, space.owner_user_id, reason, JSON.stringify({workspaceId, workspaceName: space.name}), now).run();
    await env.DB.prepare(`DELETE FROM spaces WHERE id = ?`).bind(workspaceId).run();
    return new Response(null, {status: 204, headers: corsHeaders()});
}

async function bootstrapCreator(request, env) {
    if (!env.BOOTSTRAP_SECRET) {
        return fail('Bootstrap is disabled.', 404);
    }
    const supplied = request.headers.get('X-Bootstrap-Secret') ?? '';
    if (!supplied ||
        !constantTimeEqual(supplied, env.BOOTSTRAP_SECRET)) {
        return fail('Unauthorized.', 401);
    }
    const auth = await requireUser(request, env);
    if ('response' in auth) {
        return auth.response;
    }
    const existing = await env.DB.prepare(`SELECT id
       FROM users
       WHERE platform_role = 'creator'
       LIMIT 1`)
        .first();
    if (existing &&
        existing.id !==
            auth.user.id) {
        return fail('A Founder already exists.', 409);
    }
    await env.DB.prepare(`UPDATE users
     SET
       platform_role = 'creator',
       public_user_id = '00001',
       updated_at = ?
     WHERE id = ?`)
        .bind(Date.now(), auth.user.id)
        .run();
    return json({
        ok: true,
        message: 'Founder assigned.',
    });
}

/* =========================================================
   DESKTOP UPDATER / RELEASE DELIVERY
   ========================================================= */

const DESKTOP_RELEASE_MANIFEST_KEY = 'desktop/latest.json';
const DESKTOP_RELEASE_PLATFORM_KEYS = new Set([
    'windows-x86_64',
]);

function normalizeDesktopVersion(value) {
    const version = String(value ?? '').trim();
    return /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/u.test(version)
        ? version
        : '';
}

function compareDesktopVersions(leftValue, rightValue) {
    const left = normalizeDesktopVersion(leftValue);
    const right = normalizeDesktopVersion(rightValue);

    if (!left || !right) return 0;

    const [leftCore, leftPre = ''] = left.split('-', 2);
    const [rightCore, rightPre = ''] = right.split('-', 2);
    const leftParts = leftCore.split('.').map(Number);
    const rightParts = rightCore.split('.').map(Number);

    for (let index = 0; index < 3; index += 1) {
        const difference = (leftParts[index] ?? 0) - (rightParts[index] ?? 0);
        if (difference !== 0) return difference > 0 ? 1 : -1;
    }

    if (leftPre === rightPre) return 0;
    if (!leftPre) return 1;
    if (!rightPre) return -1;
    return leftPre.localeCompare(rightPre, 'en', { numeric: true }) > 0 ? 1 : -1;
}

function desktopReleasePlatformKey(target, arch) {
    return `${String(target ?? '').toLowerCase()}-${String(arch ?? '').toLowerCase()}`;
}

function desktopReleaseArtifactKey(version, target, arch) {
    const cleanVersion = normalizeDesktopVersion(version);
    const cleanTarget = String(target ?? '').toLowerCase();
    const cleanArch = String(arch ?? '').toLowerCase();

    if (!cleanVersion) return '';
    if (cleanTarget !== 'windows' || cleanArch !== 'x86_64') return '';

    return `desktop/${cleanVersion}/windows/x86_64/Spaces_${cleanVersion}_x64-setup.exe`;
}

async function readDesktopReleaseManifest(env) {
    if (!env.DESKTOP_RELEASES) return null;

    const object = await env.DESKTOP_RELEASES.get(DESKTOP_RELEASE_MANIFEST_KEY);
    if (!object) return null;

    try {
        const manifest = JSON.parse(await object.text());
        if (!manifest || typeof manifest !== 'object') return null;
        return manifest;
    }
    catch (caught) {
        console.error('Invalid desktop release manifest.', caught);
        return null;
    }
}

function desktopUpdaterNoContent() {
    return new Response(null, {
        status: 204,
        headers: corsHeaders(),
    });
}

async function desktopUpdateCheck(request, env, target, arch, currentVersion) {
    const platformKey = desktopReleasePlatformKey(target, arch);
    if (!DESKTOP_RELEASE_PLATFORM_KEYS.has(platformKey)) {
        return desktopUpdaterNoContent();
    }

    const current = normalizeDesktopVersion(currentVersion);
    if (!current) {
        return desktopUpdaterNoContent();
    }

    const manifest = await readDesktopReleaseManifest(env);
    if (!manifest) {
        return desktopUpdaterNoContent();
    }

    const nextVersion = normalizeDesktopVersion(manifest.version);
    if (!nextVersion || compareDesktopVersions(nextVersion, current) <= 0) {
        return desktopUpdaterNoContent();
    }

    const platform = manifest.platforms?.[platformKey];
    const signature = String(platform?.signature ?? '').trim();
    const artifactKey = String(platform?.artifactKey ?? '').trim();
    const expectedArtifactKey = desktopReleaseArtifactKey(nextVersion, target, arch);

    if (!signature || !artifactKey || artifactKey !== expectedArtifactKey) {
        console.error('Desktop release manifest is missing a valid platform artifact/signature.');
        return desktopUpdaterNoContent();
    }

    const requestUrl = new URL(request.url);
    const downloadUrl = new URL(
        `/v1/desktop/releases/${encodeURIComponent(nextVersion)}/${encodeURIComponent(String(target).toLowerCase())}/${encodeURIComponent(String(arch).toLowerCase())}`,
        requestUrl.origin,
    );

    return json({
        version: nextVersion,
        notes: String(manifest.notes ?? ''),
        pub_date: String(manifest.pub_date ?? ''),
        url: downloadUrl.toString(),
        signature,
    });
}

async function desktopReleaseDownload(env, version, target, arch, method = 'GET') {
    if (!env.DESKTOP_RELEASES) {
        return fail('Desktop release storage is not configured.', 503);
    }

    const artifactKey = desktopReleaseArtifactKey(version, target, arch);
    if (!artifactKey) {
        return fail('Desktop release not found.', 404);
    }

    const object = await env.DESKTOP_RELEASES.get(artifactKey);
    if (!object) {
        return fail('Desktop release not found.', 404);
    }

    const headers = new Headers();
    if (typeof object.writeHttpMetadata === 'function') {
        object.writeHttpMetadata(headers);
    }

    const cleanVersion = normalizeDesktopVersion(version);
    const fileName = `Spaces_${cleanVersion}_x64-setup.exe`;

    headers.set('Content-Type', headers.get('Content-Type') || 'application/octet-stream');
    headers.set('Content-Disposition', `attachment; filename="${fileName}"`);
    headers.set('Cache-Control', 'public, max-age=31536000, immutable');
    headers.set('X-Content-Type-Options', 'nosniff');
    headers.set('Cross-Origin-Resource-Policy', 'cross-origin');
    headers.set('Access-Control-Allow-Origin', '*');
    if (object.httpEtag) headers.set('ETag', object.httpEtag);
    if (Number.isFinite(object.size)) headers.set('Content-Length', String(object.size));

    return new Response(method === 'HEAD' ? null : object.body, {
        status: 200,
        headers,
    });
}

async function health(env) {
    const check = await env.DB.prepare('SELECT 1 AS ok')
        .first();
    return json({
        ok: check?.ok === 1,
        service: 'Spaces',
        apiVersion: '6.6',
        database: 'connected',
        authKdf: `client-pbkdf2-sha256/${CLIENT_PASSWORD_ITERATIONS}`,
        spacesHub: true,
        moderation: true,
        liveChat: true,
        roleManagement: true,
        noteCommits: true,
        platformUpdates: true,
        spaceIdentity: true,
        channelPermissions: true,
        cropAvatarClient: true,
        spaceCreation: true,
        inviteCodes: true,
        accountSecurity: true,
        sessionManagement: true,
        channelCreation: true,
        moderationIdentityReset: true,
        incrementalSync: true,
        publicBetaHardening: true,
        mobileShell: true,
        messageControls: true,
        communityRoles: true,
        customEmojis: true,
        noteComments: true,
        spaceBranding: true,
        responsiveCommunityShell: true,
        requestRateLimits: true,
        channelDeletePermissions: true,
        privateBetaAccess: true,
        founderPlatformRole: true,
        profileCustomization: true,
        profileBanners: true,
        verifiedEmail: true,
        authenticator2fa: true,
        recoveryCodes: true,
        supportPlatformRole: true,
        supportConsole: true,
        supportCaseSystem: true,
        supportDirectMessages: true,
        supportSpaceRestrictions: true,
        publicUserIds: true,
        supportUserLookup: true,
        supportStaffChat: true,
        randomInviteCodesOnly: true,
        directMessaging: true,
        messageRequests: true,
        perSpaceDmPrivacy: true,
        friendsTerminology: true,
        friendOnlyGroupChats: true,
        verifiedEmailReauthentication: true,
        accessibilityTextScaling: true,
        baseRolePresentation: true,
        emailService: Boolean(env.EMAIL && typeof env.EMAIL.send === 'function'),
        emailSenderConfigured: Boolean(String(env.SPACES_EMAIL_FROM ?? '').trim()),
        originAllowlist: true,
        hardenedResponseHeaders: true,
        desktopUpdater: Boolean(env.DESKTOP_RELEASES),
        time: Date.now(),
    });
}
export default {
    async fetch(request, env) {
        if (!requestOriginAllowed(request, env)) {
            return forbiddenOriginResponse();
        }

        if (request.method ===
            'OPTIONS') {
            return new Response(null, {
                status: 204,
                headers: corsHeaders(),
            });
        }
        const url = new URL(request.url);
        try {
            if (request.method === 'GET' &&
                (url.pathname === '/' ||
                    url.pathname === '/health')) {
                return health(env);
            }


            const desktopUpdateRoute =
                url.pathname.match(
                    /^\/v1\/desktop\/update\/([^/]+)\/([^/]+)\/([^/]+)$/u,
                );

            if (request.method === 'GET' && desktopUpdateRoute) {
                return desktopUpdateCheck(
                    request,
                    env,
                    decodeURIComponent(desktopUpdateRoute[1] ?? ''),
                    decodeURIComponent(desktopUpdateRoute[2] ?? ''),
                    decodeURIComponent(desktopUpdateRoute[3] ?? ''),
                );
            }

            const desktopReleaseRoute =
                url.pathname.match(
                    /^\/v1\/desktop\/releases\/([^/]+)\/([^/]+)\/([^/]+)$/u,
                );

            if (
                (request.method === 'GET' || request.method === 'HEAD') &&
                desktopReleaseRoute
            ) {
                return desktopReleaseDownload(
                    env,
                    decodeURIComponent(desktopReleaseRoute[1] ?? ''),
                    decodeURIComponent(desktopReleaseRoute[2] ?? ''),
                    decodeURIComponent(desktopReleaseRoute[3] ?? ''),
                    request.method,
                );
            }
            if (request.method === 'POST' &&
                url.pathname ===
                    '/v1/auth/register') {
                const accountCount = await env.DB.prepare(
                    'SELECT COUNT(*) AS count FROM users',
                ).first();

                const registrationBody = await request
                    .clone()
                    .json()
                    .catch(() => ({}));

                if (
                    Number(accountCount?.count ?? 0) !== 0 ||
                    normalizeUsername(registrationBody?.username ?? '') !==
                        'spagotei'
                ) {
                    return fail(
                        'Spaces account registration is currently closed.',
                        403,
                    );
                }

                return register(request, env);
            }
            if (request.method === 'GET' &&
                url.pathname ===
                    '/v1/auth/challenge') {
                return authChallenge(request, env);
            }

            if (request.method === 'POST' &&
                url.pathname ===
                    '/v1/auth/login') {
                return login(request, env);
            }
            if (request.method === 'POST' &&
                url.pathname ===
                    '/v1/auth/logout') {
                return logout(request, env);
            }
            if (request.method === 'GET' &&
                url.pathname ===
                    '/v1/account/me') {
                return me(request, env);
            }
            if (request.method === 'PATCH' &&
                url.pathname ===
                    '/v1/account/profile') {
                return updateProfile(request, env);
            }
            if (request.method === 'PATCH' &&
                url.pathname ===
                    '/v1/account/avatar') {
                return updateAvatar(request, env);
            }
            if (request.method === 'PATCH' &&
                url.pathname ===
                    '/v1/account/banner') {
                return updateBanner(request, env);
            }
            if (
                request.method === 'PATCH' &&
                url.pathname ===
                    '/v1/account/password'
            ) {
                return changeAccountPassword(
                    request,
                    env,
                );
            }

            if (
                request.method === 'GET' &&
                url.pathname ===
                    '/v1/account/sessions'
            ) {
                return listAccountSessions(
                    request,
                    env,
                );
            }

            if (
                request.method === 'GET' &&
                url.pathname ===
                    '/v1/account/security'
            ) {
                return getAccountSecurity(request, env);
            }
            if (request.method === 'POST' && url.pathname === '/v1/account/email/start') {
                return startAccountEmailVerification(request, env);
            }
            if (request.method === 'POST' && url.pathname === '/v1/account/email/verify') {
                return verifyAccountEmail(request, env);
            }
            if (request.method === 'POST' && url.pathname === '/v1/account/2fa/setup') {
                return beginAccountTwoFactorSetup(request, env);
            }
            if (request.method === 'POST' && url.pathname === '/v1/account/2fa/enable') {
                return enableAccountTwoFactor(request, env);
            }
            if (request.method === 'POST' && url.pathname === '/v1/account/2fa/disable') {
                return disableAccountTwoFactor(request, env);
            }
            if (request.method === 'POST' && url.pathname === '/v1/account/2fa/recovery') {
                return regenerateAccountRecoveryCodes(request, env);
            }

            if (request.method === 'GET' && url.pathname === '/v1/direct/center') {
                return getDirectCenter(request, env);
            }
            if (request.method === 'POST' && url.pathname === '/v1/direct/groups') {
                return createDirectGroup(request, env);
            }
            const directGroupRoute = url.pathname.match(/^\/v1\/direct\/groups\/([^/]+)$/u);
            if (request.method === 'PATCH' && directGroupRoute) {
                return updateDirectGroup(request, env, decodeURIComponent(directGroupRoute[1] ?? ''));
            }
            const directGroupMessagesRoute = url.pathname.match(/^\/v1\/direct\/groups\/([^/]+)\/messages$/u);
            if (directGroupMessagesRoute) {
                const groupId = decodeURIComponent(directGroupMessagesRoute[1] ?? '');
                if (request.method === 'GET') return listDirectGroupMessages(request, env, groupId);
                if (request.method === 'POST') return sendDirectGroupMessage(request, env, groupId);
            }
            if (request.method === 'POST' && url.pathname === '/v1/direct/requests') {
                return createDirectRequest(request, env);
            }
            const directAcceptRoute = url.pathname.match(/^\/v1\/direct\/conversations\/([^/]+)\/accept$/u);
            if (request.method === 'POST' && directAcceptRoute) {
                return acceptDirectRequest(request, env, decodeURIComponent(directAcceptRoute[1] ?? ''));
            }
            const directRequestRoute = url.pathname.match(/^\/v1\/direct\/conversations\/([^/]+)\/request$/u);
            if (request.method === 'DELETE' && directRequestRoute) {
                return declineDirectRequest(request, env, decodeURIComponent(directRequestRoute[1] ?? ''));
            }
            const directMessagesRoute = url.pathname.match(/^\/v1\/direct\/conversations\/([^/]+)\/messages$/u);
            if (directMessagesRoute) {
                const directId = decodeURIComponent(directMessagesRoute[1] ?? '');
                if (request.method === 'GET') return listDirectConversationMessages(request, env, directId);
                if (request.method === 'POST') return sendDirectConversationMessage(request, env, directId);
            }

            const accountSessionRoute =
                url.pathname.match(
                    /^\/v1\/account\/sessions\/([^/]+)$/u,
                );

            if (
                request.method === 'DELETE' &&
                accountSessionRoute
            ) {
                return revokeAccountSession(
                    request,
                    env,
                    decodeURIComponent(
                        accountSessionRoute[1] ?? '',
                    ),
                );
            }
            const platformRoleRoute = url.pathname.match(/^\/v1\/platform\/users\/([^/]+)\/role$/u);
            if (request.method === 'PATCH' && platformRoleRoute) {
                return setPlatformSupportRole(request, env, decodeURIComponent(platformRoleRoute[1] ?? ''));
            }

            if (request.method === 'GET' &&
                url.pathname === '/v1/notifications') {
                return listNotifications(request, env);
            }
            if (request.method === 'GET' &&
                url.pathname ===
                    '/v1/workspaces') {
                return listSpaces(request, env);
            }
            if (
                request.method === 'POST' &&
                url.pathname ===
                    '/v1/workspaces'
            ) {
                return createWorkspace(
                    request,
                    env,
                );
            }

            if (
                request.method === 'POST' &&
                url.pathname ===
                    '/v1/invites/join'
            ) {
                return joinWorkspaceInvite(
                    request,
                    env,
                );
            }
            if (
                request.method === 'POST' &&
                url.pathname ===
                    '/v1/workspaces/join'
            ) {
                return joinWorkspaceInvite(
                    request,
                    env,
                );
            }


            const workspaceDmPreferenceRoute = url.pathname.match(/^\/v1\/workspaces\/([^/]+)\/dm-preference$/u);
            if (workspaceDmPreferenceRoute) {
                const workspaceDmId = decodeURIComponent(workspaceDmPreferenceRoute[1] ?? '');
                if (request.method === 'GET') return getWorkspaceDmPreference(request, env, workspaceDmId);
                if (request.method === 'PATCH') return updateWorkspaceDmPreference(request, env, workspaceDmId);
            }

            const workspaceSettingsRoute =
                url.pathname.match(
                    /^\/v1\/workspaces\/([^/]+)$/u,
                );

            if (
                request.method === 'PATCH' &&
                workspaceSettingsRoute
            ) {
                return updateWorkspace(
                    request,
                    env,
                    decodeURIComponent(
                        workspaceSettingsRoute[1] ?? '',
                    ),
                );
            }

            if (
                request.method === 'DELETE' &&
                workspaceSettingsRoute
            ) {
                return deleteWorkspace(
                    request,
                    env,
                    decodeURIComponent(
                        workspaceSettingsRoute[1] ?? '',
                    ),
                );
            }

            const workspaceMembershipRoute =
                url.pathname.match(
                    /^\/v1\/workspaces\/([^/]+)\/membership$/u,
                );

            if (
                request.method === 'DELETE' &&
                workspaceMembershipRoute
            ) {
                return leaveWorkspace(
                    request,
                    env,
                    decodeURIComponent(
                        workspaceMembershipRoute[1] ?? '',
                    ),
                );
            }

            const workspaceInvitesRoute =
                url.pathname.match(
                    /^\/v1\/workspaces\/([^/]+)\/invites$/u,
                );

            if (
                request.method === 'GET' &&
                workspaceInvitesRoute
            ) {
                return listWorkspaceInvites(
                    request,
                    env,
                    decodeURIComponent(
                        workspaceInvitesRoute[1] ?? '',
                    ),
                );
            }

            if (
                request.method === 'POST' &&
                workspaceInvitesRoute
            ) {
                return createWorkspaceInvite(
                    request,
                    env,
                    decodeURIComponent(
                        workspaceInvitesRoute[1] ?? '',
                    ),
                );
            }

            const workspaceInviteRoute =
                url.pathname.match(
                    /^\/v1\/workspaces\/([^/]+)\/invites\/([^/]+)$/u,
                );

            if (
                request.method === 'DELETE' &&
                workspaceInviteRoute
            ) {
                return revokeWorkspaceInvite(
                    request,
                    env,
                    decodeURIComponent(
                        workspaceInviteRoute[1] ?? '',
                    ),
                    decodeURIComponent(
                        workspaceInviteRoute[2] ?? '',
                    ),
                );
            }

            const workspaceChannelsRoute =
                url.pathname.match(
                    /^\/v1\/workspaces\/([^/]+)\/channels$/u,
                );

            if (
                request.method === 'POST' &&
                workspaceChannelsRoute
            ) {
                return createWorkspaceChannel(
                    request,
                    env,
                    decodeURIComponent(
                        workspaceChannelsRoute[1] ?? '',
                    ),
                );
            }

            const workspaceChannelRoute =
                url.pathname.match(
                    /^\/v1\/workspaces\/([^/]+)\/channels\/([^/]+)$/u,
                );

            if (request.method === 'DELETE' && workspaceChannelRoute) {
                return deleteWorkspaceChannel(
                    request,
                    env,
                    decodeURIComponent(workspaceChannelRoute[1] ?? ''),
                    decodeURIComponent(workspaceChannelRoute[2] ?? ''),
                );
            }

            const workspaceChannelPermissionsRoute =
                url.pathname.match(
                    /^\/v1\/workspaces\/([^/]+)\/channels\/([^/]+)\/permissions$/u,
                );

            if (request.method === 'PATCH' && workspaceChannelPermissionsRoute) {
                return updateWorkspaceChannelPermissions(
                    request,
                    env,
                    decodeURIComponent(workspaceChannelPermissionsRoute[1] ?? ''),
                    decodeURIComponent(workspaceChannelPermissionsRoute[2] ?? ''),
                );
            }

            const workspaceChannelOverwritesRoute =
                url.pathname.match(
                    /^\/v1\/workspaces\/([^/]+)\/channels\/([^/]+)\/permission-overwrites$/u,
                );

            if (request.method === 'GET' && workspaceChannelOverwritesRoute) {
                return listWorkspaceChannelPermissionOverwrites(
                    request,
                    env,
                    decodeURIComponent(workspaceChannelOverwritesRoute[1] ?? ''),
                    decodeURIComponent(workspaceChannelOverwritesRoute[2] ?? ''),
                );
            }

            if (request.method === 'PUT' && workspaceChannelOverwritesRoute) {
                return saveWorkspaceChannelPermissionOverwrite(
                    request,
                    env,
                    decodeURIComponent(workspaceChannelOverwritesRoute[1] ?? ''),
                    decodeURIComponent(workspaceChannelOverwritesRoute[2] ?? ''),
                );
            }

            const workspaceChannelOverwriteRoute =
                url.pathname.match(
                    /^\/v1\/workspaces\/([^/]+)\/channels\/([^/]+)\/permission-overwrites\/([^/]+)\/([^/]+)$/u,
                );

            if (request.method === 'DELETE' && workspaceChannelOverwriteRoute) {
                return deleteWorkspaceChannelPermissionOverwrite(
                    request,
                    env,
                    decodeURIComponent(workspaceChannelOverwriteRoute[1] ?? ''),
                    decodeURIComponent(workspaceChannelOverwriteRoute[2] ?? ''),
                    decodeURIComponent(workspaceChannelOverwriteRoute[3] ?? ''),
                    decodeURIComponent(workspaceChannelOverwriteRoute[4] ?? ''),
                );
            }

            const workspaceBootstrapMatch =
                url.pathname.match(
                    /^\/v1\/workspaces\/([^/]+)\/bootstrap$/u,
                );

            if (request.method === 'GET' &&
                workspaceBootstrapMatch) {
                return workspaceBootstrap(
                    request,
                    env,
                    decodeURIComponent(
                        workspaceBootstrapMatch[1] ?? '',
                    ),
                );
            }
            const workspaceSyncMatch =
                url.pathname.match(
                    /^\/v1\/workspaces\/([^/]+)\/sync$/u,
                );

            if (
                request.method === 'GET' &&
                workspaceSyncMatch
            ) {
                return workspaceSync(
                    request,
                    env,
                    decodeURIComponent(
                        workspaceSyncMatch[1] ?? '',
                    ),
                );
            }

            if (
                request.method === 'GET' &&
                url.pathname === '/v1/updates'
            ) {
                return listPlatformUpdates(
                    request,
                    env,
                );
            }

            if (
                request.method === 'POST' &&
                url.pathname === '/v1/updates'
            ) {
                return createPlatformUpdate(
                    request,
                    env,
                );
            }

            const updateRoute =
                url.pathname.match(
                    /^\/v1\/updates\/([^/]+)$/u,
                );

            if (
                updateRoute &&
                request.method === 'PATCH'
            ) {
                return updatePlatformUpdate(
                    request,
                    env,
                    decodeURIComponent(
                        updateRoute[1] ?? '',
                    ),
                );
            }

            if (
                updateRoute &&
                request.method === 'DELETE'
            ) {
                return deletePlatformUpdate(
                    request,
                    env,
                    decodeURIComponent(
                        updateRoute[1] ?? '',
                    ),
                );
            }

            const noteCreateRoute =
                url.pathname.match(
                    /^\/v1\/workspaces\/([^/]+)\/notes$/u,
                );

            if (
                noteCreateRoute &&
                request.method === 'POST'
            ) {
                return saveWorkspaceNote(
                    request,
                    env,
                    decodeURIComponent(
                        noteCreateRoute[1] ?? '',
                    ),
                    null,
                );
            }

            const noteUpdateRoute =
                url.pathname.match(
                    /^\/v1\/workspaces\/([^/]+)\/notes\/([^/]+)$/u,
                );

            if (
                noteUpdateRoute &&
                request.method === 'PATCH'
            ) {
                return saveWorkspaceNote(
                    request,
                    env,
                    decodeURIComponent(
                        noteUpdateRoute[1] ?? '',
                    ),
                    decodeURIComponent(
                        noteUpdateRoute[2] ?? '',
                    ),
                );
            }

            const noteVersionsRoute =
                url.pathname.match(
                    /^\/v1\/workspaces\/([^/]+)\/notes\/([^/]+)\/versions$/u,
                );

            if (
                request.method === 'GET' &&
                noteVersionsRoute
            ) {
                return listWorkspaceNoteVersions(
                    request,
                    env,
                    decodeURIComponent(
                        noteVersionsRoute[1] ?? '',
                    ),
                    decodeURIComponent(
                        noteVersionsRoute[2] ?? '',
                    ),
                );
            }

            const noteDeleteRoute =
                url.pathname.match(
                    /^\/v1\/workspaces\/([^/]+)\/notes\/([^/]+)$/u,
                );

            if (
                request.method === 'DELETE' &&
                noteDeleteRoute
            ) {
                return deleteWorkspaceNote(
                    request,
                    env,
                    decodeURIComponent(
                        noteDeleteRoute[1] ?? '',
                    ),
                    decodeURIComponent(
                        noteDeleteRoute[2] ?? '',
                    ),
                );
            }

            const messageRoute =
                url.pathname.match(
                    /^\/v1\/workspaces\/([^/]+)\/channels\/([^/]+)\/messages$/u,
                );

            if (
                request.method === 'POST' &&
                messageRoute
            ) {
                return sendWorkspaceMessage(
                    request,
                    env,
                    decodeURIComponent(
                        messageRoute[1] ?? '',
                    ),
                    decodeURIComponent(
                        messageRoute[2] ?? '',
                    ),
                );
            }

            const messageItemRoute =
                url.pathname.match(
                    /^\/v1\/workspaces\/([^/]+)\/messages\/([^/]+)$/u,
                );

            const messageAttachmentRoute =
                url.pathname.match(
                    /^\/v1\/workspaces\/([^/]+)\/messages\/([^/]+)\/attachment$/u,
                );

            if (request.method === 'GET' && messageAttachmentRoute) {
                return getWorkspaceMessageAttachment(
                    request, env,
                    decodeURIComponent(messageAttachmentRoute[1] ?? ''),
                    decodeURIComponent(messageAttachmentRoute[2] ?? ''),
                );
            }

            if (request.method === 'PATCH' && messageItemRoute) {
                return editWorkspaceMessage(
                    request, env,
                    decodeURIComponent(messageItemRoute[1] ?? ''),
                    decodeURIComponent(messageItemRoute[2] ?? ''),
                );
            }

            if (request.method === 'DELETE' && messageItemRoute) {
                return deleteWorkspaceMessage(
                    request, env,
                    decodeURIComponent(messageItemRoute[1] ?? ''),
                    decodeURIComponent(messageItemRoute[2] ?? ''),
                );
            }

            const baseRolesRoute =
                url.pathname.match(
                    /^\/v1\/workspaces\/([^/]+)\/base-roles$/u,
                );

            if (request.method === 'GET' && baseRolesRoute) {
                return getWorkspaceBaseRoleSettings(
                    request, env,
                    decodeURIComponent(baseRolesRoute[1] ?? ''),
                );
            }

            const baseRoleItemRoute =
                url.pathname.match(
                    /^\/v1\/workspaces\/([^/]+)\/base-roles\/(owner|member)$/u,
                );

            if (request.method === 'PATCH' && baseRoleItemRoute) {
                return updateWorkspaceBaseRoleSetting(
                    request, env,
                    decodeURIComponent(baseRoleItemRoute[1] ?? ''),
                    decodeURIComponent(baseRoleItemRoute[2] ?? ''),
                );
            }

            const customRolesRoute =
                url.pathname.match(
                    /^\/v1\/workspaces\/([^/]+)\/roles$/u,
                );

            if (request.method === 'POST' && customRolesRoute) {
                return createWorkspaceCustomRole(
                    request, env,
                    decodeURIComponent(customRolesRoute[1] ?? ''),
                );
            }

            const customRoleItemRoute =
                url.pathname.match(
                    /^\/v1\/workspaces\/([^/]+)\/roles\/([^/]+)$/u,
                );

            if (request.method === 'PATCH' && customRoleItemRoute) {
                return updateWorkspaceCustomRole(
                    request, env,
                    decodeURIComponent(customRoleItemRoute[1] ?? ''),
                    decodeURIComponent(customRoleItemRoute[2] ?? ''),
                );
            }

            if (request.method === 'DELETE' && customRoleItemRoute) {
                return deleteWorkspaceCustomRole(
                    request, env,
                    decodeURIComponent(customRoleItemRoute[1] ?? ''),
                    decodeURIComponent(customRoleItemRoute[2] ?? ''),
                );
            }

            const memberCustomRolesRoute =
                url.pathname.match(
                    /^\/v1\/workspaces\/([^/]+)\/members\/([^/]+)\/custom-roles$/u,
                );

            if (request.method === 'PATCH' && memberCustomRolesRoute) {
                return setWorkspaceMemberCustomRoles(
                    request, env,
                    decodeURIComponent(memberCustomRolesRoute[1] ?? ''),
                    decodeURIComponent(memberCustomRolesRoute[2] ?? ''),
                );
            }

            const emojisRoute =
                url.pathname.match(
                    /^\/v1\/workspaces\/([^/]+)\/emojis$/u,
                );

            if (request.method === 'POST' && emojisRoute) {
                return createWorkspaceEmoji(
                    request, env,
                    decodeURIComponent(emojisRoute[1] ?? ''),
                );
            }

            const emojiItemRoute =
                url.pathname.match(
                    /^\/v1\/workspaces\/([^/]+)\/emojis\/([^/]+)$/u,
                );

            if (request.method === 'DELETE' && emojiItemRoute) {
                return deleteWorkspaceEmoji(
                    request, env,
                    decodeURIComponent(emojiItemRoute[1] ?? ''),
                    decodeURIComponent(emojiItemRoute[2] ?? ''),
                );
            }

            const noteCommentsRoute =
                url.pathname.match(
                    /^\/v1\/workspaces\/([^/]+)\/notes\/([^/]+)\/comments$/u,
                );

            if (request.method === 'POST' && noteCommentsRoute) {
                return createNoteComment(
                    request, env,
                    decodeURIComponent(noteCommentsRoute[1] ?? ''),
                    decodeURIComponent(noteCommentsRoute[2] ?? ''),
                );
            }

            const commentItemRoute =
                url.pathname.match(
                    /^\/v1\/workspaces\/([^/]+)\/comments\/([^/]+)$/u,
                );

            if (request.method === 'PATCH' && commentItemRoute) {
                return editNoteComment(
                    request, env,
                    decodeURIComponent(commentItemRoute[1] ?? ''),
                    decodeURIComponent(commentItemRoute[2] ?? ''),
                );
            }

            if (request.method === 'DELETE' && commentItemRoute) {
                return deleteNoteComment(
                    request, env,
                    decodeURIComponent(commentItemRoute[1] ?? ''),
                    decodeURIComponent(commentItemRoute[2] ?? ''),
                );
            }

            const memberRoleRoute =
                url.pathname.match(
                    /^\/v1\/workspaces\/([^/]+)\/members\/([^/]+)\/role$/u,
                );

            if (
                request.method === 'PATCH' &&
                memberRoleRoute
            ) {
                return changeWorkspaceMemberRole(
                    request,
                    env,
                    decodeURIComponent(
                        memberRoleRoute[1] ?? '',
                    ),
                    decodeURIComponent(
                        memberRoleRoute[2] ?? '',
                    ),
                );
            }

            const memberDeleteRoute =
                url.pathname.match(
                    /^\/v1\/workspaces\/([^/]+)\/members\/([^/]+)$/u,
                );

            if (
                request.method === 'DELETE' &&
                memberDeleteRoute
            ) {
                return removeWorkspaceMember(
                    request,
                    env,
                    decodeURIComponent(
                        memberDeleteRoute[1] ?? '',
                    ),
                    decodeURIComponent(
                        memberDeleteRoute[2] ?? '',
                    ),
                );
            }

            if (
                request.method === 'POST' &&
                url.pathname === '/v1/reports'
            ) {
                return createPlatformReport(
                    request,
                    env,
                );
            }

            if (
                request.method === 'GET' &&
                url.pathname === '/v1/moderation/reports'
            ) {
                return listModerationReports(
                    request,
                    env,
                );
            }

            const moderationReportRoute =
                url.pathname.match(
                    /^\/v1\/moderation\/reports\/([^/]+)$/u,
                );

            if (
                request.method === 'PATCH' &&
                moderationReportRoute
            ) {
                return updateModerationReportStatus(
                    request,
                    env,
                    decodeURIComponent(
                        moderationReportRoute[1] ?? '',
                    ),
                );
            }

            const moderationIdentityRoute =
                url.pathname.match(
                    /^\/v1\/moderation\/users\/([^/]+)\/identity$/u,
                );

            if (
                request.method === 'PATCH' &&
                moderationIdentityRoute
            ) {
                return moderateUserIdentity(
                    request,
                    env,
                    decodeURIComponent(
                        moderationIdentityRoute[1] ?? '',
                    ),
                );
            }

            const banRoute =
                url.pathname.match(
                    /^\/v1\/moderation\/users\/([^/]+)\/ban$/u,
                );

            if (
                (
                    request.method === 'POST' ||
                    request.method === 'DELETE'
                ) &&
                banRoute
            ) {
                return banPlatformUser(
                    request,
                    env,
                    decodeURIComponent(
                        banRoute[1] ?? '',
                    ),
                );
            }

            if (url.pathname === '/v1/support/cases') {
                if (request.method === 'GET') return listSupportCases(request, env);
                if (request.method === 'POST') return createSupportCase(request, env);
            }
            const supportCaseRoute = url.pathname.match(/^\/v1\/support\/cases\/([^/]+)$/u);
            if (request.method === 'PATCH' && supportCaseRoute) {
                return updateSupportCase(request, env, decodeURIComponent(supportCaseRoute[1] ?? ''));
            }
            if (url.pathname === '/v1/support/messages') {
                if (request.method === 'GET') return listSupportMessages(request, env);
                if (request.method === 'POST') return sendSupportMessage(request, env);
            }
            if (url.pathname === '/v1/support/users' && request.method === 'GET') {
                return searchSupportUsers(request, env);
            }
            if (url.pathname === '/v1/support/staff-chat') {
                if (request.method === 'GET') return listSupportStaffMessages(request, env);
                if (request.method === 'POST') return sendSupportStaffMessage(request, env);
            }
            const supportRestrictionRoute = url.pathname.match(/^\/v1\/support\/spaces\/([^/]+)\/restriction$/u);
            if ((request.method === 'POST' || request.method === 'DELETE') && supportRestrictionRoute) {
                return supportSpaceRestriction(request, env, decodeURIComponent(supportRestrictionRoute[1] ?? ''));
            }
            const supportSpaceRoute = url.pathname.match(/^\/v1\/support\/spaces\/([^/]+)$/u);
            if (request.method === 'DELETE' && supportSpaceRoute) {
                return supportDeleteSpace(request, env, decodeURIComponent(supportSpaceRoute[1] ?? ''));
            }

            if (request.method === 'POST' &&
                url.pathname ===
                    '/v1/admin/bootstrap-creator') {
                return bootstrapCreator(request, env);
            }
            const profileMatch = url.pathname.match(/^\/v1\/profiles\/([^/]+)$/u);
            if (request.method === 'GET' &&
                profileMatch) {
                return getPublicProfile(decodeURIComponent(profileMatch[1] ?? ''), env);
            }
            return fail('Not found.', 404);
        }
        catch (caught) {
            console.error(caught);

            if (caught instanceof ApiRequestError) {
                return fail(caught.message, caught.status);
            }

            return fail(caught instanceof Error
                ? caught.message
                : 'Unexpected server error.', 500);
        }
    },
};
