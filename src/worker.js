import { handleSpacesProgramsV90 } from './space-programs-v90.mjs'; // SPACES_V90_PROGRAM_API
import { routeNotesFoldersV89 } from './notes-folders-v89.mjs'; // SPACES_V89_NOTE_FOLDERS_IMPORT
import { finishDmCallV85, finalizeExpiredDmCallsV85, getDmCallEventsV85, missedDmNotificationsV85 } from './voice-dm-events-v85.mjs'; // SPACES_V85_HISTORY_IMPORT
import { recordFailedLoginV85, recordStaffDeniedV85 } from './security-audit-v85.mjs'; // SPACES_V85_SECURITY_IMPORT
import { createStaffCenter, receiveStaffEmail } from './staff-inbox-v84-3.mjs'; // SPACES_V84_3_INBOX_IMPORT
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
        'Access-Control-Allow-Headers': 'Authorization, Content-Type, X-Bootstrap-Secret, X-Spaces-Developer-Mode',
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
            ...corsHeaders(),
            'Content-Type': 'application/json; charset=utf-8',
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
// Cloudflare Workers WebCrypto caps one PBKDF2 operation at 100000 iterations.
// Normal Spaces passwords still use 310000 on the client; only the random
// temporary beta-invite password uses the Worker-safe count below.
const BETA_INVITE_PASSWORD_ITERATIONS = 100000;

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
        parentCommentId: row.parent_comment_id ?? null,
        authorUsername: row.author_username ?? '',
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
           u.platform_role,
           u.presence_status,
           u.custom_status,
           u.updated_at AS presence_seen_at
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
           m.attachment_name, m.attachment_type, m.attachment_size, m.reply_to_message_id,
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
                    status: memberPresence(member.presence_status, member.presence_seen_at),
                    customStatus: String(member.custom_status ?? ''),
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
                    attachment:
                        messageAttachmentFromRow(message),
                    replyToMessageId: message.reply_to_message_id ?? null,
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
                   u.platform_role,
                   u.presence_status,
                   u.custom_status,
                   u.updated_at AS presence_seen_at
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
               m.reply_to_message_id,
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
                            memberPresence(member.presence_status, member.presence_seen_at),
                        customStatus:
                            String(member.custom_status ?? ''),
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
                    replyToMessageId: message.reply_to_message_id ?? null,
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
    if (!Number.isSafeInteger(next) || next < 20) {
        throw new ApiRequestError('Spaces public ID allocation failed.', 503);
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

function supportRoleRankV70(role) {
    if (role === 'creator') return 4;
    if (role === 'staff') return 3;
    if (role === 'support') return 2;
    return 1;
}

function supportRoleCanActOn(actorRole, targetRole) {
    if (targetRole === 'creator') return false;
    return supportRoleRankV70(actorRole) > supportRoleRankV70(targetRole);
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
        presence: normalizePresencePreference(user.presence_status),
        customStatus: String(user.custom_status ?? ''),
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
        profileSetupRequired: Boolean(user.beta_profile_pending),
        loginIdentifier: user.beta_profile_pending ? (user.email ?? undefined) : undefined,
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

    const v77PlatformRestriction = row.platform_role === 'creator' ? null : await activeSupportRestrictionV77(env, 'user', row.id, 'platform_access');
    if (v77PlatformRestriction) {
        await env.DB.prepare(`DELETE FROM sessions WHERE user_id = ?`).bind(row.id).run();
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
    if (reservedUsername(username) && username !== 'spagotei') {
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
    const publicUserId =
        username === 'spagotei'
            ? '00001'
            : await nextPublicUserId(env);
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
async function completeBetaProfile(request, env) {
    const auth = await requireUser(request, env);
    if ('response' in auth) return auth.response;

    const current = await env.DB.prepare(
        `SELECT * FROM users WHERE id = ? LIMIT 1`
    ).bind(auth.user.id).first();

    if (!current) {
        return fail('Account not found.', 404);
    }

    if (!Boolean(current.beta_profile_pending)) {
        return fail('Profile setup is already complete.', 409);
    }

    const body = await readJson(request);
    const username = normalizeUsername(body.username ?? '');
    const displayName = String(body.displayName ?? username).trim();

    if (!validNewUsername(username)) {
        return fail(
            'Username must be 4-24 characters using lowercase letters, numbers, or underscore.',
        );
    }

    if (reservedUsername(username)) {
        return fail('That username is reserved.', 409);
    }

    if (displayName.length < 1 || displayName.length > 40) {
        return fail('Display name must be 1-40 characters.');
    }

    const existing = await env.DB.prepare(
        `SELECT id FROM users
         WHERE username = ? AND id <> ?
         LIMIT 1`
    ).bind(username, current.id).first();

    if (existing) {
        return fail('That username is already taken.', 409);
    }

    const avatarUrl = body.avatarUrl === null || body.avatarUrl === undefined
        ? null
        : String(body.avatarUrl).trim();

    if (avatarUrl) {
        const remote = /^https:\/\//u.test(avatarUrl);
        const inlineImage =
            /^data:image\/(?:png|jpeg|webp);base64,[A-Za-z0-9+/=]+$/u
                .test(avatarUrl);
        const maxLength = inlineImage ? 300000 : 2048;

        if (
            avatarUrl.length > maxLength ||
            (!remote && !inlineImage)
        ) {
            return fail(
                'Avatar must be an HTTPS image or a compressed profile image.',
            );
        }
    }

    const now = Date.now();

    await env.DB.prepare(
        `UPDATE users
         SET username = ?,
             display_name = ?,
             avatar_url = ?,
             public_profile = 1,
             beta_profile_pending = 0,
             updated_at = ?
         WHERE id = ?`
    ).bind(
        username,
        displayName,
        avatarUrl,
        now,
        current.id,
    ).run();

    await env.DB.prepare(
        `UPDATE beta_access
         SET status = 'claimed',
             claimed_at = ?,
             revoked_at = NULL
         WHERE user_id = ?
           AND status = 'invited'`
    ).bind(now, current.id).run();

    const updated = await env.DB.prepare(
        `SELECT * FROM users WHERE id = ? LIMIT 1`
    ).bind(current.id).first();

    return updated
        ? createSession(env, updated)
        : fail('Profile setup failed.', 500);
}


async function betaClaimStatus(request, env) {
    const url = new URL(request.url);
    const email = normalizeEmail(url.searchParams.get('email') ?? '');

    await enforceRateLimit(
        request,
        env,
        'beta-claim-status',
        80,
        1000 * 60 * 5,
        email,
    );

    if (!validEmail(email)) {
        return json({ mode: 'unavailable' });
    }

    const access = await env.DB.prepare(
        `SELECT * FROM beta_access
         WHERE email = ? COLLATE NOCASE
         LIMIT 1`
    ).bind(email).first();

    const account = await env.DB.prepare(
        `SELECT * FROM users
         WHERE email = ? COLLATE NOCASE
         LIMIT 1`
    ).bind(email).first();

    if (account) {
        if (isLegacyBetaPlaceholderAccount(account, access)) {
            return json({
                mode: access?.status === 'invited'
                    ? 'claim'
                    : 'unavailable',
            });
        }

        return json({ mode: 'login' });
    }

    return json({
        mode: access?.status === 'invited'
            ? 'claim'
            : 'unavailable',
    });
}


async function startBetaClaim(request, env) {
    const body = await readJson(request);
    const email = normalizeEmail(body.email ?? '');

    await enforceRateLimit(
        request,
        env,
        'beta-claim-start',
        12,
        1000 * 60 * 10,
        email,
    );

    if (!validEmail(email)) {
        return fail('Enter a valid email address.');
    }

    const access = await env.DB.prepare(
        `SELECT * FROM beta_access
         WHERE email = ? COLLATE NOCASE
         LIMIT 1`
    ).bind(email).first();

    if (!access || access.status !== 'invited') {
        return fail('This email does not currently have beta access.', 403);
    }

    const existingUser = await env.DB.prepare(
        `SELECT * FROM users
         WHERE email = ? COLLATE NOCASE
         LIMIT 1`
    ).bind(email).first();

    if (
        existingUser &&
        !isLegacyBetaPlaceholderAccount(existingUser, access)
    ) {
        return fail(
            'This email already has a Spaces account. Sign in with your password instead.',
            409,
        );
    }

    if (!env.EMAIL || typeof env.EMAIL.send !== 'function') {
        return fail('Cloudflare Email Service is not configured yet.', 503);
    }

    const sender = String(env.SPACES_EMAIL_FROM ?? '').trim();
    if (!sender) {
        return fail('SPACES_EMAIL_FROM is not configured yet.', 503);
    }

    const id = crypto.randomUUID();
    const code = randomNumericCode(6);
    const codeHash = await sha256Base64(`${id}:${code}`);
    const now = Date.now();
    const expiresAt = now + EMAIL_CODE_TTL_MS;

    await env.DB.prepare(
        `DELETE FROM beta_claim_challenges
         WHERE email = ? COLLATE NOCASE
           AND consumed_at IS NULL`
    ).bind(email).run();

    await env.DB.prepare(
        `INSERT INTO beta_claim_challenges
          (id, email, code_hash, claim_token_hash, created_at, expires_at, attempts, verified_at, consumed_at)
         VALUES (?, ?, ?, NULL, ?, ?, 0, NULL, NULL)`
    ).bind(id, email, codeHash, now, expiresAt).run();

    try {
        const messageV76 = renderSpacesCodeEmailV76({ kind: 'invite', code, expiresMinutes: Math.max(1, Math.round(EMAIL_CODE_TTL_MS / 60000)) });
        await env.EMAIL.send({
            to: email,
            from: { email: sender, name: 'Spaces' },
            replyTo: String(env.SPACES_EMAIL_REPLY_TO ?? '').trim() || sender,
            subject: messageV76.subject,
            text: messageV76.text,
            html: messageV76.html,
        });
    } catch (error) {
        console.error('Beta claim verification email failed.', error);
        await env.DB.prepare(
            `DELETE FROM beta_claim_challenges WHERE id = ?`
        ).bind(id).run();
        return fail('Could not send the beta verification email.', 502);
    }

    return json({ sent: true, email, expiresAt });
}

async function verifyBetaClaim(request, env) {
    const body = await readJson(request);
    const email = normalizeEmail(body.email ?? '');
    const code = String(body.code ?? '').replace(/\D/gu, '');

    await enforceRateLimit(
        request,
        env,
        'beta-claim-verify',
        20,
        1000 * 60 * 10,
        email,
    );

    if (!validEmail(email) || !/^\d{6}$/u.test(code)) {
        return fail('Enter the 6-digit code from your email.', 400);
    }

    const challenge = await env.DB.prepare(
        `SELECT * FROM beta_claim_challenges
         WHERE email = ? COLLATE NOCASE
           AND consumed_at IS NULL
         ORDER BY created_at DESC
         LIMIT 1`
    ).bind(email).first();

    if (!challenge || Number(challenge.expires_at) <= Date.now()) {
        return fail('That verification code expired. Request a new one.', 410);
    }

    if (Number(challenge.attempts ?? 0) >= 8) {
        return fail('Too many incorrect attempts. Request a new code.', 429);
    }

    await env.DB.prepare(
        `UPDATE beta_claim_challenges
         SET attempts = attempts + 1
         WHERE id = ?`
    ).bind(challenge.id).run();

    const expected = await sha256Base64(`${challenge.id}:${code}`);
    if (!constantTimeEqual(expected, challenge.code_hash)) {
        return fail('That verification code is not correct.', 401);
    }

    const claimToken = randomToken(32);
    const claimTokenHash =
        await sha256Base64(`${challenge.id}:${claimToken}`);
    const now = Date.now();
    const claimExpiresAt = now + 1000 * 60 * 15;

    await env.DB.prepare(
        `UPDATE beta_claim_challenges
         SET verified_at = ?,
             claim_token_hash = ?,
             expires_at = ?
         WHERE id = ?`
    ).bind(now, claimTokenHash, claimExpiresAt, challenge.id).run();

    return json({
        email,
        claimToken,
        expiresAt: claimExpiresAt,
    });
}


async function claimBetaAccount(request, env) {
    const body = await readJson(request);
    const email = normalizeEmail(body.email ?? '');
    const claimToken = String(body.claimToken ?? '');
    const username = normalizeUsername(body.username ?? '');
    const displayName = String(body.displayName ?? username).trim();
    const passwordSalt = String(body.passwordSalt ?? '');
    const passwordVerifier = String(body.passwordVerifier ?? '');
    const passwordIterations = Number(body.passwordIterations ?? 0);

    await enforceRateLimit(
        request,
        env,
        'beta-claim-complete',
        12,
        1000 * 60 * 30,
        email,
    );

    if (!validEmail(email) || !claimToken) {
        return fail('Verify your invited email before creating the account.', 401);
    }

    const access = await env.DB.prepare(
        `SELECT * FROM beta_access
         WHERE email = ? COLLATE NOCASE
         LIMIT 1`
    ).bind(email).first();

    if (!access || access.status !== 'invited') {
        return fail('This beta invitation is no longer available.', 403);
    }

    const challenge = await env.DB.prepare(
        `SELECT * FROM beta_claim_challenges
         WHERE email = ? COLLATE NOCASE
           AND verified_at IS NOT NULL
           AND claim_token_hash IS NOT NULL
           AND consumed_at IS NULL
           AND expires_at > ?
         ORDER BY verified_at DESC
         LIMIT 1`
    ).bind(email, Date.now()).first();

    if (!challenge) {
        return fail('Your verified beta claim expired. Verify the email again.', 401);
    }

    const claimTokenHash =
        await sha256Base64(`${challenge.id}:${claimToken}`);

    if (!constantTimeEqual(claimTokenHash, challenge.claim_token_hash)) {
        return fail('Your beta claim could not be verified.', 401);
    }

    if (!validNewUsername(username)) {
        return fail('Username must be 4-24 characters using lowercase letters, numbers, or underscore.');
    }

    if (reservedUsername(username)) {
        return fail('That username is reserved.', 409);
    }

    if (displayName.length < 1 || displayName.length > 40) {
        return fail('Display name must be 1-40 characters.');
    }

    if (
        passwordIterations !== CLIENT_PASSWORD_ITERATIONS ||
        !isBase64Bytes(passwordSalt, 16) ||
        !isBase64Bytes(passwordVerifier, 32)
    ) {
        return fail('Invalid password verifier.');
    }

    const duplicateEmail = await env.DB.prepare(
        `SELECT * FROM users
         WHERE email = ? COLLATE NOCASE
         LIMIT 1`
    ).bind(email).first();

    const reuseLegacyAccount =
        isLegacyBetaPlaceholderAccount(duplicateEmail, access);

    if (duplicateEmail && !reuseLegacyAccount) {
        return fail(
            'This email already has a Spaces account. Sign in instead.',
            409,
        );
    }

    const duplicateUsername = await env.DB.prepare(
        `SELECT id FROM users
         WHERE username = ?
         LIMIT 1`
    ).bind(username).first();

    if (
        duplicateUsername &&
        String(duplicateUsername.id) !==
            String(duplicateEmail?.id ?? '')
    ) {
        return fail('That username is already taken.', 409);
    }

    const verifierHash =
        await hashPasswordVerifier(passwordVerifier);
    const now = Date.now();

    let userId;

    if (reuseLegacyAccount) {
        userId = duplicateEmail.id;

        await env.DB.prepare(
            `DELETE FROM sessions WHERE user_id = ?`
        ).bind(userId).run();

        await env.DB.prepare(
            `UPDATE users
             SET username = ?,
                 display_name = ?,
                 password_salt = ?,
                 password_hash = ?,
                 public_profile = 1,
                 spaces_access = 1,
                 email_verified = 1,
                 beta_profile_pending = 0,
                 updated_at = ?
             WHERE id = ?`
        ).bind(
            username,
            displayName,
            passwordSalt,
            `client-pbkdf2-sha256$${passwordIterations}$${verifierHash}`,
            now,
            userId,
        ).run();
    } else {
        userId = crypto.randomUUID();
        const publicUserId = await nextPublicUserId(env);

        await env.DB.prepare(
            `INSERT INTO users (
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
                updated_at,
                spaces_access,
                email,
                email_verified,
                beta_profile_pending
             )
             VALUES (
                ?, ?, ?, ?, ?, ?,
                NULL, '', 1, NULL, ?, ?,
                1, ?, 1, 0
             )`
        ).bind(
            userId,
            publicUserId,
            username,
            displayName,
            passwordSalt,
            `client-pbkdf2-sha256$${passwordIterations}$${verifierHash}`,
            now,
            now,
            email,
        ).run();
    }

    await ensureHubMembership(env, userId);

    await env.DB.prepare(
        `UPDATE beta_access
         SET status = 'claimed',
             user_id = ?,
             claimed_at = ?,
             revoked_at = NULL
         WHERE id = ?`
    ).bind(userId, now, access.id).run();

    await env.DB.prepare(
        `UPDATE beta_claim_challenges
         SET consumed_at = ?
         WHERE id = ?`
    ).bind(now, challenge.id).run();

    const user = await env.DB.prepare(
        `SELECT * FROM users WHERE id = ? LIMIT 1`
    ).bind(userId).first();

    return user
        ? createSession(env, user)
        : fail('Account creation failed.', 500);
}

async function authChallenge(request, env) {
    const url = new URL(request.url);
    const rawIdentifier = String(
        url.searchParams.get('identifier') ??
        url.searchParams.get('username') ??
        '',
    ).trim().toLowerCase();

    const emailLogin = rawIdentifier.includes('@');
    const identifier = emailLogin
        ? normalizeEmail(rawIdentifier)
        : normalizeUsername(rawIdentifier);

    await enforceRateLimit(
        request,
        env,
        'auth-challenge',
        40,
        1000 * 60 * 5,
        identifier,
    );

    const identifierIsValid = emailLogin
        ? validEmail(identifier)
        : validUsername(identifier);

    let user = null;
    if (identifierIsValid) {
        user = emailLogin
            ? await env.DB.prepare(
                `SELECT password_salt, password_hash
                 FROM users
                 WHERE email = ? COLLATE NOCASE
                 LIMIT 1`
            ).bind(identifier).first()
            : await env.DB.prepare(
                `SELECT password_salt, password_hash
                 FROM users
                 WHERE username = ?
                 LIMIT 1`
            ).bind(identifier).first();
    }

    // Always return KDF work for unknown/invalid identifiers so this endpoint
    // does not directly disclose whether an account exists.
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
    const rawIdentifier = String(
        body.identifier ??
        body.username ??
        '',
    ).trim().toLowerCase();

    const emailLogin = rawIdentifier.includes('@');
    const identifier = emailLogin
        ? normalizeEmail(rawIdentifier)
        : normalizeUsername(rawIdentifier);

    await enforceRateLimit(
        request,
        env,
        'login',
        12,
        1000 * 60 * 10,
        identifier,
    );

    const identifierIsValid = emailLogin
        ? validEmail(identifier)
        : validUsername(identifier);

    if (!identifierIsValid) {
        await recordFailedLoginV85(env,request,identifier); return fail('Invalid username or password.', 401);
    }

    const passwordVerifier = body.passwordVerifier ?? '';
    const user = emailLogin
        ? await env.DB.prepare(
            `SELECT *
             FROM users
             WHERE email = ? COLLATE NOCASE
             LIMIT 1`
        ).bind(identifier).first()
        : await env.DB.prepare(
            `SELECT *
             FROM users
             WHERE username = ?
             LIMIT 1`
        ).bind(identifier).first();

    if (!user) {
        await recordFailedLoginV85(env,request,identifier); return fail('Invalid username or password.', 401);
    }

    const validPassword = await verifyPasswordVerifier(
        user,
        passwordVerifier,
        env,
    );

    if (!validPassword) {
        await recordFailedLoginV85(env,request,identifier); return fail('Invalid username or password.', 401);
    }

    const ban = await activePlatformBan(
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
            identifier,
        );

        const validTotp = await verifyTotp(
            user.totp_secret,
            twoFactorCode,
        );
        const validRecovery = validTotp
            ? false
            : await useRecoveryCode(
                env,
                user.id,
                twoFactorCode,
            );

        if (!validTotp && !validRecovery) {
            return fail(
                'Invalid authenticator or recovery code.',
                401,
            );
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

function renderSpacesCodeEmailV76({ kind, code, expiresMinutes = 10 }) {
    const variant = String(kind || 'verification');
    const copy = variant === 'invite'
        ? { eyebrow: 'INVITE CODE', heading: 'Confirm your Spaces invite', intro: 'Use this code to continue setting up your Spaces account.' }
        : variant === 'signin'
            ? { eyebrow: 'SIGN-IN CODE', heading: 'Sign in to Spaces', intro: 'Use this one-time code to finish signing in.' }
            : variant === 'security'
                ? { eyebrow: 'CODE REQUESTED', heading: 'Confirm your security action', intro: 'Use this code to confirm the security change you requested.' }
                : { eyebrow: 'EMAIL VERIFICATION', heading: 'Verify your Spaces email', intro: 'Use this code to verify the email address on your Spaces account.' };
    const subjectPrefix = variant === 'invite' ? 'Your Spaces invite code' : variant === 'signin' ? 'Your Spaces sign-in code' : 'Your Spaces verification code';
    const subject = `${subjectPrefix}: ${code}`;
    const text = [
        copy.eyebrow,
        '',
        copy.heading,
        copy.intro,
        '',
        String(code),
        '',
        `Expires in ${expiresMinutes} minutes.`,
        'Never share this code with anyone. Spaces Support will never ask you for it.',
        'If you did not request this, you can safely ignore this email.',
        '',
        'Spaces by Spagotei',
    ].join('\n');
    const html = `<!doctype html><html><body style="margin:0;background:#09080d;color:#f4f1f7;font-family:Inter,Segoe UI,Arial,sans-serif"><div style="display:none;max-height:0;overflow:hidden;opacity:0">${copy.heading} · code ${code}</div><table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#09080d;padding:28px 12px"><tr><td align="center"><table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:560px;background:#100e15;border:1px solid #26202d;border-radius:18px;overflow:hidden"><tr><td style="padding:28px 30px 12px"><div style="display:inline-block;width:30px;height:30px;line-height:30px;text-align:center;border-radius:9px;background:#8b6ca8;color:white;font-weight:800">S</div><span style="margin-left:10px;font-size:15px;font-weight:800;letter-spacing:.06em;color:#f5eff9">SPACES</span></td></tr><tr><td style="padding:8px 30px 30px"><div style="font-size:10px;font-weight:800;letter-spacing:.16em;color:#a88abd">${copy.eyebrow}</div><h1 style="margin:10px 0 8px;font-size:24px;line-height:1.25;color:#faf7fc">${copy.heading}</h1><p style="margin:0 0 22px;color:#b9b0bf;font-size:14px;line-height:1.6">${copy.intro}</p><div style="border:1px solid #392d43;background:#0b0a0f;border-radius:14px;padding:21px 16px;text-align:center"><div style="font-size:10px;letter-spacing:.14em;color:#817788;margin-bottom:9px">YOUR CODE</div><div style="font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:34px;line-height:1.1;letter-spacing:8px;font-weight:800;color:#ffffff;user-select:all">${code}</div><div style="font-size:11px;color:#776f7e;margin-top:10px">Select or copy this code · Expires in ${expiresMinutes} minutes</div></div><p style="margin:20px 0 0;color:#8e8495;font-size:12px;line-height:1.6">Never share this code with anyone. Spaces Support will never ask you for it.</p><p style="margin:7px 0 0;color:#706878;font-size:12px;line-height:1.6">If you did not request this, you can safely ignore this email.</p></td></tr><tr><td style="border-top:1px solid #211c26;padding:16px 30px;color:#625a69;font-size:11px">Spaces by Spagotei</td></tr></table></td></tr></table></body></html>`;
    return { subject, text, html };
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
        const messageV76 = renderSpacesCodeEmailV76({ kind: 'verification', code, expiresMinutes: Math.max(1, Math.round(EMAIL_CODE_TTL_MS / 60000)) });
        await env.EMAIL.send({
            to: email,
            from: { email: sender, name: 'Spaces' },
            replyTo: String(env.SPACES_EMAIL_REPLY_TO ?? '').trim() || sender,
            subject: messageV76.subject,
            text: messageV76.text,
            html: messageV76.html,
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

    // SPACES_V77_7_AUTHY_BRAND: use a unique issuer so Authy does not confuse Spaces with another service.
    const SPACES_TOTP_ISSUER_V777 = 'Spaces by Spagotei';
    const label = encodeURIComponent(`${SPACES_TOTP_ISSUER_V777}:@${fresh.username}`);
    const issuer = encodeURIComponent(SPACES_TOTP_ISSUER_V777);
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


function directPreferencePayload(row) {
    return {
        pinnedAt: row?.pinned_at ? Number(row.pinned_at) : null,
        mutedUntil: row?.muted_until ? Number(row.muted_until) : null,
        closedAt: row?.closed_at ? Number(row.closed_at) : null,
    };
}

async function directThreadPreference(env, userId, threadKind, threadId) {
    const row = await env.DB.prepare(
        `SELECT pinned_at, muted_until, closed_at
         FROM direct_thread_preferences
         WHERE user_id = ?
           AND thread_kind = ?
           AND thread_id = ?
         LIMIT 1`
    ).bind(userId, threadKind, threadId).first();

    return directPreferencePayload(row);
}

function directThreadVisible(preference, lastMessageAt) {
    if (!preference.closedAt) return true;
    return Boolean(lastMessageAt && Number(lastMessageAt) > Number(preference.closedAt));
}

function directThreadSort(left, right) {
    const leftPinned = Number(left.pinnedAt ?? 0);
    const rightPinned = Number(right.pinnedAt ?? 0);
    if (leftPinned !== rightPinned) return rightPinned - leftPinned;

    const leftTime = Number(left.lastMessageAt ?? left.updatedAt ?? left.createdAt ?? 0);
    const rightTime = Number(right.lastMessageAt ?? right.updatedAt ?? right.createdAt ?? 0);
    return rightTime - leftTime;
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
        presence: publicVisiblePresence(user.presence_status, user.updated_at),
        customStatus: String(user.custom_status ?? ''),
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
    const preference = await directThreadPreference(env, currentUserId, 'dm', row.id);
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
        ...preference,
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
        const payload = await directGroupPayload(env, row, userId);
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

async function directGroupPayload(env, row, currentUserId = null) {
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
    const preference = currentUserId
        ? await directThreadPreference(env, currentUserId, 'group', row.id)
        : { pinnedAt: null, mutedUntil: null, closedAt: null };
    return {
        id: row.id,
        name: row.name,
        ownerUserId: row.owner_user_id,
        members,
        createdAt: Number(row.created_at ?? 0),
        updatedAt: Number(row.updated_at ?? 0),
        lastMessage: last?.body ?? null,
        lastMessageAt: last ? Number(last.created_at ?? 0) : null,
        ...preference,
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
    if (memberUserIds.length > 19) return fail('Group chats support up to 20 members total.', 400);

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
    return json(await directGroupPayload(env, row, auth.user.id), 201);
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
    await upsertNotificationReadCursorV72(env, auth.user.id, 'group', groupId, Date.now());
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
    const v77GroupRestriction = auth.user.platform_role === 'creator' ? null : (await activeSupportRestrictionV77(env, 'user', auth.user.id, 'direct_messages') || await activeSupportRestrictionV77(env, 'user', auth.user.id, 'send_messages'));
    if (v77GroupRestriction) return fail('Your account is currently view-only for group messages.', 403);
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

// SPACES_DIRECT_GROUP_INVITE_V67
async function addDirectGroupMemberV67(request, env, groupId) {
    const auth = await requireUser(request, env);
    if ('response' in auth) return auth.response;

    const group = await directGroupForUser(env, groupId, auth.user.id);
    if (!group) return fail('Group chat not found.', 404);

    const body = await readJson(request);
    const userId = String(body.userId ?? '').trim();

    if (!userId || userId === auth.user.id) {
        return fail('Choose another Spaces user to invite.', 400);
    }

    const target = await env.DB.prepare(
        `SELECT id FROM users WHERE id = ? LIMIT 1`
    ).bind(userId).first();

    if (!target) return fail('That Spaces user was not found.', 404);

    const existing = await env.DB.prepare(
        `SELECT 1
         FROM direct_group_members
         WHERE group_id = ? AND user_id = ?
         LIMIT 1`
    ).bind(groupId, userId).first();

    if (existing) {
        const current = await env.DB.prepare(
            `SELECT * FROM direct_groups WHERE id = ? LIMIT 1`
        ).bind(groupId).first();
        return json(await directGroupPayload(env, current, auth.user.id));
    }

    const blocked = await env.DB.prepare(
        `SELECT 1
         FROM user_blocks
         WHERE (blocker_user_id = ? AND blocked_user_id = ?)
            OR (blocker_user_id = ? AND blocked_user_id = ?)
         LIMIT 1`
    ).bind(auth.user.id, userId, userId, auth.user.id).first();

    if (blocked) {
        return fail('You cannot invite this account while either account has the other blocked.', 403);
    }

    const low = auth.user.id < userId ? auth.user.id : userId;
    const high = auth.user.id < userId ? userId : auth.user.id;

    const friendship = await env.DB.prepare(
        `SELECT id
         FROM direct_conversations
         WHERE user_low_id = ?
           AND user_high_id = ?
           AND status = 'accepted'
         LIMIT 1`
    ).bind(low, high).first();

    if (!friendship) {
        return fail('You can only invite an accepted friend to a group DM.', 403);
    }

    const memberCount = await env.DB.prepare('SELECT COUNT(*) AS n FROM direct_group_members WHERE group_id=?').bind(groupId).first();
    if (Number(memberCount?.n ?? 0) >= 20) return fail('This group DM is full (20 members).',400);
    const now = Date.now();

    await env.DB.prepare(
        `INSERT INTO direct_group_members (group_id, user_id, joined_at, added_by)
         SELECT ?, ?, ?, ? WHERE (SELECT COUNT(*) FROM direct_group_members WHERE group_id = ?) < 20
         ON CONFLICT(group_id, user_id) DO NOTHING`
    ).bind(groupId, userId, now, auth.user.id, groupId).run();

    await env.DB.prepare(
        `UPDATE direct_groups SET updated_at = ? WHERE id = ?`
    ).bind(now, groupId).run();

    const updated = await env.DB.prepare(
        `SELECT * FROM direct_groups WHERE id = ? LIMIT 1`
    ).bind(groupId).first();

    return json(await directGroupPayload(env, updated, auth.user.id));
}


async function getDirectCenter(request, env) {
    const auth = await requireUser(request, env);
    if ('response' in auth) return auth.response;

    const result = await env.DB.prepare(`SELECT * FROM direct_conversations
      WHERE user_low_id = ? OR user_high_id = ?
      ORDER BY updated_at DESC LIMIT 200`).bind(auth.user.id, auth.user.id).all();

    const conversations = [];
    const friends = [];
    const incomingRequests = [];
    const outgoingRequests = [];

    for (const row of result.results ?? []) {
        const item = await directConversationPayload(env, row, auth.user.id);
        if (!item) continue;
        if (item.status === 'accepted') {
            // Friendship exists even when its DM thread is closed.
            friends.push(item);
            if (directThreadVisible(item, item.lastMessageAt)) conversations.push(item);
        } else if (item.status === 'pending' && item.requestedByMe) {
            outgoingRequests.push(item);
        } else if (item.status === 'pending') {
            incomingRequests.push(item);
        }
    }

    conversations.sort(directThreadSort);

    const groups = (await directGroupsForUser(env, auth.user.id))
        .filter(item => directThreadVisible(item, item.lastMessageAt))
        .sort(directThreadSort);

    const supportLast = await env.DB.prepare(
        `SELECT body, subject, created_at
         FROM support_messages
         WHERE recipient_user_id = ? OR sender_user_id = ?
         ORDER BY created_at DESC
         LIMIT 1`
    ).bind(auth.user.id, auth.user.id).first();

    let supportThread = null;
    if (supportLast) {
        const supportPreference =
            await directThreadPreference(env, auth.user.id, 'support', 'support');

        if (directThreadVisible(supportPreference, supportLast.created_at)) {
            const unread = await env.DB.prepare(
                `SELECT COUNT(*) AS count
                 FROM support_messages
                 WHERE recipient_user_id = ?
                   AND read_at IS NULL`
            ).bind(auth.user.id).first();

            supportThread = {
                id: 'support',
                title: 'Support Tickets',
                lastMessage: supportLast.body ?? supportLast.subject ?? 'Support message',
                lastMessageAt: Number(supportLast.created_at ?? 0),
                unreadCount: Number(unread?.count ?? 0),
                ...supportPreference,
            };
        }
    }

    return json({
        friends,
        conversations,
        incomingRequests,
        outgoingRequests,
        groups,
        supportThread,
    });
}

async function updateDirectThreadPreference(request, env, threadKind, threadId) {
    const auth = await requireUser(request, env);
    if ('response' in auth) return auth.response;

    if (!['dm', 'group', 'support'].includes(threadKind)) {
        return fail('Unknown direct-message thread type.', 400);
    }

    if (threadKind === 'dm') {
        const conversation = await directConversationForUser(env, threadId, auth.user.id);
        if (!conversation || conversation.status !== 'accepted') {
            return fail('Direct conversation not found.', 404);
        }
    } else if (threadKind === 'group') {
        const group = await directGroupForUser(env, threadId, auth.user.id);
        if (!group) return fail('Group chat not found.', 404);
    } else if (threadId !== 'support') {
        return fail('Support conversation not found.', 404);
    }

    const current =
        await directThreadPreference(env, auth.user.id, threadKind, threadId);
    const body = await readJson(request);
    const now = Date.now();

    let pinnedAt = current.pinnedAt;
    let mutedUntil = current.mutedUntil;
    let closedAt = current.closedAt;

    if (typeof body.pinned === 'boolean') {
        pinnedAt = body.pinned ? now : null;
    }

    if (body.unmute === true) {
        mutedUntil = null;
    } else if (body.muteMinutes !== undefined) {
        const muteMinutes = Number(body.muteMinutes);
        if (muteMinutes === -1) {
            mutedUntil = 253402300799000;
        } else if (Number.isFinite(muteMinutes) && muteMinutes > 0) {
            mutedUntil = now + Math.min(muteMinutes, 60 * 24 * 365) * 60_000;
        } else {
            return fail('Choose a valid mute duration.', 400);
        }
    }

    if (typeof body.closed === 'boolean') {
        closedAt = body.closed ? now : null;
        if (body.closed) pinnedAt = null;
    }

    await env.DB.prepare(
        `INSERT INTO direct_thread_preferences
          (user_id, thread_kind, thread_id, pinned_at, muted_until, closed_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(user_id, thread_kind, thread_id) DO UPDATE SET
           pinned_at = excluded.pinned_at,
           muted_until = excluded.muted_until,
           closed_at = excluded.closed_at,
           updated_at = excluded.updated_at`
    ).bind(
        auth.user.id,
        threadKind,
        threadId,
        pinnedAt,
        mutedUntil,
        closedAt,
        now,
    ).run();

    return json({
        threadKind,
        threadId,
        pinnedAt,
        mutedUntil,
        closedAt,
    });
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
    if (await accountBlockExists(env, auth.user.id, target.id)) {
        return fail('Friend requests are unavailable while either account is blocked.', 403);
    }

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
        if (existing.status === 'blocked') {
            await env.DB.prepare(
                `UPDATE direct_conversations
                 SET status = 'pending',
                     requested_by = ?,
                     source_space_id = ?,
                     updated_at = ?
                 WHERE id = ?`
            ).bind(auth.user.id, sourceWorkspaceId, now, existing.id).run();
            const reopened = await env.DB.prepare(
                `SELECT * FROM direct_conversations WHERE id = ? LIMIT 1`
            ).bind(existing.id).first();
            return json(await directConversationPayload(env, reopened, auth.user.id));
        }
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
    const otherUserId = row.user_low_id === auth.user.id ? row.user_high_id : row.user_low_id;
    if (await accountBlockExists(env, auth.user.id, otherUserId)) {
        return fail('This friend request cannot be accepted while either account is blocked.', 403);
    }
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
    await upsertNotificationReadCursorV72(env, auth.user.id, 'dm', conversationId, Date.now());
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
    const v77DirectRestriction = auth.user.platform_role === 'creator' ? null : (await activeSupportRestrictionV77(env, 'user', auth.user.id, 'direct_messages') || await activeSupportRestrictionV77(env, 'user', auth.user.id, 'send_messages'));
    if (v77DirectRestriction) return fail('Your account is currently view-only for direct messages.', 403);
    await enforceRateLimit(request, env, 'direct-message', 300, 1000 * 60 * 60, auth.user.id);
    const row = await directConversationForUser(env, conversationId, auth.user.id);
    if (!row) return fail('Direct conversation not found.', 404);
    const otherUserId = row.user_low_id === auth.user.id ? row.user_high_id : row.user_low_id;
    if (await accountBlockExists(env, auth.user.id, otherUserId)) {
        return fail('Direct messages are unavailable while either account is blocked.', 403);
    }
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

async function directPinnedThreadAccess(env, userId, kind, threadId) {
    if (kind === 'dm') {
        const row = await directConversationForUser(env, threadId, userId);
        return row && row.status === 'accepted' ? row : null;
    }

    if (kind === 'group') {
        const row = await env.DB.prepare(
            `SELECT g.id
             FROM direct_groups g
             JOIN direct_group_members gm ON gm.group_id = g.id
             WHERE g.id = ? AND gm.user_id = ?
             LIMIT 1`
        ).bind(threadId, userId).first();
        return row ?? null;
    }

    return null;
}

async function listDirectPinnedMessages(request, env, kind, threadId) {
    const auth = await requireUser(request, env);
    if ('response' in auth) return auth.response;

    const access = await directPinnedThreadAccess(env, auth.user.id, kind, threadId);
    if (!access) return fail('Direct thread not found.', 404);

    const table = kind === 'dm' ? 'direct_messages' : 'direct_group_messages';
    const threadColumn = kind === 'dm' ? 'conversation_id' : 'group_id';

    const result = await env.DB.prepare(
        `SELECT
           p.message_id,
           p.pinned_by,
           p.pinned_at,
           m.sender_user_id,
           m.body,
           m.created_at,
           u.display_name AS sender_name
         FROM direct_message_pins p
         JOIN ${table} m ON m.id = p.message_id
         JOIN users u ON u.id = m.sender_user_id
         WHERE p.thread_kind = ?
           AND p.thread_id = ?
           AND m.${threadColumn} = ?
         ORDER BY p.pinned_at DESC
         LIMIT 100`
    ).bind(kind, threadId, threadId).all();

    return json((result.results ?? []).map(row => ({
        id: row.message_id,
        senderUserId: row.sender_user_id,
        senderName: row.sender_name,
        body: row.body,
        createdAt: Number(row.created_at ?? 0),
        pinnedBy: row.pinned_by,
        pinnedAt: Number(row.pinned_at ?? 0),
    })));
}

async function updateDirectPinnedMessage(request, env, kind, threadId, messageId, pin) {
    const auth = await requireUser(request, env);
    if ('response' in auth) return auth.response;

    const access = await directPinnedThreadAccess(env, auth.user.id, kind, threadId);
    if (!access) return fail('Direct thread not found.', 404);

    const table = kind === 'dm' ? 'direct_messages' : 'direct_group_messages';
    const threadColumn = kind === 'dm' ? 'conversation_id' : 'group_id';
    const message = await env.DB.prepare(
        `SELECT id FROM ${table}
         WHERE id = ? AND ${threadColumn} = ?
         LIMIT 1`
    ).bind(messageId, threadId).first();

    if (!message) return fail('Message not found in this thread.', 404);

    if (pin) {
        const now = Date.now();
        await env.DB.prepare(
            `INSERT INTO direct_message_pins
              (thread_kind, thread_id, message_id, pinned_by, pinned_at)
             VALUES (?, ?, ?, ?, ?)
             ON CONFLICT(thread_kind, thread_id, message_id)
             DO UPDATE SET pinned_by = excluded.pinned_by, pinned_at = excluded.pinned_at`
        ).bind(kind, threadId, messageId, auth.user.id, now).run();

        return json({ messageId, pinnedAt: now });
    }

    await env.DB.prepare(
        `DELETE FROM direct_message_pins
         WHERE thread_kind = ?
           AND thread_id = ?
           AND message_id = ?`
    ).bind(kind, threadId, messageId).run();

    return new Response(null, { status: 204, headers: corsHeaders() });
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
    return json({
        ...publicProfile(user),
        presence: publicVisiblePresence(user.presence_status, user.updated_at),
    });
}

function normalizePresencePreference(value) {
    const normalized = String(value ?? 'online').toLowerCase();
    return ['online', 'idle', 'dnd', 'invisible'].includes(normalized)
        ? normalized
        : 'online';
}

// SPACES_PRESENCE_TTL_V65
const PRESENCE_HEARTBEAT_TTL_MS = 70_000;

function publicVisiblePresence(value, lastSeenAt = null) {
    const normalized = normalizePresencePreference(value);
    if (normalized === 'invisible') return 'offline';

    // A status preference is not proof that an app/device is still connected.
    // Only enforce liveness when the caller supplies the user's last heartbeat.
    if (lastSeenAt !== null && lastSeenAt !== undefined) {
        const seenAt = Number(lastSeenAt);
        if (!Number.isFinite(seenAt) || seenAt <= 0 || Date.now() - seenAt > PRESENCE_HEARTBEAT_TTL_MS) {
            return 'offline';
        }
    }

    return normalized;
}

function memberPresence(value, lastSeenAt) {
    const visible = publicVisiblePresence(value, lastSeenAt);
    return visible === 'idle' ? 'away' : visible;
}

async function updateMyPresence(request, env) {
    const auth = await requireUser(request, env);
    if ('response' in auth) return auth.response;

    const body = await readJson(request);
    const presence = normalizePresencePreference(body.presence);
    const customStatus = String(body.customStatus ?? '').trim().slice(0, 128);
    const now = Date.now();

    await env.DB.prepare(
        `UPDATE users
         SET presence_status = ?,
             custom_status = ?,
             updated_at = ?
         WHERE id = ?`
    ).bind(presence, customStatus, now, auth.user.id).run();

    const updated = await env.DB.prepare(
        `SELECT * FROM users WHERE id = ? LIMIT 1`
    ).bind(auth.user.id).first();

    return updated ? json(publicProfile(updated)) : fail('Account not found.', 404);
}

async function accountBlockExists(env, leftUserId, rightUserId) {
    const row = await env.DB.prepare(
        `SELECT blocker_user_id, blocked_user_id
         FROM user_blocks
         WHERE (blocker_user_id = ? AND blocked_user_id = ?)
            OR (blocker_user_id = ? AND blocked_user_id = ?)
         LIMIT 1`
    ).bind(leftUserId, rightUserId, rightUserId, leftUserId).first();

    return Boolean(row);
}

async function listBlockedUsers(request, env) {
    const auth = await requireUser(request, env);
    if ('response' in auth) return auth.response;

    const result = await env.DB.prepare(
        `SELECT u.*
         FROM user_blocks b
         JOIN users u ON u.id = b.blocked_user_id
         WHERE b.blocker_user_id = ?
         ORDER BY b.created_at DESC`
    ).bind(auth.user.id).all();

    return json((result.results ?? []).map(user => ({
        ...publicProfile(user),
        presence: publicVisiblePresence(user.presence_status, user.updated_at),
    })));
}

async function blockAccountUser(request, env, userId) {
    const auth = await requireUser(request, env);
    if ('response' in auth) return auth.response;

    if (!userId || userId === auth.user.id) {
        return fail('You cannot block your own account.', 400);
    }

    const target = await env.DB.prepare(
        `SELECT id FROM users WHERE id = ? LIMIT 1`
    ).bind(userId).first();

    if (!target) return fail('That Spaces user was not found.', 404);

    const now = Date.now();

    await env.DB.prepare(
        `INSERT INTO user_blocks (blocker_user_id, blocked_user_id, created_at)
         VALUES (?, ?, ?)
         ON CONFLICT(blocker_user_id, blocked_user_id)
         DO UPDATE SET created_at = excluded.created_at`
    ).bind(auth.user.id, userId, now).run();

    const [low, high] = directPair(auth.user.id, userId);
    await env.DB.prepare(
        `UPDATE direct_conversations
         SET status = 'blocked',
             updated_at = ?
         WHERE user_low_id = ?
           AND user_high_id = ?`
    ).bind(now, low, high).run();

    return new Response(null, { status: 204, headers: corsHeaders() });
}

async function unblockAccountUser(request, env, userId) {
    const auth = await requireUser(request, env);
    if ('response' in auth) return auth.response;

    await env.DB.prepare(
        `DELETE FROM user_blocks
         WHERE blocker_user_id = ?
           AND blocked_user_id = ?`
    ).bind(auth.user.id, userId).run();

    return new Response(null, { status: 204, headers: corsHeaders() });
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


async function notificationReadCursorMapV72(env, userId) {
  const result = await env.DB.prepare(
    `SELECT scope_kind, scope_id, read_at
     FROM notification_read_cursors
     WHERE user_id = ?`
  ).bind(userId).all();
  const map = new Map();
  for (const row of result.results ?? []) {
    map.set(`${row.scope_kind}:${row.scope_id}`, Number(row.read_at ?? 0));
  }
  return map;
}

function notificationReadAtV72(map, kind, id) {
  return Number(map.get(`${kind}:${id}`) ?? 0);
}

async function upsertNotificationReadCursorV72(env, userId, scopeKind, scopeId, readAt = Date.now()) {
  await env.DB.prepare(
    `INSERT INTO notification_read_cursors (user_id, scope_kind, scope_id, read_at)
     VALUES (?, ?, ?, ?)
     ON CONFLICT(user_id, scope_kind, scope_id) DO UPDATE SET
       read_at = MAX(notification_read_cursors.read_at, excluded.read_at)`
  ).bind(userId, scopeKind, scopeId, readAt).run();
}

async function notificationScopeAccessV72(request, env, scopeKind, scopeId, { typing = false } = {}) {
  const auth = await requireUser(request, env);
  if ('response' in auth) return auth;

  if (scopeKind === 'all') return { auth };

  if (scopeKind === 'channel') {
    const channel = await env.DB.prepare(
      `SELECT id, space_id, post_min_role, kind
       FROM channels WHERE id = ? LIMIT 1`
    ).bind(scopeId).first();
    if (!channel) return { response: fail('Channel not found.', 404) };
    const access = await workspaceAccessForUser(env, auth.user.id, channel.space_id);
    if (!access) return { response: fail('You are not a member of that Space.', 403) };
    const rowsResult = await env.DB.prepare(
      `SELECT * FROM channel_permission_overwrites WHERE space_id = ? AND channel_id = ?`
    ).bind(channel.space_id, channel.id).all();
    const rows = rowsResult.results ?? [];
    if (channelPermissionDecision(access, rows, 'view_channel') === 'deny') {
      return { response: fail('You cannot view that channel.', 403) };
    }
    if (typing) {
      const postRequired = normalizeChannelPermission(channel.post_min_role, channel.kind === 'announcement' ? 'admin' : 'contributor');
      const baseSend = postRequired !== 'disabled' &&
        (roleMeetsPermission(access.role, postRequired) || accessHas(access, 'send_messages'));
      if (!channelPermissionAllowed(access, rows, 'send_messages', baseSend)) {
        return { response: fail('You cannot send messages in that channel.', 403) };
      }
    }
    return { auth, access, workspaceId: channel.space_id };
  }

  if (scopeKind === 'dm') {
    const row = await directConversationForUser(env, scopeId, auth.user.id);
    if (!row || row.status !== 'accepted') return { response: fail('Direct conversation not found.', 404) };
    return { auth };
  }

  if (scopeKind === 'group') {
    const row = await directGroupForUser(env, scopeId, auth.user.id);
    if (!row) return { response: fail('Group chat not found.', 404) };
    return { auth };
  }

  if (scopeKind === 'support') {
    if (scopeId !== 'support') return { response: fail('Support conversation not found.', 404) };
    return { auth };
  }

  if (scopeKind === 'friend_request') {
    if (scopeId !== 'requests') return { response: fail('Friend request scope not found.', 404) };
    return { auth };
  }

  return { response: fail('Unknown notification scope.', 400) };
}

async function markNotificationReadV72(request, env) {
  const body = await readJson(request);
  const scopeKind = String(body.scopeKind ?? '').trim();
  const scopeId = String(body.scopeId ?? '').trim();
  if (!scopeKind || !scopeId) return fail('Notification scope is required.', 400);
  const access = await notificationScopeAccessV72(request, env, scopeKind, scopeId);
  if ('response' in access) return access.response;
  const readAtInput = Number(body.readAt ?? Date.now());
  const readAt = Number.isFinite(readAtInput) ? Math.min(readAtInput, Date.now() + 60_000) : Date.now();
  await upsertNotificationReadCursorV72(env, access.auth.user.id, scopeKind, scopeId, readAt);
  if (scopeKind === 'support') {
    await env.DB.prepare(
      `UPDATE support_messages
       SET read_at = COALESCE(read_at, ?)
       WHERE recipient_user_id = ? AND read_at IS NULL AND created_at <= ?`
    ).bind(readAt, access.auth.user.id, readAt).run();
  }
  return json({ scopeKind, scopeId, readAt });
}

async function typingPresenceV72(request, env, scopeKind, scopeId) {
  if (!['channel', 'dm', 'group', 'support'].includes(scopeKind)) {
    return fail('Unknown typing scope.', 400);
  }
  const access = await notificationScopeAccessV72(request, env, scopeKind, scopeId, { typing: true });
  if ('response' in access) return access.response;
  const now = Date.now();

  if (request.method === 'GET') {
    const result = await env.DB.prepare(
      `SELECT tp.user_id, tp.updated_at, u.display_name
       FROM typing_presence tp
       JOIN users u ON u.id = tp.user_id
       WHERE tp.scope_kind = ?
         AND tp.scope_id = ?
         AND tp.user_id <> ?
         AND tp.updated_at > ?
       ORDER BY tp.updated_at DESC
       LIMIT 12`
    ).bind(scopeKind, scopeId, access.auth.user.id, now - 5500).all();
    return json((result.results ?? []).map(row => ({
      userId: row.user_id,
      displayName: row.display_name || 'Someone',
      updatedAt: Number(row.updated_at ?? 0),
    })));
  }

  if (request.method === 'DELETE') {
    await env.DB.prepare(
      `DELETE FROM typing_presence WHERE user_id = ? AND scope_kind = ? AND scope_id = ?`
    ).bind(access.auth.user.id, scopeKind, scopeId).run();
    return new Response(null, { status: 204, headers: corsHeaders() });
  }

  await env.DB.prepare(
    `INSERT INTO typing_presence (user_id, scope_kind, scope_id, updated_at)
     VALUES (?, ?, ?, ?)
     ON CONFLICT(user_id, scope_kind, scope_id) DO UPDATE SET updated_at = excluded.updated_at`
  ).bind(access.auth.user.id, scopeKind, scopeId, now).run();
  await env.DB.prepare(`DELETE FROM typing_presence WHERE updated_at < ?`).bind(now - 30_000).run();
  return json({ ok: true, updatedAt: now });
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

    const readCursorsV72 = await notificationReadCursorMapV72(env, auth.user.id);
    const globalReadV72 = notificationReadAtV72(readCursorsV72, 'all', 'all');

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

    const blockedRows = await env.DB.prepare(
        `SELECT blocked_user_id
         FROM user_blocks
         WHERE blocker_user_id = ?`
    ).bind(auth.user.id).all();
    const blockedUserIds = new Set(
        (blockedRows.results ?? []).map(row => String(row.blocked_user_id)),
    );

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
    const mutedThreadKeys = new Set();
    try {
        const mutedRows = await env.DB.prepare(
            `SELECT thread_kind, thread_id
             FROM direct_thread_preferences
             WHERE user_id = ?
               AND muted_until IS NOT NULL
               AND muted_until > ?`
        ).bind(auth.user.id, Date.now()).all();
        for (const row of mutedRows.results ?? []) {
            mutedThreadKeys.add(`${row.thread_kind}:${row.thread_id}`);
        }
    } catch (caught) {
        console.warn('Direct mute preferences unavailable.', caught);
    }
    const accessBySpace = new Map();
    const overwritesBySpace = new Map();

    for (const row of result.results ?? []) {
        if (Number(row.created_at ?? 0) <= Math.max(globalReadV72, notificationReadAtV72(readCursorsV72, 'channel', row.channel_id))) continue;
        if (blockedUserIds.has(String(row.author_id))) continue;
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
            `SELECT m.id, m.subject, m.body, m.message_kind, m.created_at, sender.display_name AS sender_name
             FROM support_messages m
             JOIN users sender ON sender.id = m.sender_user_id
             WHERE m.recipient_user_id = ? AND m.created_at > ? AND m.ticket_id IS NULL
             ORDER BY m.created_at DESC LIMIT 80`
        ).bind(auth.user.id, since).all();
        for (const row of supportRows.results ?? []) {
            if (Number(row.created_at ?? 0) <= Math.max(globalReadV72, notificationReadAtV72(readCursorsV72, 'support', 'support'))) continue;
            if (mutedThreadKeys.has('support:support')) continue;
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
                mentionLabel: row.message_kind === 'reply' ? 'Support reply' : 'Support DM',
            });
        }
    } catch (caught) {
        console.warn('Support DM notifications unavailable.', caught);
    }

    try {
        const directRows = await env.DB.prepare(`SELECT
             dm.id, dm.conversation_id, dm.sender_user_id, dm.body, dm.created_at,
             sender.display_name AS sender_name
           FROM direct_messages dm
           JOIN direct_conversations dc ON dc.id = dm.conversation_id
           JOIN users sender ON sender.id = dm.sender_user_id
           WHERE dc.status = 'accepted'
             AND (dc.user_low_id = ? OR dc.user_high_id = ?)
             AND dm.sender_user_id <> ?
             AND dm.created_at > ?
           ORDER BY dm.created_at DESC LIMIT 100`)
            .bind(auth.user.id, auth.user.id, auth.user.id, since).all();
        for (const row of directRows.results ?? []) {
            if (Number(row.created_at ?? 0) <= Math.max(globalReadV72, notificationReadAtV72(readCursorsV72, 'dm', row.conversation_id))) continue;
            if (blockedUserIds.has(String(row.sender_user_id))) continue;
            if (mutedThreadKeys.has(`dm:${row.conversation_id}`)) continue;
            items.push({
                id: `direct-${row.id}`,
                workspaceId: '__direct__',
                workspaceName: 'Direct Messages',
                channelId: row.conversation_id,
                channelName: 'Direct Message',
                authorName: row.sender_name || 'Friend',
                preview: String(row.body ?? '').slice(0, 180),
                createdAt: Number(row.created_at ?? 0),
                kind: 'direct',
                mentionLabel: 'Direct message',
                conversationId: row.conversation_id,
            });
        }

        const groupRows = await env.DB.prepare(`SELECT
             gm.id, gm.group_id, gm.sender_user_id, gm.body, gm.created_at,
             g.name AS group_name, sender.display_name AS sender_name
           FROM direct_group_messages gm
           JOIN direct_group_members mine ON mine.group_id = gm.group_id AND mine.user_id = ?
           JOIN direct_groups g ON g.id = gm.group_id
           JOIN users sender ON sender.id = gm.sender_user_id
           WHERE gm.sender_user_id <> ? AND gm.created_at > ?
           ORDER BY gm.created_at DESC LIMIT 100`)
            .bind(auth.user.id, auth.user.id, since).all();
        for (const row of groupRows.results ?? []) {
            if (Number(row.created_at ?? 0) <= Math.max(globalReadV72, notificationReadAtV72(readCursorsV72, 'group', row.group_id))) continue;
            if (blockedUserIds.has(String(row.sender_user_id))) continue;
            if (mutedThreadKeys.has(`group:${row.group_id}`)) continue;
            items.push({
                id: `group-${row.id}`,
                workspaceId: '__direct__',
                workspaceName: 'Direct Messages',
                channelId: row.group_id,
                channelName: row.group_name || 'Group Chat',
                authorName: row.sender_name || 'Friend',
                preview: String(row.body ?? '').slice(0, 180),
                createdAt: Number(row.created_at ?? 0),
                kind: 'group',
                mentionLabel: 'Group message',
                groupId: row.group_id,
            });
        }

        const requestRows = await env.DB.prepare(`SELECT
             dc.id, dc.updated_at, requester.id AS requester_id, requester.display_name AS requester_name
           FROM direct_conversations dc
           JOIN users requester ON requester.id = dc.requested_by
           WHERE dc.status = 'pending'
             AND dc.requested_by <> ?
             AND (dc.user_low_id = ? OR dc.user_high_id = ?)
             AND dc.updated_at > ?
           ORDER BY dc.updated_at DESC LIMIT 50`)
            .bind(auth.user.id, auth.user.id, auth.user.id, since).all();
        for (const row of requestRows.results ?? []) {
            if (Number(row.updated_at ?? 0) <= Math.max(globalReadV72, notificationReadAtV72(readCursorsV72, 'friend_request', 'requests'))) continue;
            if (blockedUserIds.has(String(row.requester_id))) continue;
            items.push({
                id: `friend-request-${row.id}`,
                workspaceId: '__friends__',
                workspaceName: 'Friends',
                channelId: row.id,
                channelName: 'Requests',
                authorName: row.requester_name || 'Someone',
                preview: `${row.requester_name || 'Someone'} sent you a friend request.`,
                createdAt: Number(row.updated_at ?? 0),
                kind: 'friend_request',
                mentionLabel: 'Friend request',
                conversationId: row.id,
            });
        }
    } catch (caught) {
        console.warn('Direct/friend notifications unavailable.', caught);
    }

    try {
        const commentRows = await env.DB.prepare(`SELECT
             c.id, c.space_id, c.note_id, c.author_id, c.body, c.created_at,
             n.title AS note_title, n.channel_id, n.created_by,
             sp.name AS workspace_name, ch.name AS channel_name,
             u.display_name AS author_name
           FROM note_comments c
           JOIN notes n ON n.id = c.note_id
           JOIN spaces sp ON sp.id = c.space_id
           JOIN channels ch ON ch.id = n.channel_id AND ch.space_id = c.space_id
           JOIN users u ON u.id = c.author_id
           JOIN space_members mine ON mine.space_id = c.space_id AND mine.user_id = ?
           WHERE c.author_id <> ?
             AND c.created_at > ?
             AND c.deleted_at IS NULL
             AND (
               n.created_by = ?
               OR EXISTS (
                 SELECT 1 FROM note_comments mine_comment
                 WHERE mine_comment.note_id = c.note_id
                   AND mine_comment.author_id = ?
                   AND mine_comment.created_at < c.created_at
               )
             )
           ORDER BY c.created_at DESC LIMIT 80`)
          .bind(auth.user.id, auth.user.id, since, auth.user.id, auth.user.id).all();

        for (const row of commentRows.results ?? []) {
            if (Number(row.created_at ?? 0) <= Math.max(globalReadV72, notificationReadAtV72(readCursorsV72, 'channel', row.channel_id))) continue;
            const access = await workspaceAccessForUser(env, auth.user.id, row.space_id);
            if (!access) continue;
            const overwriteRows = await env.DB.prepare(
              `SELECT * FROM channel_permission_overwrites WHERE space_id = ? AND channel_id = ?`
            ).bind(row.space_id, row.channel_id).all();
            if (channelPermissionDecision(access, overwriteRows.results ?? [], 'view_channel') === 'deny') continue;
            items.push({
                id: `comment-${row.id}`,
                workspaceId: row.space_id,
                workspaceName: row.workspace_name,
                channelId: row.channel_id,
                channelName: row.channel_name,
                authorName: row.author_name || 'Member',
                preview: String(row.body ?? '').slice(0, 180),
                createdAt: Number(row.created_at ?? 0),
                kind: 'comment',
                mentionLabel: 'New comment on note',
                noteTitle: row.note_title || 'note',
            });
        }
    } catch (caught) {
        console.warn('Note comment notifications unavailable.', caught);
    }


    try {
        if (isSupportTeamUserV73(auth.user)) {
            const ticketRows = await env.DB.prepare(`SELECT
                m.id,
                m.body,
                m.created_at,
                t.ticket_number,
                t.topic,
                owner.display_name AS owner_name
              FROM support_messages m
              JOIN support_tickets t ON t.id = m.ticket_id
              JOIN users owner ON owner.id = t.user_id
              WHERE m.ticket_id IS NOT NULL
                AND m.sender_user_id = t.user_id
                AND (
                  t.status = 'waiting'
                  OR t.assigned_to = ?
                  OR EXISTS (
                    SELECT 1
                    FROM support_ticket_collaborators c
                    WHERE c.ticket_id = t.id AND c.user_id = ?
                  )
                )
                AND m.created_at > ?
              ORDER BY m.created_at DESC
              LIMIT 80`)
              .bind(auth.user.id, auth.user.id, since)
              .all();

            for (const row of ticketRows.results ?? []) {
                items.push({
                    id: `support-ticket-staff-${row.id}`,
                    workspaceId: SPACES_HUB_ID,
                    workspaceName: 'Spaces Support',
                    channelId: 'spaces-hub-updates',
                    channelName: 'Support Ticket',
                    authorName: row.owner_name || 'Spaces member',
                    preview: `${row.ticket_number} · ${row.topic}: ${row.body}`.slice(0, 180),
                    createdAt: Number(row.created_at ?? 0),
                    kind: 'support',
                    mentionLabel: 'Support ticket',
                    supportTicketNumber: row.ticket_number,
                    supportTicketStaff: true,
                });
            }
        } else {
            const ticketRows = await env.DB.prepare(`SELECT
                m.id,
                m.body,
                m.created_at,
                t.ticket_number,
                t.topic,
                sender.display_name AS sender_name
              FROM support_messages m
              JOIN support_tickets t ON t.id = m.ticket_id
              JOIN users sender ON sender.id = m.sender_user_id
              WHERE m.ticket_id IS NOT NULL
                AND m.recipient_user_id = ?
                AND m.created_at > ?
              ORDER BY m.created_at DESC
              LIMIT 80`)
              .bind(auth.user.id, since)
              .all();

            for (const row of ticketRows.results ?? []) {
                items.push({
                    id: `support-ticket-user-${row.id}`,
                    workspaceId: SPACES_HUB_ID,
                    workspaceName: 'Spaces Support',
                    channelId: 'spaces-hub-updates',
                    channelName: 'Support Ticket',
                    authorName: row.sender_name || 'Spaces Support',
                    preview: `${row.ticket_number} · ${row.topic}: ${row.body}`.slice(0, 180),
                    createdAt: Number(row.created_at ?? 0),
                    kind: 'support',
                    mentionLabel: 'Support reply',
                    supportTicketNumber: row.ticket_number,
                    supportTicketStaff: false,
                });
            }
        }
    } catch (caught) {
        console.warn('Support ticket notifications unavailable.', caught);
    }

    try {
      items.push(...await missedDmNotificationsV85(env, auth.user.id, since, readCursorsV72, globalReadV72, mutedThreadKeys, blockedUserIds));
    } catch (error) { console.warn('Missed-call notices unavailable',error); }
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

    const v77CreateSpacesRestriction = auth.user.platform_role === 'creator' ? null : await activeSupportRestrictionV77(env, 'user', auth.user.id, 'create_spaces');
    if (v77CreateSpacesRestriction) return fail('Your account is restricted from creating Spaces.', 403);

    // v48 restriction enforcement: space_create
    if (auth.user.platform_role !== 'creator') {
        const restriction = await activePlatformRestrictionV48(env, auth.user.id, 'space_create');
        if (restriction) return fail('Your account is restricted from creating Spaces.', 403);
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

    const v77JoinSpacesRestriction = auth.user.platform_role === 'creator' ? null : await activeSupportRestrictionV77(env, 'user', auth.user.id, 'join_spaces');
    if (v77JoinSpacesRestriction) return fail('Your account is restricted from joining Spaces.', 403);

    // v48 restriction enforcement: space_join
    if (auth.user.platform_role !== 'creator') {
        const restriction = await activePlatformRestrictionV48(env, auth.user.id, 'space_join');
        if (restriction) return fail('Your account is restricted from joining Spaces.', 403);
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

    const v77SpaceJoinRestriction = await activeSupportRestrictionV77(env, 'space', invite.space_id, 'join_space');
    if (v77SpaceJoinRestriction) return fail('This Space is temporarily restricted from accepting new joins.', 403);

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

    const v77UserMessageRestriction = access.user.platform_role === 'creator' ? null : await activeSupportRestrictionV77(env, 'user', access.user.id, 'send_messages');
    const v77SpaceMessageRestriction = await activeSupportRestrictionV77(env, 'space', workspaceId, 'send_messages');
    if (v77UserMessageRestriction || v77SpaceMessageRestriction) return fail('Messaging is restricted here. You can still view accessible content.', 403);

    // v48 restriction enforcement: chat
    if (access.user.platform_role !== 'creator') {
        const restriction = await activePlatformRestrictionV48(env, access.user.id, 'chat');
        if (restriction) return fail('Your account is temporarily restricted from sending messages.', 403);
    }

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
    const v77ChannelMessageRestriction = await activeSupportRestrictionV77(env, 'channel', channelId, 'send_messages');
    if (v77ChannelMessageRestriction) return fail('This channel is temporarily locked by Spaces Support.', 403);

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
    const replyToMessageId = String(body.replyToMessageId ?? '').trim() || null;
    if (replyToMessageId) {
        const replyTarget = await env.DB.prepare('SELECT id FROM messages WHERE id = ? AND space_id = ? AND channel_id = ? LIMIT 1').bind(replyToMessageId, workspaceId, channelId).first();
        if (!replyTarget) return fail('Reply target not found in this channel.', 404);
    }
    const attachment = parseChatAttachment(body.attachment);
    if (attachment && access.user.platform_role !== 'creator' && await activeSupportRestrictionV77(env, 'user', access.user.id, 'uploads')) return fail('Your account is restricted from uploading files or media.', 403);
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
           deleted_at, deleted_by, attachment_name, attachment_type, attachment_size, attachment_data, reply_to_message_id)
         VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, NULL, ?, ?, ?, ?, ?)`
    ).bind(
        id, workspaceId, channelId, access.user.id, messageBody, now,
        attachment?.name ?? null,
        attachment?.type ?? null,
        attachment?.size ?? null,
        attachment?.dataUrl ?? null,
        replyToMessageId,
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
        replyToMessageId,
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
    let parentCommentId = String(body.parentCommentId ?? '').trim() || null;
    if (parentCommentId) {
        const parent = await env.DB.prepare('SELECT id, parent_comment_id FROM note_comments WHERE id = ? AND space_id = ? AND note_id = ? LIMIT 1').bind(parentCommentId, workspaceId, noteId).first();
        if (!parent) return fail('Reply target not found for this note.', 404);
        parentCommentId = parent.parent_comment_id || parent.id;
    }
    if (!commentBody || commentBody.length > 1000) return fail('Comment must be 1-1000 characters.');
    const id = crypto.randomUUID();
    const now = Date.now();
    await env.DB.prepare(
        `INSERT INTO note_comments (id, space_id, note_id, author_id, body, created_at, edited_at, deleted_at, deleted_by, parent_comment_id)
         VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, NULL, ?)`
    ).bind(id, workspaceId, noteId, access.user.id, commentBody, now, parentCommentId).run();
    await env.DB.prepare(
        `INSERT INTO audit_logs
          (id, space_id, actor_id, action, target_type, target_id, target_label, reason, metadata_json, created_at)
         VALUES (?, ?, ?, 'comment.created', 'comment', ?, ?, 'Comment added to a shared post.', ?, ?)`
    ).bind(crypto.randomUUID(), workspaceId, access.user.id, id, note.title, JSON.stringify({ noteId }), now).run();
    return json({ id, workspaceId, noteId, authorId: access.user.id,
        authorName: access.user.display_name, authorInitials: String(access.user.display_name || access.user.username || 'M').slice(0,1).toUpperCase(),
        authorAvatarUrl: access.user.avatar_url ?? null, authorUsername: access.user.username ?? '', body: commentBody, createdAt: now, editedAt: null, deletedAt: null, deletedBy: null, parentCommentId }, 201);
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
        authorAvatarUrl: access.user.avatar_url ?? null, authorUsername: access.user.username ?? '', body: commentBody, createdAt: comment.created_at, editedAt: now, deletedAt: null, deletedBy: null, parentCommentId: comment.parent_comment_id ?? null });
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
               public_user_id,
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
            publicUserId:
                auth.user.public_user_id ?? '',
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
            publicUserId:
                reported.public_user_id ?? '',
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
    const moderator = await requireSupportCapability(request, env, 'view_reports');
    if ('response' in moderator) return moderator.response;

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
               r.archived_at,
               r.archived_by,
               u.public_user_id AS current_public_user_id,
               u.username AS current_username,
               reporter_user.public_user_id AS reporter_public_user_id,
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
             LEFT JOIN users reporter_user
               ON reporter_user.id = r.reporter_id
             ORDER BY
               CASE WHEN r.archived_at IS NULL THEN 0 ELSE 1 END,
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

                if (snapshot.reporter) {
                    snapshot.reporter = {
                        ...snapshot.reporter,
                        publicUserId: report.reporter_public_user_id ?? snapshot.reporter.publicUserId ?? '',
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
                        publicUserId:
                            report.current_public_user_id ?? snapshot.reported.publicUserId ?? '',
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
                    archivedAt:
                        report.archived_at ? Number(report.archived_at) : null,
                    archivedBy:
                        report.archived_by ?? null,
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
    const moderator = await requireSupportCapability(request, env, 'reset_identity');
    if ('response' in moderator) return moderator.response;

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
    const moderator = await requireSupportCapability(request, env, 'manage_reports');
    if ('response' in moderator) return moderator.response;

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
    const moderator = await requireSupportCapability(request, env, 'ban_users');
    if ('response' in moderator) return moderator.response;

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

    // v48 role hierarchy guard
    if (!supportRoleCanActOn(moderator.user.platform_role, target.platform_role)) {
        return fail('Your Support role cannot act on that platform role.', 403);
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
        reporter.public_user_id AS reporter_public_user_id,
        s.name AS workspace_name, s.owner_user_id AS workspace_owner_id,
        owner.display_name AS workspace_owner_name, owner.public_user_id AS workspace_owner_public_user_id,
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
      reporterPublicUserId: row.reporter_public_user_id ?? '',
      targetWorkspaceId: row.target_workspace_id ?? null, targetWorkspaceName: row.workspace_name ?? null,
      targetWorkspaceOwnerId: row.workspace_owner_id ?? null, targetWorkspaceOwnerName: row.workspace_owner_name ?? null,
      targetWorkspaceOwnerPublicUserId: row.workspace_owner_public_user_id ?? '',
      subject: row.subject, details: row.details, status: row.status, priority: row.priority,
      assignedTo: row.assigned_to ?? null, assignedToName: row.assigned_to_name ?? null,
      restricted: Boolean(row.restricted), archivedAt: row.archived_at ? Number(row.archived_at) : null,
      archivedBy: row.archived_by ?? null,
      createdAt: Number(row.created_at), updatedAt: Number(row.updated_at), resolvedAt: row.resolved_at ? Number(row.resolved_at) : null,
    });
}

const SUPPORT_CAPABILITIES_V48 = [
    'view_reports',
    'manage_reports',
    'manage_bugs',
    'view_accounts',
    'view_verified_emails',
    'send_support_dms',
    'ban_users',
    'chat_restrict',
    'space_create_restrict',
    'space_join_restrict',
    'space_restrict',
    'delete_space',
    'reset_identity',
    'view_audit',
    'manage_beta_access',
    'staff_chat',
];

const SUPPORT_ROLE_DEFAULTS_V48 = {
    support: [
        'view_reports',
        'manage_reports',
        'manage_bugs',
        'view_accounts',
        'send_support_dms',
        'staff_chat',
    ],
    staff: SUPPORT_CAPABILITIES_V48.slice(),
};

function normalizeSupportPermissionsV48(value) {
    const source = Array.isArray(value) ? value : [];
    return [...new Set(source
        .map(item => String(item ?? '').trim())
        .filter(item => SUPPORT_CAPABILITIES_V48.includes(item)))];
}

async function supportPermissionsForUserV48(env, user) {
    if (user.platform_role === 'creator') return SUPPORT_CAPABILITIES_V48.slice();
    const row = await env.DB.prepare(
        `SELECT permissions_json
         FROM support_staff_permissions
         WHERE user_id = ?
         LIMIT 1`
    ).bind(user.id).first();

    if (row) {
        try {
            return normalizeSupportPermissionsV48(JSON.parse(row.permissions_json ?? '[]'));
        } catch {
            return [];
        }
    }

    return (SUPPORT_ROLE_DEFAULTS_V48[user.platform_role] ?? []).slice();
}

async function requireSupportCapability(request, env, capability) {
    const support = await requireSupportConsole(request, env);
    if ('response' in support) return support;
    const permissions = await supportPermissionsForUserV48(env, support.user);
    if (!permissions.includes(capability)) {
        return { response: fail(`Support permission required: ${capability}.`, 403) };
    }
    return { user: support.user, permissions };
}

async function requireSupportCapabilityAnyV53(request, env, capabilities) {
    const support = await requireSupportConsole(request, env);
    if ('response' in support) return support;
    const permissions = await supportPermissionsForUserV48(env, support.user);
    if (!capabilities.some(capability => permissions.includes(capability))) {
        return { response: fail('Support permission required: ' + capabilities.join(' or ') + '.', 403) };
    }
    return { user: support.user, permissions };
}

async function requireFounderSupportV48(request, env) {
    const support = await requireSupportConsole(request, env);
    if ('response' in support) return support;
    if (support.user.platform_role !== 'creator') {
        return { response: fail('Only the Founder can manage the Support team.', 403) };
    }
    return { user: support.user, permissions: SUPPORT_CAPABILITIES_V48.slice() };
}

function supportDurationMinutesV48(value) {
    if (value === null || value === undefined || value === '' || value === 'permanent') return null;
    const parsed = Number(value);
    if (!Number.isFinite(parsed) || parsed <= 0) return null;
    return Math.min(Math.round(parsed), 525600);
}

function supportRestrictionActiveV48(active, expiresAt) {
    return Boolean(active) && (!expiresAt || Number(expiresAt) > Date.now());
}

async function supportAuditV48(env, moderatorId, targetUserId, action, reason, metadata = {}) {
    await env.DB.prepare(
        `INSERT INTO platform_moderation_actions
          (id, moderator_id, target_user_id, action, reason, metadata_json, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
    ).bind(
        crypto.randomUUID(),
        moderatorId,
        targetUserId,
        action,
        String(reason ?? '').slice(0, 1200),
        JSON.stringify(metadata ?? {}),
        Date.now(),
    ).run();
}

async function activePlatformRestrictionV48(env, userId, kind) {
    const now = Date.now();
    return env.DB.prepare(
        `SELECT *
         FROM platform_restrictions
         WHERE user_id = ?
           AND kind = ?
           AND active = 1
           AND (expires_at IS NULL OR expires_at > ?)
         ORDER BY created_at DESC
         LIMIT 1`
    ).bind(userId, kind, now).first();
}

async function supportMeV48(request, env) {
    const support = await requireSupportConsole(request, env);
    if ('response' in support) return support.response;
    const permissions = await supportPermissionsForUserV48(env, support.user);
    return json({
        id: support.user.id,
        role: clientPlatformRole(support.user.platform_role),
        permissions,
        founder: support.user.platform_role === 'creator',
    });
}

async function listSupportTeamV48(request, env) {
    const founder = await requireFounderSupportV48(request, env);
    if ('response' in founder) return founder.response;
    const result = await env.DB.prepare(
        `SELECT
           u.id,
           u.public_user_id,
           u.username,
           u.display_name,
           u.avatar_url,
           u.platform_role,
           u.email,
           u.email_verified,
           u.created_at,
           p.permissions_json,
           p.updated_at AS permissions_updated_at
         FROM users u
         LEFT JOIN support_staff_permissions p ON p.user_id = u.id
         WHERE u.platform_role IN ('creator','staff','support')
         ORDER BY CASE u.platform_role WHEN 'creator' THEN 0 WHEN 'staff' THEN 1 ELSE 2 END,
                  u.created_at ASC`
    ).all();

    return json((result.results ?? []).map(row => ({
        id: row.id,
        publicUserId: row.public_user_id ?? '',
        username: row.username,
        displayName: row.display_name,
        avatarUrl: row.avatar_url ?? null,
        platformRole: clientPlatformRole(row.platform_role),
        email: row.email_verified ? (row.email ?? null) : null,
        emailVerified: Boolean(row.email_verified),
        createdAt: Number(row.created_at),
        permissions: row.platform_role === 'creator'
            ? SUPPORT_CAPABILITIES_V48.slice()
            : row.permissions_json
                ? normalizeSupportPermissionsV48(JSON.parse(row.permissions_json))
                : (SUPPORT_ROLE_DEFAULTS_V48[row.platform_role] ?? []).slice(),
        customPermissions: Boolean(row.permissions_json),
    })));
}

async function updateSupportTeamMemberV48(request, env, userId) {
    const founder = await requireFounderSupportV48(request, env);
    if ('response' in founder) return founder.response;
    if (userId === founder.user.id) return fail('Founder access cannot be changed here.', 400);

    const body = await readJson(request);
    const role = body.role === 'staff'
        ? 'staff'
        : body.role === 'support'
            ? 'support'
            : body.role === null
                ? null
                : undefined;
    if (role === undefined) return fail('Platform role must be staff, support, or null.');

    const target = await env.DB.prepare(
        `SELECT id, username, display_name, platform_role
         FROM users WHERE id = ? LIMIT 1`
    ).bind(userId).first();
    if (!target) return fail('Account not found.', 404);
    if (target.platform_role === 'creator') return fail('Founder access cannot be changed.', 403);

    const now = Date.now();
    await env.DB.prepare(
        `UPDATE users SET platform_role = ?, updated_at = ? WHERE id = ?`
    ).bind(role, now, userId).run();

    if (!role) {
        await env.DB.prepare(
            `DELETE FROM support_staff_permissions WHERE user_id = ?`
        ).bind(userId).run();
    }

    await supportAuditV48(
        env,
        founder.user.id,
        userId,
        'support.team_role',
        `Platform role changed to ${role ?? 'member'}.`,
        { previousRole: target.platform_role, role },
    );

    return json({
        id: userId,
        role: clientPlatformRole(role),
    });
}

async function updateSupportTeamPermissionsV48(request, env, userId) {
    const founder = await requireFounderSupportV48(request, env);
    if ('response' in founder) return founder.response;
    if (userId === founder.user.id) return fail('Founder permissions are always full access.', 400);

    const target = await env.DB.prepare(
        `SELECT id, platform_role FROM users WHERE id = ? LIMIT 1`
    ).bind(userId).first();
    if (!target) return fail('Account not found.', 404);
    if (!['staff','support'].includes(target.platform_role)) {
        return fail('Permissions can only be assigned to Staff or Support accounts.', 409);
    }

    const body = await readJson(request);
    const permissions = normalizeSupportPermissionsV48(body.permissions);
    const now = Date.now();
    await env.DB.prepare(
        `INSERT INTO support_staff_permissions
          (user_id, permissions_json, updated_by, updated_at)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(user_id) DO UPDATE SET
           permissions_json = excluded.permissions_json,
           updated_by = excluded.updated_by,
           updated_at = excluded.updated_at`
    ).bind(userId, JSON.stringify(permissions), founder.user.id, now).run();

    await supportAuditV48(
        env,
        founder.user.id,
        userId,
        'support.permissions',
        'Support Console capabilities updated.',
        { permissions },
    );
    return json({ userId, permissions, updatedAt: now });
}

async function updateSupportPublicIdV48(request, env, userId) {
    const founder = await requireFounderSupportV48(request, env);
    if ('response' in founder) return founder.response;
    if (userId === founder.user.id) return fail('Founder Spaces ID is reserved.', 400);

    const body = await readJson(request);
    const number = Number.parseInt(String(body.number ?? ''), 10);
    if (!Number.isInteger(number) || number < 2 || number > 19) {
        return fail('Reserved Spaces IDs must be between #2 and #19.');
    }
    const publicUserId = String(number).padStart(5, '0');

    const target = await env.DB.prepare(
        `SELECT id, public_user_id, platform_role FROM users WHERE id = ? LIMIT 1`
    ).bind(userId).first();
    if (!target) return fail('Account not found.', 404);
    if (target.platform_role === 'creator') return fail('Founder Spaces ID is reserved.', 403);

    const collision = await env.DB.prepare(
        `SELECT id FROM users WHERE public_user_id = ? AND id <> ? LIMIT 1`
    ).bind(publicUserId, userId).first();
    if (collision) return fail(`#${number} is already assigned.`, 409);
    if (target.public_user_id === publicUserId) {
        return json({ userId, publicUserId });
    }

    const now = Date.now();
    await env.DB.prepare(
        `INSERT INTO public_user_id_history
          (id, user_id, old_public_user_id, new_public_user_id, changed_by, reason, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
    ).bind(
        crypto.randomUUID(), userId, target.public_user_id ?? '', publicUserId,
        founder.user.id, 'Founder reserved-ID assignment', now,
    ).run();
    await env.DB.prepare(
        `UPDATE users SET public_user_id = ?, updated_at = ? WHERE id = ?`
    ).bind(publicUserId, now, userId).run();

    await supportAuditV48(
        env, founder.user.id, userId, 'support.public_id',
        `Reserved Spaces ID assigned: #${number}.`,
        { oldPublicUserId: target.public_user_id ?? '', publicUserId },
    );
    return json({ userId, publicUserId });
}

async function supportAccountInspectorV48(request, env, userId) {
    const support = await requireSupportCapability(request, env, 'view_accounts');
    if ('response' in support) return support.response;
    const target = await env.DB.prepare(
        `SELECT
           id, public_user_id, username, display_name, avatar_url, banner_url,
           profile_accent, bio, platform_role, public_profile, created_at,
           email, email_verified, totp_enabled, totp_secret
         FROM users WHERE id = ? LIMIT 1`
    ).bind(userId).first();
    if (!target) return fail('Account not found.', 404);

    const canViewEmail = support.permissions.includes('view_verified_emails');
    const canViewReports = support.permissions.includes('view_reports');
    const canViewDms = support.permissions.includes('send_support_dms');
    const canViewAudit = support.permissions.includes('view_audit');
    const memberships = await env.DB.prepare(
        `SELECT s.id AS workspace_id, s.name AS workspace_name, sm.role, sm.joined_at
         FROM space_members sm
         JOIN spaces s ON s.id = sm.space_id
         WHERE sm.user_id = ?
         ORDER BY sm.joined_at DESC`
    ).bind(userId).all();

    const restrictions = await env.DB.prepare(
        `SELECT id, kind, reason, created_by, created_at, expires_at, active, revoked_at, revoked_by
         FROM platform_restrictions
         WHERE user_id = ? ORDER BY created_at DESC LIMIT 200`
    ).bind(userId).all();

    const bans = await env.DB.prepare(
        `SELECT id, reason, banned_by, created_at, expires_at, active
         FROM platform_bans
         WHERE user_id = ? ORDER BY created_at DESC LIMIT 100`
    ).bind(userId).all();

    const reports = canViewReports
        ? await env.DB.prepare(
            `SELECT id, reporter_id, reported_user_id, workspace_id, reason, details, status, created_at, reviewed_by, reviewed_at
             FROM reports
             WHERE reporter_id = ? OR reported_user_id = ?
             ORDER BY created_at DESC LIMIT 100`
        ).bind(userId, userId).all()
        : { results: [] };

    const cases = canViewReports
        ? await env.DB.prepare(
            `SELECT id, kind, subject, details, priority, status, target_workspace_id, assigned_to, created_at, updated_at
             FROM support_cases
             WHERE reporter_id = ?
             ORDER BY created_at DESC LIMIT 100`
        ).bind(userId).all()
        : { results: [] };

    const dms = canViewDms
        ? await env.DB.prepare(
            `SELECT id, sender_user_id, subject, body, case_id, created_at
             FROM support_messages
             WHERE recipient_user_id = ?
             ORDER BY created_at DESC LIMIT 100`
        ).bind(userId).all()
        : { results: [] };

    const actions = canViewAudit
        ? await env.DB.prepare(
            `SELECT a.id, a.moderator_id, a.action, a.reason, a.metadata_json, a.created_at,
                    u.display_name AS moderator_name
             FROM platform_moderation_actions a
             LEFT JOIN users u ON u.id = a.moderator_id
             WHERE a.target_user_id = ?
             ORDER BY a.created_at DESC LIMIT 150`
        ).bind(userId).all()
        : { results: [] };

    return json({
        profile: {
            id: target.id,
            publicUserId: target.public_user_id ?? '',
            username: target.username,
            displayName: target.display_name,
            avatarUrl: target.avatar_url ?? null,
            bannerUrl: target.banner_url ?? null,
            profileAccent: target.profile_accent ?? '#8b6ca8',
            bio: target.bio ?? '',
            platformRole: clientPlatformRole(target.platform_role),
            publicProfile: Boolean(target.public_profile),
            createdAt: Number(target.created_at),
        },
        security: {
            email: canViewEmail && target.email_verified ? (target.email ?? null) : null,
            emailVerified: Boolean(target.email_verified),
            emailVisible: Boolean(canViewEmail && target.email_verified),
            twoFactorEnabled: Boolean(target.totp_enabled && target.totp_secret),
        },
        memberships: (memberships.results ?? []).map(row => ({
            workspaceId: row.workspace_id,
            workspaceName: row.workspace_name,
            role: row.role,
            joinedAt: Number(row.joined_at),
        })),
        restrictions: [
            ...(bans.results ?? []).map(row => ({
                source: 'ban', id: row.id, kind: 'ban', reason: row.reason,
                createdBy: row.banned_by, createdAt: Number(row.created_at),
                expiresAt: row.expires_at ? Number(row.expires_at) : null,
                active: supportRestrictionActiveV48(row.active, row.expires_at),
            })),
            ...(restrictions.results ?? []).map(row => ({
                source: 'restriction', id: row.id, kind: row.kind, reason: row.reason,
                createdBy: row.created_by, createdAt: Number(row.created_at),
                expiresAt: row.expires_at ? Number(row.expires_at) : null,
                active: supportRestrictionActiveV48(row.active, row.expires_at),
                revokedAt: row.revoked_at ? Number(row.revoked_at) : null,
                revokedBy: row.revoked_by ?? null,
            })),
        ].sort((a, b) => b.createdAt - a.createdAt),
        reports: reports.results ?? [],
        cases: cases.results ?? [],
        supportMessages: dms.results ?? [],
        moderationActions: (actions.results ?? []).map(row => ({
            id: row.id,
            moderatorId: row.moderator_id,
            moderatorName: row.moderator_name ?? 'Spaces',
            action: row.action,
            reason: row.reason,
            metadata: (() => { try { return JSON.parse(row.metadata_json ?? '{}'); } catch { return {}; } })(),
            createdAt: Number(row.created_at),
        })),
    });
}

async function listSupportRestrictionsV48(request, env) {
    const support = await requireSupportCapability(request, env, 'view_accounts');
    if ('response' in support) return support.response;
    const canViewEmail = support.permissions.includes('view_verified_emails');
    const now = Date.now();

    const bans = await env.DB.prepare(
        `SELECT pb.*, u.public_user_id, u.username, u.display_name, u.avatar_url,
                u.email, u.email_verified, actor.display_name AS actor_name
         FROM platform_bans pb
         JOIN users u ON u.id = pb.user_id
         LEFT JOIN users actor ON actor.id = pb.banned_by
         ORDER BY pb.created_at DESC LIMIT 300`
    ).all();
    const account = await env.DB.prepare(
        `SELECT pr.*, u.public_user_id, u.username, u.display_name, u.avatar_url,
                u.email, u.email_verified, actor.display_name AS actor_name
         FROM platform_restrictions pr
         JOIN users u ON u.id = pr.user_id
         LEFT JOIN users actor ON actor.id = pr.created_by
         ORDER BY pr.created_at DESC LIMIT 500`
    ).all();
    const spaces = await env.DB.prepare(
        `SELECT sr.*, s.name AS space_name, s.owner_user_id,
                actor.display_name AS actor_name
         FROM space_restrictions sr
         JOIN spaces s ON s.id = sr.space_id
         LEFT JOIN users actor ON actor.id = sr.restricted_by
         ORDER BY sr.created_at DESC LIMIT 300`
    ).all();

    const userShape = row => ({
        userId: row.user_id,
        publicUserId: row.public_user_id ?? '',
        username: row.username,
        displayName: row.display_name,
        avatarUrl: row.avatar_url ?? null,
        email: canViewEmail && row.email_verified ? (row.email ?? null) : null,
        emailVerified: Boolean(row.email_verified),
    });

    return json([
        ...(bans.results ?? []).map(row => ({
            source: 'ban', id: row.id, kind: 'ban', ...userShape(row),
            reason: row.reason, createdBy: row.banned_by,
            createdByName: row.actor_name ?? 'Spaces', createdAt: Number(row.created_at),
            expiresAt: row.expires_at ? Number(row.expires_at) : null,
            active: Boolean(row.active) && (!row.expires_at || Number(row.expires_at) > now),
        })),
        ...(account.results ?? []).map(row => ({
            source: 'restriction', id: row.id, kind: row.kind, ...userShape(row),
            reason: row.reason, createdBy: row.created_by,
            createdByName: row.actor_name ?? 'Spaces', createdAt: Number(row.created_at),
            expiresAt: row.expires_at ? Number(row.expires_at) : null,
            active: Boolean(row.active) && (!row.expires_at || Number(row.expires_at) > now),
            revokedAt: row.revoked_at ? Number(row.revoked_at) : null,
        })),
        ...(spaces.results ?? []).map(row => ({
            source: 'space', id: row.id, kind: 'space',
            workspaceId: row.space_id, workspaceName: row.space_name,
            userId: row.owner_user_id,
            reason: row.reason, createdBy: row.restricted_by,
            createdByName: row.actor_name ?? 'Spaces', createdAt: Number(row.created_at),
            expiresAt: row.expires_at ? Number(row.expires_at) : null,
            active: Boolean(row.active) && (!row.expires_at || Number(row.expires_at) > now),
        })),
    ].sort((a, b) => b.createdAt - a.createdAt));
}

async function applySupportRestrictionV48(request, env, userId) {
    const body = await readJson(request);
    const kind = String(body.kind ?? '').trim();
    const capability = {
        ban: 'ban_users',
        chat: 'chat_restrict',
        space_create: 'space_create_restrict',
        space_join: 'space_join_restrict',
    }[kind];
    if (!capability) return fail('Invalid restriction type.');

    const support = await requireSupportCapability(request, env, capability);
    if ('response' in support) return support.response;
    if (userId === support.user.id) return fail('You cannot restrict your own account.', 400);

    const target = await env.DB.prepare(
        `SELECT id, username, display_name, platform_role FROM users WHERE id = ? LIMIT 1`
    ).bind(userId).first();
    if (!target) return fail('Account not found.', 404);
    if (!supportRoleCanActOn(support.user.platform_role, target.platform_role)) {
        return fail('Your Support role cannot act on that platform role.', 403);
    }

    const reason = String(body.reason ?? 'Platform moderation action').trim().slice(0, 1200);
    if (!reason) return fail('A moderation reason is required.');
    const durationMinutes = supportDurationMinutesV48(body.durationMinutes);
    const now = Date.now();
    const expiresAt = durationMinutes ? now + durationMinutes * 60_000 : null;
    const id = crypto.randomUUID();

    if (kind === 'ban') {
        await env.DB.prepare(
            `UPDATE platform_bans SET active = 0 WHERE user_id = ? AND active = 1`
        ).bind(userId).run();
        await env.DB.prepare(
            `INSERT INTO platform_bans
              (id, user_id, banned_by, reason, created_at, expires_at, active)
             VALUES (?, ?, ?, ?, ?, ?, 1)`
        ).bind(id, userId, support.user.id, reason, now, expiresAt).run();
        await env.DB.prepare(`DELETE FROM sessions WHERE user_id = ?`).bind(userId).run();
    } else {
        await env.DB.prepare(
            `UPDATE platform_restrictions SET active = 0, revoked_at = ?, revoked_by = ?
             WHERE user_id = ? AND kind = ? AND active = 1`
        ).bind(now, support.user.id, userId, kind).run();
        await env.DB.prepare(
            `INSERT INTO platform_restrictions
              (id, user_id, kind, reason, created_by, created_at, expires_at, active, revoked_at, revoked_by)
             VALUES (?, ?, ?, ?, ?, ?, ?, 1, NULL, NULL)`
        ).bind(id, userId, kind, reason, support.user.id, now, expiresAt).run();
    }

    await supportAuditV48(
        env, support.user.id, userId, `restriction.${kind}`, reason,
        { restrictionId: id, expiresAt, actorRole: support.user.platform_role ?? null, targetRole: target.platform_role ?? null, restrictionType: kind, durationMinutes: durationMinutes ?? null, appliedAt: now },
    );
    return json({ id, userId, kind, reason, createdAt: now, expiresAt, active: true }, 201);
}

async function revokeSupportRestrictionV48(request, env, source, restrictionId) {
    if (source === 'ban') {
        const support = await requireSupportCapability(request, env, 'ban_users');
        if ('response' in support) return support.response;
        const row = await env.DB.prepare(
            `SELECT * FROM platform_bans WHERE id = ? LIMIT 1`
        ).bind(restrictionId).first();
        if (!row) return fail('Ban not found.', 404);
        const target = await env.DB.prepare(
            `SELECT platform_role FROM users WHERE id = ? LIMIT 1`
        ).bind(row.user_id).first();
        if (target && !supportRoleCanActOn(support.user.platform_role, target.platform_role)) {
            return fail('Your Support role cannot act on that platform role.', 403);
        }
        await env.DB.prepare(`UPDATE platform_bans SET active = 0 WHERE id = ?`).bind(restrictionId).run();
        await supportAuditV48(env, support.user.id, row.user_id, 'restriction.ban.revoked', 'Platform ban removed.', { restrictionId });
        return new Response(null, { status: 204, headers: corsHeaders() });
    }

    if (source === 'space') {
        const support = await requireSupportCapability(request, env, 'space_restrict');
        if ('response' in support) return support.response;
        const row = await env.DB.prepare(
            `SELECT sr.*, s.owner_user_id, u.platform_role AS owner_platform_role
             FROM space_restrictions sr
             JOIN spaces s ON s.id = sr.space_id
             JOIN users u ON u.id = s.owner_user_id
             WHERE sr.id = ? LIMIT 1`
        ).bind(restrictionId).first();
        if (!row) return fail('Space restriction not found.', 404);
        if (!supportRoleCanActOn(support.user.platform_role, row.owner_platform_role)) {
            return fail('Your Support role cannot act on that Space owner.', 403);
        }
        await env.DB.prepare(`UPDATE space_restrictions SET active = 0 WHERE id = ?`).bind(restrictionId).run();
        await supportAuditV48(env, support.user.id, row.owner_user_id, 'restriction.space.revoked', 'Space restriction removed.', { restrictionId, workspaceId: row.space_id });
        return new Response(null, { status: 204, headers: corsHeaders() });
    }

    if (source !== 'restriction') return fail('Invalid restriction source.');
    const row = await env.DB.prepare(
        `SELECT * FROM platform_restrictions WHERE id = ? LIMIT 1`
    ).bind(restrictionId).first();
    if (!row) return fail('Restriction not found.', 404);
    const capability = {
        chat: 'chat_restrict',
        space_create: 'space_create_restrict',
        space_join: 'space_join_restrict',
    }[row.kind];
    if (!capability) return fail('Invalid restriction type.', 409);
    const support = await requireSupportCapability(request, env, capability);
    if ('response' in support) return support.response;
    const target = await env.DB.prepare(
        `SELECT platform_role FROM users WHERE id = ? LIMIT 1`
    ).bind(row.user_id).first();
    if (target && !supportRoleCanActOn(support.user.platform_role, target.platform_role)) {
        return fail('Your Support role cannot act on that platform role.', 403);
    }
    const now = Date.now();
    await env.DB.prepare(
        `UPDATE platform_restrictions SET active = 0, revoked_at = ?, revoked_by = ? WHERE id = ?`
    ).bind(now, support.user.id, restrictionId).run();
    await supportAuditV48(env, support.user.id, row.user_id, `restriction.${row.kind}.revoked`, 'Account restriction removed.', { restrictionId });
    return new Response(null, { status: 204, headers: corsHeaders() });
}

// ---- Spaces V77 Support Operations -------------------------------------------------
const SUPPORT_V77_CASE_TYPES = ['request','user_report','space_report','bug_report','appeal','other'];
const SUPPORT_V77_STATUSES = ['waiting','reviewing','resolved','archived'];
const SUPPORT_V77_PRIORITIES = ['low','normal','high','urgent'];
const SUPPORT_V77_USER_CAPABILITIES = ['platform_access','send_messages','direct_messages','uploads','create_spaces','join_spaces'];
const SUPPORT_V77_SPACE_CAPABILITIES = ['send_messages','join_space'];
const SUPPORT_V77_CHANNEL_CAPABILITIES = ['send_messages'];

function supportV77Json(value, fallback = {}) {
    try { return value ? JSON.parse(value) : fallback; }
    catch { return fallback; }
}

function supportV77IsTeam(user) {
    return ['creator','staff','support'].includes(user?.platform_role);
}

function supportV77ClientRole(value) {
    return value === 'creator' ? 'founder' : (['staff','support'].includes(value) ? value : null);
}

function supportV77CaseNumber() {
    return `SP-${Date.now().toString(36).toUpperCase()}-${crypto.randomUUID().slice(0, 4).toUpperCase()}`;
}

function supportV77MapLegacyStatus(value, archivedAt = null) {
    if (archivedAt) return 'archived';
    if (value === 'waiting' || value === 'open') return 'waiting';
    if (value === 'reviewing' || value === 'reviewed' || value === 'actioned') return 'reviewing';
    if (value === 'resolved' || value === 'dismissed' || value === 'closed') return 'resolved';
    return 'waiting';
}

async function supportV77Audit(env, actor, action, targetType, targetId, caseId = null, reasonCategory = '', note = '', before = {}, after = {}, expiresAt = null) {
    await env.DB.prepare(`INSERT INTO support_audit_v77
      (id, actor_id, actor_role, action, target_type, target_id, case_id, reason_category, note, before_json, after_json, expires_at, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .bind(crypto.randomUUID(), actor.id, actor.platform_role ?? null, action, targetType, targetId, caseId, String(reasonCategory ?? '').slice(0,120), String(note ?? '').slice(0,1200), JSON.stringify(before ?? {}), JSON.stringify(after ?? {}), expiresAt, Date.now()).run();
}

async function activeSupportRestrictionV77(env, targetType, targetId, capability) {
    const now = Date.now();
    return env.DB.prepare(`SELECT * FROM support_restrictions_v77
      WHERE target_type = ? AND target_id = ? AND capability = ? AND active = 1
        AND (expires_at IS NULL OR expires_at > ?)
      ORDER BY created_at DESC LIMIT 1`).bind(targetType, targetId, capability, now).first();
}

async function supportV77SyncLegacy(env) {
    // V73/V75 ticket compatibility. Every operation is best-effort so an older
    // installation without one of these tables is still valid.
    try {
        const result = await env.DB.prepare(`SELECT * FROM support_tickets ORDER BY last_activity_at DESC LIMIT 500`).all();
        for (const row of result.results ?? []) {
            const id = `legacy-ticket:${row.id}`;
            const status = supportV77MapLegacyStatus(row.status, null);
            await env.DB.prepare(`INSERT OR IGNORE INTO support_cases_v77
              (id,case_number,case_type,subtype,reporter_id,target_user_id,target_space_id,target_channel_id,subject,answers_json,details,priority,status,assigned_to,source,created_at,updated_at,last_activity_at,resolved_at,resolved_by,archived_at,archived_by)
              VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
              .bind(id, row.ticket_number || `SP-${String(row.id).slice(0,8)}`, 'request', String(row.topic ?? 'Legacy Support Ticket'), row.user_id, null, null, null, String(row.topic ?? `Support Ticket ${row.ticket_number ?? ''}`), '{}', '', 'normal', status, row.assigned_to ?? null, 'legacy_ticket', Number(row.created_at ?? Date.now()), Number(row.updated_at ?? row.created_at ?? Date.now()), Number(row.last_activity_at ?? row.updated_at ?? row.created_at ?? Date.now()), row.resolved_at ? Number(row.resolved_at) : null, row.resolved_by ?? null, null, null).run();
            // SPACES_V77_6_ARCHIVE_TITLEBAR_ROLES: once a case has any native V77 activity, V77 becomes
            // authoritative for lifecycle state. Older ticket rows may continue to feed
            // messages/events, but they must never pull Archived/Reviewing back to a
            // stale legacy status on the next queue refresh.
            const v776NativeActivity = await env.DB.prepare(`SELECT id FROM support_case_events_v77 WHERE case_id = ? AND id NOT LIKE 'legacy-%' LIMIT 1`).bind(id).first();
            if (!v776NativeActivity) {
                await env.DB.prepare(`UPDATE support_cases_v77 SET status = ?, assigned_to = ?, updated_at = ?, last_activity_at = ?, resolved_at = ?, resolved_by = ? WHERE id = ? AND source = 'legacy_ticket'`)
                  .bind(status, row.assigned_to ?? null, Number(row.updated_at ?? row.created_at ?? Date.now()), Number(row.last_activity_at ?? row.updated_at ?? row.created_at ?? Date.now()), row.resolved_at ? Number(row.resolved_at) : null, row.resolved_by ?? null, id).run();
            } else {
                // Repair cases that were already reverted by V77.5 before this hotfix.
                // The screenshot case has a native archive event but its row was pulled
                // back to resolved by the legacy sync; this restores that event as truth.
                const v776LatestArchive = await env.DB.prepare(`SELECT actor_user_id, created_at FROM support_case_events_v77 e WHERE e.case_id = ? AND e.id NOT LIKE 'legacy-%' AND e.event_type = 'archive' AND NOT EXISTS (SELECT 1 FROM support_case_events_v77 later WHERE later.case_id = e.case_id AND later.id NOT LIKE 'legacy-%' AND later.created_at > e.created_at AND later.event_type IN ('reopen','reviewing','take','release','resolve','archive')) ORDER BY e.created_at DESC LIMIT 1`).bind(id).first();
                if (v776LatestArchive) {
                    await env.DB.prepare(`UPDATE support_cases_v77 SET status='archived', archived_at=COALESCE(archived_at,?), archived_by=COALESCE(archived_by,?), updated_at=MAX(updated_at,?), last_activity_at=MAX(last_activity_at,?) WHERE id=? AND source='legacy_ticket'`)
                      .bind(Number(v776LatestArchive.created_at), v776LatestArchive.actor_user_id ?? null, Number(v776LatestArchive.created_at), Number(v776LatestArchive.created_at), id).run();
                }
            }
        }
        try {
            const events = await env.DB.prepare(`SELECT * FROM support_ticket_events ORDER BY created_at ASC LIMIT 4000`).all();
            for (const event of events.results ?? []) {
                await env.DB.prepare(`INSERT OR IGNORE INTO support_case_events_v77 (id,case_id,actor_user_id,event_type,body,metadata_json,created_at) VALUES (?,?,?,?,?,?,?)`)
                  .bind(`legacy-ticket-event:${event.id}`, `legacy-ticket:${event.ticket_id}`, event.actor_user_id ?? null, String(event.event_type ?? 'legacy_event'), '', String(event.metadata_json ?? '{}'), Number(event.created_at ?? Date.now())).run();
            }
        } catch { /* optional legacy event table */ }
        try {
            const messages = await env.DB.prepare(`SELECT id,ticket_id,sender_user_id,body,created_at FROM support_messages WHERE ticket_id IS NOT NULL ORDER BY created_at ASC LIMIT 4000`).all();
            for (const message of messages.results ?? []) {
                await env.DB.prepare(`INSERT OR IGNORE INTO support_case_events_v77 (id,case_id,actor_user_id,event_type,body,metadata_json,created_at) VALUES (?,?,?,?,?,?,?)`)
                  .bind(`legacy-ticket-message:${message.id}`, `legacy-ticket:${message.ticket_id}`, message.sender_user_id ?? null, 'message', String(message.body ?? ''), '{"legacy":true}', Number(message.created_at ?? Date.now())).run();
            }
        } catch { /* ticket_id may not exist on very old support_messages */ }
    } catch { /* support_tickets did not exist */ }

    try {
        const result = await env.DB.prepare(`SELECT * FROM support_cases ORDER BY created_at DESC LIMIT 500`).all();
        for (const row of result.results ?? []) {
            const id = `legacy-case:${row.id}`;
            const archivedAt = row.archived_at ? Number(row.archived_at) : null;
            const type = row.kind === 'bug' ? 'bug_report' : 'space_report';
            await env.DB.prepare(`INSERT OR IGNORE INTO support_cases_v77
              (id,case_number,case_type,subtype,reporter_id,target_user_id,target_space_id,target_channel_id,subject,answers_json,details,priority,status,assigned_to,source,created_at,updated_at,last_activity_at,resolved_at,resolved_by,archived_at,archived_by)
              VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
              .bind(id, `CASE-${String(row.id).slice(0,8).toUpperCase()}`, type, row.kind === 'bug' ? 'Legacy bug report' : 'Legacy Space report', row.reporter_id, null, row.target_workspace_id ?? null, null, String(row.subject ?? 'Legacy Support case'), String(row.metadata_json ?? '{}'), String(row.details ?? ''), SUPPORT_V77_PRIORITIES.includes(row.priority) ? row.priority : 'normal', supportV77MapLegacyStatus(row.status, archivedAt), row.assigned_to ?? null, 'legacy_case', Number(row.created_at ?? Date.now()), Number(row.updated_at ?? row.created_at ?? Date.now()), Number(row.updated_at ?? row.created_at ?? Date.now()), row.resolved_at ? Number(row.resolved_at) : null, null, archivedAt, row.archived_by ?? null).run();
        }
    } catch { /* old support_cases did not exist */ }

    try {
        const result = await env.DB.prepare(`SELECT * FROM reports ORDER BY created_at DESC LIMIT 500`).all();
        for (const row of result.results ?? []) {
            const id = `legacy-report:${row.id}`;
            const archivedAt = row.archived_at ? Number(row.archived_at) : null;
            await env.DB.prepare(`INSERT OR IGNORE INTO support_cases_v77
              (id,case_number,case_type,subtype,reporter_id,target_user_id,target_space_id,target_channel_id,subject,answers_json,details,priority,status,assigned_to,source,created_at,updated_at,last_activity_at,resolved_at,resolved_by,archived_at,archived_by)
              VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
              .bind(id, `REPORT-${String(row.id).slice(0,8).toUpperCase()}`, 'user_report', String(row.reason ?? 'Legacy user report'), row.reporter_id, row.reported_user_id ?? null, row.workspace_id ?? null, null, String(row.reason ?? 'User report'), '{}', String(row.details ?? ''), 'normal', supportV77MapLegacyStatus(row.status, archivedAt), row.reviewed_by ?? null, 'legacy_report', Number(row.created_at ?? Date.now()), Number(row.reviewed_at ?? row.created_at ?? Date.now()), Number(row.reviewed_at ?? row.created_at ?? Date.now()), ['actioned','dismissed'].includes(row.status) ? Number(row.reviewed_at ?? row.created_at ?? Date.now()) : null, row.reviewed_by ?? null, archivedAt, row.archived_by ?? null).run();
        }
    } catch { /* reports did not exist */ }
}

function supportV77Identity(row, prefix) {
    const id = row[`${prefix}_id`];
    if (!id) return null;
    const displayName = String(row[`${prefix}_display_name`] ?? row[`${prefix}_username`] ?? 'Spaces member');
    return {
        id: String(id),
        publicUserId: String(row[`${prefix}_public_user_id`] ?? ''),
        username: String(row[`${prefix}_username`] ?? ''),
        displayName,
        initials: displayName.trim().slice(0,1).toUpperCase() || 'S',
        avatarUrl: row[`${prefix}_avatar_url`] ?? null,
        bannerUrl: row[`${prefix}_banner_url`] ?? null,
        profileAccent: normalizeHexColor(row[`${prefix}_profile_accent`]),
        bio: String(row[`${prefix}_bio`] ?? ''),
        platformRole: supportV77ClientRole(row[`${prefix}_platform_role`]),
        presence: publicVisiblePresence(row[`${prefix}_presence_status`]),
        customStatus: String(row[`${prefix}_custom_status`] ?? ''),
    };
}

async function supportV77CaseRow(env, caseId) {
    return env.DB.prepare(`SELECT c.*,
      r.id reporter_id, r.public_user_id reporter_public_user_id, r.username reporter_username, r.display_name reporter_display_name, r.avatar_url reporter_avatar_url, r.banner_url reporter_banner_url, r.profile_accent reporter_profile_accent, r.bio reporter_bio, r.platform_role reporter_platform_role, r.presence_status reporter_presence_status, r.custom_status reporter_custom_status,
      t.id target_id, t.public_user_id target_public_user_id, t.username target_username, t.display_name target_display_name, t.avatar_url target_avatar_url, t.banner_url target_banner_url, t.profile_accent target_profile_accent, t.bio target_bio, t.platform_role target_platform_role, t.presence_status target_presence_status, t.custom_status target_custom_status,
      s.name target_space_name, ch.name target_channel_name, a.display_name assigned_to_name
      FROM support_cases_v77 c
      JOIN users r ON r.id = c.reporter_id
      LEFT JOIN users t ON t.id = c.target_user_id
      LEFT JOIN spaces s ON s.id = c.target_space_id
      LEFT JOIN channels ch ON ch.id = c.target_channel_id
      LEFT JOIN users a ON a.id = c.assigned_to
      WHERE c.id = ? LIMIT 1`).bind(caseId).first();
}

function supportV77CaseSummary(row) {
    return {
      id: row.id,
      caseNumber: row.case_number,
      caseType: row.case_type,
      subtype: row.subtype ?? '',
      reporter: supportV77Identity(row, 'reporter'),
      targetUser: supportV77Identity(row, 'target'),
      targetSpaceId: row.target_space_id ?? null,
      targetSpaceName: row.target_space_name ?? null,
      targetChannelId: row.target_channel_id ?? null,
      targetChannelName: row.target_channel_name ?? null,
      subject: row.subject,
      answers: supportV77Json(row.answers_json, {}),
      details: row.details ?? '',
      priority: row.priority,
      status: row.status,
      assignedTo: row.assigned_to ?? null,
      assignedToName: row.assigned_to_name ?? null,
      source: row.source,
      createdAt: Number(row.created_at),
      updatedAt: Number(row.updated_at),
      lastActivityAt: Number(row.last_activity_at),
      resolvedAt: row.resolved_at ? Number(row.resolved_at) : null,
      archivedAt: row.archived_at ? Number(row.archived_at) : null,
    };
}

async function supportV77CasePayload(env, caseId, staffView = false) {
    const row = await supportV77CaseRow(env, caseId);
    if (!row) return null;
    const result = await env.DB.prepare(`SELECT e.*, u.display_name actor_name, u.platform_role actor_platform_role
      FROM support_case_events_v77 e LEFT JOIN users u ON u.id = e.actor_user_id
      WHERE e.case_id = ? ${staffView ? '' : "AND e.event_type <> 'note'"}
      ORDER BY e.created_at ASC LIMIT 1200`).bind(caseId).all();
    return {
      ...supportV77CaseSummary(row),
      events: (result.results ?? []).map(event => ({
        id: event.id, caseId: event.case_id, actorUserId: event.actor_user_id ?? null,
        actorName: event.actor_name ?? (event.actor_user_id ? 'Spaces member' : 'System'),
        actorRole: supportV77ClientRole(event.actor_platform_role), eventType: event.event_type,
        body: event.body ?? '', metadata: supportV77Json(event.metadata_json, {}), createdAt: Number(event.created_at),
      })),
    };
}

async function supportV77CanManage(env, user, caseRow) {
    if (user.platform_role === 'creator') return true;
    if (!supportV77IsTeam(user)) return false;
    const permissions = await supportPermissionsForUserV48(env, user);
    if (caseRow?.case_type === 'bug_report') return permissions.includes('manage_bugs') || permissions.includes('manage_reports');
    return permissions.includes('manage_reports');
}

async function listSupportCasesV77(request, env) {
    const support = await requireSupportCapability(request, env, 'view_reports');
    if ('response' in support) return support.response;
    await supportV77SyncLegacy(env);
    const result = await env.DB.prepare(`SELECT c.*,
      r.id reporter_id, r.public_user_id reporter_public_user_id, r.username reporter_username, r.display_name reporter_display_name, r.avatar_url reporter_avatar_url, r.banner_url reporter_banner_url, r.profile_accent reporter_profile_accent, r.bio reporter_bio, r.platform_role reporter_platform_role, r.presence_status reporter_presence_status, r.custom_status reporter_custom_status,
      t.id target_id, t.public_user_id target_public_user_id, t.username target_username, t.display_name target_display_name, t.avatar_url target_avatar_url, t.banner_url target_banner_url, t.profile_accent target_profile_accent, t.bio target_bio, t.platform_role target_platform_role, t.presence_status target_presence_status, t.custom_status target_custom_status,
      s.name target_space_name, ch.name target_channel_name, a.display_name assigned_to_name
      FROM support_cases_v77 c JOIN users r ON r.id=c.reporter_id
      LEFT JOIN users t ON t.id=c.target_user_id LEFT JOIN spaces s ON s.id=c.target_space_id LEFT JOIN channels ch ON ch.id=c.target_channel_id LEFT JOIN users a ON a.id=c.assigned_to
      ORDER BY CASE c.status WHEN 'waiting' THEN 0 WHEN 'reviewing' THEN 1 WHEN 'resolved' THEN 2 ELSE 3 END, c.last_activity_at DESC LIMIT 800`).all();
    return json((result.results ?? []).map(supportV77CaseSummary));
}

async function listMySupportCasesV77(request, env) {
    const auth = await requireUser(request, env);
    if ('response' in auth) return auth.response;
    await supportV77SyncLegacy(env);
    const result = await env.DB.prepare(`SELECT c.*,
      r.id reporter_id, r.public_user_id reporter_public_user_id, r.username reporter_username, r.display_name reporter_display_name, r.avatar_url reporter_avatar_url, r.banner_url reporter_banner_url, r.profile_accent reporter_profile_accent, r.bio reporter_bio, r.platform_role reporter_platform_role, r.presence_status reporter_presence_status, r.custom_status reporter_custom_status,
      t.id target_id, t.public_user_id target_public_user_id, t.username target_username, t.display_name target_display_name, t.avatar_url target_avatar_url, t.banner_url target_banner_url, t.profile_accent target_profile_accent, t.bio target_bio, t.platform_role target_platform_role, t.presence_status target_presence_status, t.custom_status target_custom_status,
      s.name target_space_name, ch.name target_channel_name, a.display_name assigned_to_name
      FROM support_cases_v77 c JOIN users r ON r.id=c.reporter_id
      LEFT JOIN users t ON t.id=c.target_user_id LEFT JOIN spaces s ON s.id=c.target_space_id LEFT JOIN channels ch ON ch.id=c.target_channel_id LEFT JOIN users a ON a.id=c.assigned_to
      WHERE c.reporter_id = ? ORDER BY c.last_activity_at DESC LIMIT 200`).bind(auth.user.id).all();
    return json((result.results ?? []).map(supportV77CaseSummary));
}

async function createSupportCaseV77(request, env) {
    const auth = await requireUser(request, env);
    if ('response' in auth) return auth.response;
    const body = await readJson(request);
    const caseType = SUPPORT_V77_CASE_TYPES.includes(body.caseType) ? body.caseType : 'request';
    const subtype = String(body.subtype ?? '').trim().slice(0,120);
    const subject = String(body.subject ?? '').trim().slice(0,180) || 'Support request';
    const details = String(body.details ?? '').trim().slice(0,5000);
    const answers = body.answers && typeof body.answers === 'object' ? body.answers : {};
    const priority = SUPPORT_V77_PRIORITIES.includes(body.priority) ? body.priority : 'normal';
    let targetUserId = body.targetUserId ? String(body.targetUserId) : null;
    if (!targetUserId && body.targetUsername) {
        const target = await env.DB.prepare(`SELECT id FROM users WHERE username = ? LIMIT 1`).bind(normalizeUsername(body.targetUsername)).first();
        targetUserId = target?.id ?? null;
    }
    if (caseType === 'user_report' && !targetUserId) return fail('Choose a user to report.');
    if (targetUserId === auth.user.id) return fail('You cannot report your own account.');
    const targetSpaceId = body.targetSpaceId ? String(body.targetSpaceId) : null;
    const targetChannelId = body.targetChannelId ? String(body.targetChannelId) : null;
    if (targetSpaceId) {
        const space = await env.DB.prepare(`SELECT id,owner_user_id FROM spaces WHERE id = ? LIMIT 1`).bind(targetSpaceId).first();
        if (!space) return fail('Space not found.', 404);
        if (caseType === 'space_report' && !targetUserId) targetUserId = space.owner_user_id ?? null;
    }
    if (targetChannelId) {
        const channel = await env.DB.prepare(`SELECT id,space_id FROM channels WHERE id = ? LIMIT 1`).bind(targetChannelId).first();
        if (!channel || (targetSpaceId && channel.space_id !== targetSpaceId)) return fail('Channel not found.', 404);
    }
    const id = crypto.randomUUID();
    const now = Date.now();
    const caseNumber = supportV77CaseNumber();
    await env.DB.prepare(`INSERT INTO support_cases_v77
      (id,case_number,case_type,subtype,reporter_id,target_user_id,target_space_id,target_channel_id,subject,answers_json,details,priority,status,assigned_to,source,created_at,updated_at,last_activity_at,resolved_at,resolved_by,archived_at,archived_by)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?, 'waiting', NULL, ?,?,?,?,NULL,NULL,NULL,NULL)`)
      .bind(id,caseNumber,caseType,subtype,auth.user.id,targetUserId,targetSpaceId,targetChannelId,subject,JSON.stringify(answers),details,priority,String(body.source ?? 'support_bot').slice(0,80),now,now,now).run();
    await env.DB.prepare(`INSERT INTO support_case_events_v77 (id,case_id,actor_user_id,event_type,body,metadata_json,created_at) VALUES (?,?,?,?,?,?,?)`)
      .bind(crypto.randomUUID(),id,auth.user.id,'opened',details || subtype,JSON.stringify({caseType,subtype}),now).run();
    return json(await supportV77CasePayload(env,id,false),201);
}

async function supportV77CaseAccess(request, env, caseId) {
    const auth = await requireUser(request, env);
    if ('response' in auth) return auth;
    const row = await env.DB.prepare(`SELECT * FROM support_cases_v77 WHERE id = ? LIMIT 1`).bind(caseId).first();
    if (!row) return { response: fail('Support case not found.',404) };
    const staff = supportV77IsTeam(auth.user);
    if (row.reporter_id !== auth.user.id && !staff) return { response: fail('Support case not found.',404) };
    if (staff) {
        const permissions = await supportPermissionsForUserV48(env,auth.user);
        if (!permissions.includes('view_reports')) return { response: fail('Support permission required: view_reports.',403) };
        return { user: auth.user, row, staff: true, permissions };
    }
    return { user: auth.user, row, staff: false, permissions: [] };
}

async function getSupportCaseV77(request, env, caseId) {
    const access = await supportV77CaseAccess(request,env,caseId);
    if ('response' in access) return access.response;
    return json(await supportV77CasePayload(env,caseId,access.staff));
}

async function updateSupportCaseV77(request, env, caseId) {
    const access = await supportV77CaseAccess(request,env,caseId);
    if ('response' in access) return access.response;
    const body = await readJson(request);
    const action = String(body.action ?? '');
    const now = Date.now();
    const before = { status: access.row.status, assignedTo: access.row.assigned_to ?? null };
    if (!access.staff) {
        if (action !== 'reopen' || !['resolved','archived'].includes(access.row.status)) return fail('That case cannot be changed.',403);
        await env.DB.prepare(`UPDATE support_cases_v77 SET status='reviewing', resolved_at=NULL,resolved_by=NULL,archived_at=NULL,archived_by=NULL,updated_at=?,last_activity_at=? WHERE id=?`).bind(now,now,caseId).run();
        await env.DB.prepare(`INSERT INTO support_case_events_v77 (id,case_id,actor_user_id,event_type,body,metadata_json,created_at) VALUES (?,?,?,?,?,?,?)`).bind(crypto.randomUUID(),caseId,access.user.id,'reopened','Case reopened by member.','{}',now).run();
        return json(await supportV77CasePayload(env,caseId,false));
    }
    if (!(await supportV77CanManage(env,access.user,access.row))) return fail('Support permission required to manage this case.',403);
    if (action === 'take') await env.DB.prepare(`UPDATE support_cases_v77 SET assigned_to=?,status='reviewing',updated_at=?,last_activity_at=? WHERE id=?`).bind(access.user.id,now,now,caseId).run();
    else if (action === 'release') await env.DB.prepare(`UPDATE support_cases_v77 SET assigned_to=NULL,status='waiting',updated_at=?,last_activity_at=? WHERE id=?`).bind(now,now,caseId).run();
    else if (action === 'reviewing') await env.DB.prepare(`UPDATE support_cases_v77 SET status='reviewing',assigned_to=COALESCE(assigned_to,?),updated_at=?,last_activity_at=? WHERE id=?`).bind(access.user.id,now,now,caseId).run();
    else if (action === 'resolve') await env.DB.prepare(`UPDATE support_cases_v77 SET status='resolved',resolved_at=?,resolved_by=?,updated_at=?,last_activity_at=? WHERE id=?`).bind(now,access.user.id,now,now,caseId).run();
    else if (action === 'archive') {
        if (access.row.status !== 'resolved') return fail('Resolve the case before archiving it.',409);
        await env.DB.prepare(`UPDATE support_cases_v77 SET status='archived',archived_at=?,archived_by=?,updated_at=?,last_activity_at=? WHERE id=?`).bind(now,access.user.id,now,now,caseId).run();
    } else if (action === 'reopen') await env.DB.prepare(`UPDATE support_cases_v77 SET status='reviewing',assigned_to=COALESCE(assigned_to,?),resolved_at=NULL,resolved_by=NULL,archived_at=NULL,archived_by=NULL,updated_at=?,last_activity_at=? WHERE id=?`).bind(access.user.id,now,now,caseId).run();
    else return fail('Unknown case action.');
    const afterRow = await env.DB.prepare(`SELECT status,assigned_to FROM support_cases_v77 WHERE id=?`).bind(caseId).first();
    await env.DB.prepare(`INSERT INTO support_case_events_v77 (id,case_id,actor_user_id,event_type,body,metadata_json,created_at) VALUES (?,?,?,?,?,?,?)`).bind(crypto.randomUUID(),caseId,access.user.id,action,`Case ${action}.`,JSON.stringify({before,after:afterRow}),now).run();
    await supportV77Audit(env,access.user,`case.${action}`,'case',caseId,caseId,'','',before,afterRow ?? {},null);
    return json(await supportV77CasePayload(env,caseId,true));
}

// SPACES_V77_7_PERMANENT_DELETE
async function supportV77DeleteLegacyBackingV777(env, row) {
    const source = String(row.source ?? '');
    const caseId = String(row.id ?? '');
    if (source === 'legacy_ticket') {
        const legacyId = caseId.startsWith('legacy-ticket:') ? caseId.slice('legacy-ticket:'.length) : '';
        if (!legacyId) throw new Error('Legacy Support ticket id is missing.');
        try { await env.DB.prepare(`DELETE FROM support_messages WHERE ticket_id = ?`).bind(legacyId).run(); } catch {}
        try { await env.DB.prepare(`DELETE FROM support_ticket_events WHERE ticket_id = ?`).bind(legacyId).run(); } catch {}
        await env.DB.prepare(`DELETE FROM support_tickets WHERE id = ?`).bind(legacyId).run();
        const stillThere = await env.DB.prepare(`SELECT id FROM support_tickets WHERE id = ? LIMIT 1`).bind(legacyId).first();
        if (stillThere) throw new Error('Legacy Support ticket still exists after delete.');
    } else if (source === 'legacy_case') {
        const legacyId = caseId.startsWith('legacy-case:') ? caseId.slice('legacy-case:'.length) : '';
        if (!legacyId) throw new Error('Legacy Support case id is missing.');
        try { await env.DB.prepare(`DELETE FROM support_messages WHERE case_id = ?`).bind(legacyId).run(); } catch {}
        await env.DB.prepare(`DELETE FROM support_cases WHERE id = ?`).bind(legacyId).run();
        const stillThere = await env.DB.prepare(`SELECT id FROM support_cases WHERE id = ? LIMIT 1`).bind(legacyId).first();
        if (stillThere) throw new Error('Legacy Support case still exists after delete.');
    } else if (source === 'legacy_report') {
        const legacyId = caseId.startsWith('legacy-report:') ? caseId.slice('legacy-report:'.length) : '';
        if (!legacyId) throw new Error('Legacy report id is missing.');
        await env.DB.prepare(`DELETE FROM reports WHERE id = ?`).bind(legacyId).run();
        const stillThere = await env.DB.prepare(`SELECT id FROM reports WHERE id = ? LIMIT 1`).bind(legacyId).first();
        if (stillThere) throw new Error('Legacy report still exists after delete.');
    }
}

async function deleteSupportCaseV77(request, env, caseId) {
    const support = await requireSupportConsole(request,env);
    if ('response' in support) return support.response;
    if (support.user.platform_role !== 'creator') return fail('Only the Founder can permanently delete archived cases.',403);
    const row = await env.DB.prepare(`SELECT id,case_number,status,source FROM support_cases_v77 WHERE id=? LIMIT 1`).bind(caseId).first();
    if (!row) return fail('Support case not found.',404);
    if (row.status !== 'archived') return fail('Only archived cases can be permanently deleted.',409);

    // Remove the original V73/V75 backing row first. If that fails, keep the V77
    // case visible instead of returning success and letting legacy sync recreate it.
    try { await supportV77DeleteLegacyBackingV777(env,row); }
    catch (caught) { console.error('V77 permanent delete could not remove legacy backing data.',caught); return fail('Permanent deletion could not remove the original Support record.',500); }

    // Active moderation restrictions remain enforced, but lose the case link.
    await env.DB.prepare(`UPDATE support_restrictions_v77 SET case_id=NULL WHERE case_id=?`).bind(caseId).run();
    // Delete every case-linked audit/timeline/collaborator record before the case.
    await env.DB.prepare(`DELETE FROM support_audit_v77 WHERE case_id=? OR (target_type='case' AND target_id=?)`).bind(caseId,caseId).run();
    await env.DB.prepare(`DELETE FROM support_case_collaborators_v77 WHERE case_id=?`).bind(caseId).run();
    await env.DB.prepare(`DELETE FROM support_case_events_v77 WHERE case_id=?`).bind(caseId).run();
    await env.DB.prepare(`DELETE FROM support_cases_v77 WHERE id=?`).bind(caseId).run();

    const stillThere = await env.DB.prepare(`SELECT id FROM support_cases_v77 WHERE id=? LIMIT 1`).bind(caseId).first();
    if (stillThere) return fail('Permanent deletion did not complete.',500);
    return new Response(null,{status:204,headers:corsHeaders()});
}

async function addSupportCaseEventV77(request, env, caseId) {
    const access = await supportV77CaseAccess(request,env,caseId);
    if ('response' in access) return access.response;
    const body = await readJson(request);
    const eventType = String(body.eventType ?? 'message');
    const message = String(body.body ?? '').trim().slice(0,5000);
    if (!message) return fail('Message cannot be empty.');
    if (!access.staff && eventType !== 'message') return fail('Members can only reply to their Support case.',403);
    if (!access.staff && ['resolved','archived'].includes(access.row.status)) return fail('Reopen the case before replying.',409);
    if (access.staff && !(await supportV77CanManage(env,access.user,access.row))) return fail('Support permission required to reply to this case.',403);
    if (access.staff && !['message','note'].includes(eventType)) return fail('Invalid Support event type.');
    const now = Date.now();
    await env.DB.prepare(`INSERT INTO support_case_events_v77 (id,case_id,actor_user_id,event_type,body,metadata_json,created_at) VALUES (?,?,?,?,?,?,?)`).bind(crypto.randomUUID(),caseId,access.user.id,eventType,message,'{}',now).run();
    if (access.staff && eventType === 'message' && access.row.status === 'waiting') {
        await env.DB.prepare(`UPDATE support_cases_v77 SET status='reviewing',assigned_to=COALESCE(assigned_to,?),updated_at=?,last_activity_at=? WHERE id=?`).bind(access.user.id,now,now,caseId).run();
    } else {
        await env.DB.prepare(`UPDATE support_cases_v77 SET updated_at=?,last_activity_at=? WHERE id=?`).bind(now,now,caseId).run();
    }
    return json(await supportV77CasePayload(env,caseId,access.staff),201);
}

async function supportProfileV77(request, env, userId) {
    const auth = await requireUser(request,env);
    if ('response' in auth) return auth.response;
    const target = await env.DB.prepare(`SELECT * FROM users WHERE id=? LIMIT 1`).bind(userId).first();
    if (!target) return fail('Profile not found.',404);
    const isTeam = supportV77IsTeam(auth.user);
    const shared = await env.DB.prepare(`SELECT s.id,s.name,theirs.role FROM space_members mine JOIN space_members theirs ON theirs.space_id=mine.space_id JOIN spaces s ON s.id=mine.space_id WHERE mine.user_id=? AND theirs.user_id=? ORDER BY s.name LIMIT 100`).bind(auth.user.id,userId).all();
    const direct = await env.DB.prepare(`SELECT id FROM direct_conversations WHERE status='accepted' AND ((user_low_id=? AND user_high_id=?) OR (user_low_id=? AND user_high_id=?)) LIMIT 1`).bind(auth.user.id,userId,userId,auth.user.id).first();
    if (userId !== auth.user.id && !isTeam && !Boolean(target.public_profile) && !(shared.results ?? []).length && !direct) return fail('Profile is not available.',403);
    const base = publicProfile(target);
    base.presence = publicVisiblePresence(target.presence_status);
    let activeRestrictions = [];
    let recentCases = [];
    if (isTeam) {
        const permissions = await supportPermissionsForUserV48(env,auth.user);
        if (permissions.includes('view_accounts')) {
            const restrictions = await env.DB.prepare(`SELECT r.*, u.display_name created_by_name FROM support_restrictions_v77 r LEFT JOIN users u ON u.id=r.created_by WHERE r.target_type='user' AND r.target_id=? AND r.active=1 AND (r.expires_at IS NULL OR r.expires_at>?) ORDER BY r.created_at DESC LIMIT 50`).bind(userId,Date.now()).all();
            activeRestrictions = (restrictions.results ?? []).map(row => supportV77RestrictionPayload(row,target.display_name));
            const cases = await env.DB.prepare(`SELECT id,case_number,case_type,subject,status,updated_at FROM support_cases_v77 WHERE reporter_id=? OR target_user_id=? ORDER BY updated_at DESC LIMIT 30`).bind(userId,userId).all();
            recentCases = (cases.results ?? []).map(row => ({id:row.id,caseNumber:row.case_number,caseType:row.case_type,subject:row.subject,status:row.status,updatedAt:Number(row.updated_at)}));
        }
    }
    return json({...base,sharedSpaces:(shared.results ?? []).map(row=>({id:row.id,name:row.name,role:row.role})),activeRestrictions,recentCases});
}

function supportV77RestrictionPayload(row, targetLabel = '') {
    return { id:row.id,targetType:row.target_type,targetId:row.target_id,targetLabel:targetLabel || row.target_label || row.target_id,capability:row.capability,reasonCategory:row.reason_category,note:row.note ?? '',createdBy:row.created_by,createdByName:row.created_by_name ?? 'Support',createdAt:Number(row.created_at),expiresAt:row.expires_at?Number(row.expires_at):null,active:Boolean(row.active)&&(!row.expires_at||Number(row.expires_at)>Date.now()),caseId:row.case_id??null };
}

async function supportV77RestrictionPermission(env, user, targetType, capability) {
    if (user.platform_role === 'creator') return true;
    const permissions = await supportPermissionsForUserV48(env,user);
    if (targetType === 'space' || targetType === 'channel') return permissions.includes('space_restrict');
    if (capability === 'platform_access') return permissions.includes('ban_users');
    if (capability === 'create_spaces') return permissions.includes('space_create_restrict');
    if (capability === 'join_spaces') return permissions.includes('space_join_restrict');
    return permissions.includes('chat_restrict');
}

async function createSupportRestrictionV77(request, env) {
    const support = await requireSupportConsole(request,env);
    if ('response' in support) return support.response;
    const body = await readJson(request);
    const targetType = ['user','space','channel'].includes(body.targetType) ? body.targetType : '';
    const targetId = String(body.targetId ?? '');
    const capability = String(body.capability ?? '');
    if (!targetType || !targetId) return fail('Restriction target is required.');
    const allowed = targetType === 'user' ? SUPPORT_V77_USER_CAPABILITIES : targetType === 'space' ? SUPPORT_V77_SPACE_CAPABILITIES : SUPPORT_V77_CHANNEL_CAPABILITIES;
    if (!allowed.includes(capability)) return fail('Invalid restriction capability.');
    if (!(await supportV77RestrictionPermission(env,support.user,targetType,capability))) return fail('Your Support role cannot apply that restriction.',403);
    let targetLabel = targetId;
    if (targetType === 'user') {
        const target = await env.DB.prepare(`SELECT id,display_name,platform_role FROM users WHERE id=? LIMIT 1`).bind(targetId).first();
        if (!target) return fail('Account not found.',404);
        if (!supportRoleCanActOn(support.user.platform_role,target.platform_role)) return fail('Your Support role cannot act on that account.',403);
        targetLabel = target.display_name;
    } else if (targetType === 'space') {
        const target = await env.DB.prepare(`SELECT id,name FROM spaces WHERE id=? LIMIT 1`).bind(targetId).first(); if (!target) return fail('Space not found.',404); targetLabel=target.name;
    } else {
        const target = await env.DB.prepare(`SELECT c.id,c.name,s.name space_name FROM channels c JOIN spaces s ON s.id=c.space_id WHERE c.id=? LIMIT 1`).bind(targetId).first(); if (!target) return fail('Channel not found.',404); targetLabel=`${target.space_name} / #${target.name}`;
    }
    const duration = body.durationMinutes === null || body.durationMinutes === undefined ? null : Number(body.durationMinutes);
    const expiresAt = Number.isFinite(duration) && duration > 0 ? Date.now()+Math.min(duration,525600)*60000 : null;
    const reasonCategory = String(body.reasonCategory ?? 'Other').slice(0,120);
    const note = String(body.note ?? '').slice(0,1200);
    const id = crypto.randomUUID(); const now=Date.now();
    await env.DB.prepare(`INSERT INTO support_restrictions_v77 (id,target_type,target_id,capability,reason_category,note,created_by,created_at,expires_at,active,revoked_at,revoked_by,case_id) VALUES (?,?,?,?,?,?,?,?,?,1,NULL,NULL,?)`).bind(id,targetType,targetId,capability,reasonCategory,note,support.user.id,now,expiresAt,body.caseId?String(body.caseId):null).run();
    if (targetType === 'user' && capability === 'platform_access') await env.DB.prepare(`DELETE FROM sessions WHERE user_id=?`).bind(targetId).run();
    await supportV77Audit(env,support.user,'restriction.applied',targetType,targetId,body.caseId?String(body.caseId):null,reasonCategory,note,{}, {capability}, expiresAt);
    return json(supportV77RestrictionPayload({id,target_type:targetType,target_id:targetId,capability,reason_category:reasonCategory,note,created_by:support.user.id,created_by_name:support.user.display_name,created_at:now,expires_at:expiresAt,active:1,case_id:body.caseId??null},targetLabel),201);
}

async function listSupportRestrictionsV77(request, env) {
    const support = await requireSupportConsole(request,env);
    if ('response' in support) return support.response;
    const permissions = await supportPermissionsForUserV48(env,support.user);
    if (support.user.platform_role !== 'creator' && !permissions.includes('view_accounts')) return fail('Support permission required: view_accounts.',403);
    const now=Date.now();
    const result=await env.DB.prepare(`SELECT r.*,u.display_name created_by_name,
      CASE r.target_type WHEN 'user' THEN tu.display_name WHEN 'space' THEN s.name WHEN 'channel' THEN ch.name ELSE r.target_id END target_label
      FROM support_restrictions_v77 r LEFT JOIN users u ON u.id=r.created_by LEFT JOIN users tu ON r.target_type='user' AND tu.id=r.target_id LEFT JOIN spaces s ON r.target_type='space' AND s.id=r.target_id LEFT JOIN channels ch ON r.target_type='channel' AND ch.id=r.target_id
      WHERE r.active=1 AND (r.expires_at IS NULL OR r.expires_at>?) ORDER BY r.created_at DESC LIMIT 500`).bind(now).all();
    return json((result.results??[]).map(row=>supportV77RestrictionPayload(row,row.target_label)));
}

async function revokeSupportRestrictionV77(request, env, restrictionId) {
    const support=await requireSupportConsole(request,env); if('response' in support)return support.response;
    const row=await env.DB.prepare(`SELECT * FROM support_restrictions_v77 WHERE id=? LIMIT 1`).bind(restrictionId).first(); if(!row)return fail('Restriction not found.',404);
    if(!(await supportV77RestrictionPermission(env,support.user,row.target_type,row.capability)))return fail('Your Support role cannot remove that restriction.',403);
    if(row.target_type==='user'){const target=await env.DB.prepare(`SELECT platform_role FROM users WHERE id=?`).bind(row.target_id).first();if(target&&!supportRoleCanActOn(support.user.platform_role,target.platform_role))return fail('Your Support role cannot act on that account.',403);}
    const now=Date.now();await env.DB.prepare(`UPDATE support_restrictions_v77 SET active=0,revoked_at=?,revoked_by=? WHERE id=?`).bind(now,support.user.id,restrictionId).run();
    await supportV77Audit(env,support.user,'restriction.revoked',row.target_type,row.target_id,row.case_id??null,row.reason_category,'Restriction removed.',{capability:row.capability},{active:false},null);
    return new Response(null,{status:204,headers:corsHeaders()});
}

async function sendSupportNoticeV77(request, env) {
    const support = await requireSupportCapability(request,env,'send_support_dms');
    if ('response' in support) return support.response;
    const body = await readJson(request);
    const recipientUserId = String(body.recipientUserId ?? '');
    const subject = String(body.subject ?? 'Spaces Support notice').trim().slice(0,180);
    const message = String(body.body ?? '').trim().slice(0,5000);
    if (!recipientUserId || !message) return fail('Recipient and message are required.');
    const recipient = await env.DB.prepare(`SELECT id,display_name,platform_role FROM users WHERE id=? LIMIT 1`).bind(recipientUserId).first();
    if (!recipient) return fail('Account not found.',404);
    const now=Date.now(); const id=crypto.randomUUID(); const caseNumber=supportV77CaseNumber();
    await env.DB.prepare(`INSERT INTO support_cases_v77
      (id,case_number,case_type,subtype,reporter_id,target_user_id,target_space_id,target_channel_id,subject,answers_json,details,priority,status,assigned_to,source,created_at,updated_at,last_activity_at,resolved_at,resolved_by,archived_at,archived_by)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?, 'reviewing', ?, 'staff_created', ?,?,?,NULL,NULL,NULL,NULL)`)
      .bind(id,caseNumber,'request','Support notice',recipientUserId,recipientUserId,body.targetSpaceId?String(body.targetSpaceId):null,null,subject,'{}','',String(body.priority??'normal'),support.user.id,now,now,now).run();
    await env.DB.prepare(`INSERT INTO support_case_events_v77 (id,case_id,actor_user_id,event_type,body,metadata_json,created_at) VALUES (?,?,?,?,?,?,?)`).bind(crypto.randomUUID(),id,support.user.id,'message',message,JSON.stringify({notice:true}),now).run();
    await supportV77Audit(env,support.user,'support.notice_sent','user',recipientUserId,id,String(body.reasonCategory??'Support notice'),'',{}, {caseNumber},null);
    return json(await supportV77CasePayload(env,id,true),201);
}

async function listSupportAuditV77(request, env) {
    const support=await requireSupportConsole(request,env);if('response' in support)return support.response;
    const permissions=await supportPermissionsForUserV48(env,support.user);if(support.user.platform_role!=='creator'&&!permissions.includes('view_audit'))return fail('Support permission required: view_audit.',403);
    const result=await env.DB.prepare(`SELECT a.*,u.display_name actor_name,
      CASE a.target_type WHEN 'user' THEN tu.display_name WHEN 'space' THEN s.name WHEN 'channel' THEN ch.name ELSE a.target_id END target_label
      FROM support_audit_v77 a LEFT JOIN users u ON u.id=a.actor_id LEFT JOIN users tu ON a.target_type='user' AND tu.id=a.target_id LEFT JOIN spaces s ON a.target_type='space' AND s.id=a.target_id LEFT JOIN channels ch ON a.target_type='channel' AND ch.id=a.target_id
      ORDER BY a.created_at DESC LIMIT 800`).all();
    return json((result.results??[]).map(row=>({id:row.id,actorId:row.actor_id,actorName:row.actor_name??'Support',actorRole:supportV77ClientRole(row.actor_role),action:row.action,targetType:row.target_type,targetId:row.target_id,targetLabel:row.target_label??row.target_id,caseId:row.case_id??null,reasonCategory:row.reason_category??'',note:row.note??'',expiresAt:row.expires_at?Number(row.expires_at):null,createdAt:Number(row.created_at)})));
}
// ---- End Spaces V77 Support Operations ---------------------------------------------


async function listSupportCases(request, env) {
    const support = await requireSupportCapability(request, env, 'view_reports');
    if ('response' in support) return support.response;
    const rows = await env.DB.prepare(`SELECT
        c.*, reporter.display_name AS reporter_name, reporter.username AS reporter_username,
        reporter.public_user_id AS reporter_public_user_id,
        s.name AS workspace_name, s.owner_user_id AS workspace_owner_id,
        owner.display_name AS workspace_owner_name, owner.public_user_id AS workspace_owner_public_user_id,
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
      ORDER BY CASE WHEN c.archived_at IS NULL THEN 0 ELSE 1 END,
               CASE c.priority WHEN 'urgent' THEN 0 WHEN 'high' THEN 1 WHEN 'normal' THEN 2 ELSE 3 END,
               CASE c.status WHEN 'open' THEN 0 WHEN 'reviewed' THEN 1 ELSE 2 END,
               c.created_at DESC LIMIT 300`).bind(Date.now()).all();
    return json((rows.results ?? []).map(row => ({
      id: row.id, kind: row.kind,
      reporterId: row.reporter_id, reporterName: row.reporter_name, reporterUsername: row.reporter_username,
      reporterPublicUserId: row.reporter_public_user_id ?? '',
      targetWorkspaceId: row.target_workspace_id ?? null, targetWorkspaceName: row.workspace_name ?? null,
      targetWorkspaceOwnerId: row.workspace_owner_id ?? null, targetWorkspaceOwnerName: row.workspace_owner_name ?? null,
      targetWorkspaceOwnerPublicUserId: row.workspace_owner_public_user_id ?? '',
      subject: row.subject, details: row.details, status: row.status, priority: row.priority,
      assignedTo: row.assigned_to ?? null, assignedToName: row.assigned_to_name ?? null,
      restricted: Boolean(row.restricted), archivedAt: row.archived_at ? Number(row.archived_at) : null,
      archivedBy: row.archived_by ?? null,
      createdAt: Number(row.created_at), updatedAt: Number(row.updated_at), resolvedAt: row.resolved_at ? Number(row.resolved_at) : null,
    })));
}

async function updateSupportCase(request, env, caseId) {
    const existing = await env.DB.prepare(`SELECT * FROM support_cases WHERE id = ? LIMIT 1`).bind(caseId).first();
    if (!existing) return fail('Support case not found.', 404);
    const support = existing.kind === 'bug'
      ? await requireSupportCapabilityAnyV53(request, env, ['manage_bugs', 'manage_reports'])
      : await requireSupportCapability(request, env, 'manage_reports');
    if ('response' in support) return support.response;
    const body = await readJson(request);
    const status = body.status;
    const priority = body.priority;
    if (status !== undefined && !['open','reviewed','actioned','resolved','dismissed'].includes(status)) return fail('Invalid support case status.');
    if (priority !== undefined && !['low','normal','high','urgent'].includes(priority)) return fail('Invalid support priority.');
    const nextStatus = status ?? existing.status;
    const nextPriority = priority ?? existing.priority;
    const assignedTo = body.assignToMe === true ? support.user.id : body.assignToMe === false ? null : existing.assigned_to;
    const now = Date.now();
    await env.DB.prepare(`UPDATE support_cases SET status = ?, priority = ?, assigned_to = ?, updated_at = ?, resolved_at = ? WHERE id = ?`)
      .bind(nextStatus, nextPriority, assignedTo, now, ['resolved','dismissed','actioned'].includes(nextStatus) ? now : null, caseId).run();
    return getSupportCaseById(env, caseId);
}


const SUPPORT_TICKET_STATUSES_V73 = new Set(['waiting', 'taken', 'reviewing', 'resolving', 'resolved']);
const SUPPORT_TICKET_RETENTION_MS_V73 = 60 * 24 * 60 * 60 * 1000;

function isSupportTeamUserV73(user) {
    return ['creator', 'staff', 'support'].includes(String(user?.platform_role ?? ''));
}

async function supportTicketDefaultRecipientV73(env) {
    return env.DB.prepare(`SELECT id, display_name, username
      FROM users
      WHERE platform_role IN ('creator', 'staff', 'support')
      ORDER BY CASE platform_role WHEN 'creator' THEN 0 WHEN 'staff' THEN 1 ELSE 2 END,
               created_at ASC
      LIMIT 1`).first();
}

async function uniqueSupportTicketNumberV73(env) {
    const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    for (let attempt = 0; attempt < 24; attempt += 1) {
        let code = 'SP-';
        for (let i = 0; i < 6; i += 1) {
            code += alphabet[Math.floor(Math.random() * alphabet.length)];
        }
        const existing = await env.DB.prepare(
            `SELECT id FROM support_tickets WHERE ticket_number = ? LIMIT 1`
        ).bind(code).first();
        if (!existing) return code;
    }
    return `SP-${randomAlphaNumeric(10).toUpperCase()}`;
}

async function addSupportTicketEventV73(env, ticketId, actorUserId, eventType, metadata = {}) {
    await env.DB.prepare(`INSERT INTO support_ticket_events
      (id, ticket_id, actor_user_id, event_type, metadata_json, created_at)
      VALUES (?, ?, ?, ?, ?, ?)`)
      .bind(
        crypto.randomUUID(),
        ticketId,
        actorUserId || null,
        eventType,
        JSON.stringify(metadata ?? {}),
        Date.now(),
      )
      .run();
}

async function cleanupExpiredSupportTicketTranscriptsV73(env) {
    const now = Date.now();
    const expired = await env.DB.prepare(`SELECT id
      FROM support_tickets
      WHERE status = 'resolved'
        AND delete_after IS NOT NULL
        AND delete_after <= ?
        AND transcript_deleted_at IS NULL
      LIMIT 100`).bind(now).all();

    for (const row of expired.results ?? []) {
        await env.DB.prepare(`DELETE FROM support_messages WHERE ticket_id = ?`)
          .bind(row.id)
          .run();
        await env.DB.prepare(`UPDATE support_tickets
          SET transcript_deleted_at = ?, updated_at = ?
          WHERE id = ?`)
          .bind(now, now, row.id)
          .run();
        await addSupportTicketEventV73(
          env,
          row.id,
          null,
          'auto_transcript_deleted',
          { retentionDays: 60 },
        );
    }
}

async function supportTicketRowV73(env, ticketNumber) {
    return env.DB.prepare(`SELECT
        t.*,
        owner.display_name AS user_name,
        owner.username AS username,
        owner.public_user_id AS user_public_user_id,
        owner.avatar_url AS user_avatar_url,
        assignee.display_name AS assigned_name,
        assignee.username AS assigned_username
      FROM support_tickets t
      JOIN users owner ON owner.id = t.user_id
      LEFT JOIN users assignee ON assignee.id = t.assigned_to
      WHERE t.ticket_number = ?
      LIMIT 1`)
      .bind(ticketNumber)
      .first();
}

function supportTicketPayloadV73(row) {
    return {
        id: row.id,
        ticketNumber: row.ticket_number,
        userId: row.user_id,
        userName: row.user_name,
        username: row.username,
        userPublicUserId: row.user_public_user_id ?? '',
        userAvatarUrl: row.user_avatar_url ?? null,
        topic: row.topic,
        status: row.status,
        assignedTo: row.assigned_to ?? null,
        assignedName: row.assigned_name ?? null,
        assignedUsername: row.assigned_username ?? null,
        createdAt: Number(row.created_at ?? 0),
        updatedAt: Number(row.updated_at ?? 0),
        resolvedAt: row.resolved_at ? Number(row.resolved_at) : null,
        lastActivityAt: Number(row.last_activity_at ?? row.updated_at ?? row.created_at ?? 0),
        deleteAfter: row.delete_after ? Number(row.delete_after) : null,
        reopenedAt: row.reopened_at ? Number(row.reopened_at) : null,
        transcriptDeletedAt: row.transcript_deleted_at ? Number(row.transcript_deleted_at) : null,
    };
}

async function supportTicketDetailForUserV73(env, authUser, ticketNumber) {
    await cleanupExpiredSupportTicketTranscriptsV73(env);
    const row = await supportTicketRowV73(env, ticketNumber);
    if (!row) return null;

    const staff = isSupportTeamUserV73(authUser);
    if (!staff && row.user_id !== authUser.id) return null;

    const messages = await env.DB.prepare(`SELECT
        m.id,
        m.ticket_id,
        m.recipient_user_id,
        recipient.display_name AS recipient_name,
        m.sender_user_id,
        sender.display_name AS sender_name,
        sender.username AS sender_username,
        m.subject,
        m.body,
        m.message_kind,
        m.created_at,
        m.read_at
      FROM support_messages m
      JOIN users recipient ON recipient.id = m.recipient_user_id
      JOIN users sender ON sender.id = m.sender_user_id
      WHERE m.ticket_id = ?
      ORDER BY m.created_at ASC
      LIMIT 1000`)
      .bind(row.id)
      .all();

    await env.DB.prepare(`UPDATE support_messages
      SET read_at = COALESCE(read_at, ?)
      WHERE ticket_id = ?
        AND recipient_user_id = ?
        AND read_at IS NULL`)
      .bind(Date.now(), row.id, authUser.id)
      .run();

    const events = await env.DB.prepare(`SELECT
        e.id,
        e.actor_user_id,
        actor.display_name AS actor_name,
        e.event_type,
        e.metadata_json,
        e.created_at
      FROM support_ticket_events e
      LEFT JOIN users actor ON actor.id = e.actor_user_id
      WHERE e.ticket_id = ?
      ORDER BY e.created_at ASC
      LIMIT 1000`)
      .bind(row.id)
      .all();

    const collaborators = await env.DB.prepare(`SELECT
        c.user_id,
        u.display_name,
        u.username,
        u.public_user_id,
        u.platform_role
      FROM support_ticket_collaborators c
      JOIN users u ON u.id = c.user_id
      WHERE c.ticket_id = ?
      ORDER BY c.added_at ASC`)
      .bind(row.id)
      .all();

    return {
        ticket: supportTicketPayloadV73(row),
        messages: (messages.results ?? []).map(message => ({
            id: message.id,
            ticketId: message.ticket_id,
            recipientUserId: message.recipient_user_id,
            recipientName: message.recipient_name,
            senderUserId: message.sender_user_id,
            senderName: message.sender_name,
            senderUsername: message.sender_username,
            subject: message.subject,
            body: message.body,
            messageKind: message.message_kind ?? 'official',
            createdAt: Number(message.created_at ?? 0),
            readAt: message.read_at ? Number(message.read_at) : null,
        })),
        events: (events.results ?? []).map(event => {
            let metadata = {};
            try { metadata = JSON.parse(event.metadata_json || '{}'); } catch { metadata = {}; }
            return {
                id: event.id,
                eventType: event.event_type,
                actorUserId: event.actor_user_id ?? null,
                actorName: event.actor_name ?? null,
                metadata,
                createdAt: Number(event.created_at ?? 0),
            };
        }),
        collaborators: (collaborators.results ?? []).map(person => ({
            userId: person.user_id,
            displayName: person.display_name,
            username: person.username,
            publicUserId: person.public_user_id ?? '',
            platformRole: clientPlatformRole(person.platform_role),
        })),
    };
}

async function listSupportTicketsV73(request, env) {
    const auth = await requireUser(request, env);
    if ('response' in auth) return auth.response;
    await cleanupExpiredSupportTicketTranscriptsV73(env);

    const staff = isSupportTeamUserV73(auth.user);
    const result = staff
      ? await env.DB.prepare(`SELECT
          t.*,
          owner.display_name AS user_name,
          owner.username AS username,
          owner.public_user_id AS user_public_user_id,
          owner.avatar_url AS user_avatar_url,
          assignee.display_name AS assigned_name,
          assignee.username AS assigned_username
        FROM support_tickets t
        JOIN users owner ON owner.id = t.user_id
        LEFT JOIN users assignee ON assignee.id = t.assigned_to
        ORDER BY t.last_activity_at DESC
        LIMIT 500`).all()
      : await env.DB.prepare(`SELECT
          t.*,
          owner.display_name AS user_name,
          owner.username AS username,
          owner.public_user_id AS user_public_user_id,
          owner.avatar_url AS user_avatar_url,
          assignee.display_name AS assigned_name,
          assignee.username AS assigned_username
        FROM support_tickets t
        JOIN users owner ON owner.id = t.user_id
        LEFT JOIN users assignee ON assignee.id = t.assigned_to
        WHERE t.user_id = ?
        ORDER BY t.last_activity_at DESC
        LIMIT 100`).bind(auth.user.id).all();

    return json((result.results ?? []).map(supportTicketPayloadV73));
}

async function getSupportTicketV73(request, env, ticketNumber) {
    const auth = await requireUser(request, env);
    if ('response' in auth) return auth.response;
    const detail = await supportTicketDetailForUserV73(env, auth.user, ticketNumber);
    if (!detail) return fail('Support ticket not found.', 404);
    return json(detail);
}

async function createSupportTicketV73(request, env) {
    const auth = await requireUser(request, env);
    if ('response' in auth) return auth.response;
    await enforceRateLimit(request, env, 'support-ticket-create-v73', 12, 1000 * 60 * 60, auth.user.id);

    const body = await readJson(request);
    const topic = String(body.topic ?? '').trim().slice(0, 120);
    const messageBody = String(body.message ?? '').trim().slice(0, 2400);
    if (topic.length < 2 || messageBody.length < 2) {
        return fail('A topic and first message are required.');
    }

    const recipient = await supportTicketDefaultRecipientV73(env);
    if (!recipient) return fail('Spaces Support is not available yet.', 503);

    const now = Date.now();
    const id = crypto.randomUUID();
    const ticketNumber = await uniqueSupportTicketNumberV73(env);

    await env.DB.prepare(`INSERT INTO support_tickets
      (id, ticket_number, user_id, topic, status, assigned_to, created_at, updated_at,
       resolved_at, resolved_by, last_activity_at, delete_after, reopened_at, transcript_deleted_at)
      VALUES (?, ?, ?, ?, 'waiting', NULL, ?, ?, NULL, NULL, ?, NULL, NULL, NULL)`)
      .bind(id, ticketNumber, auth.user.id, topic, now, now, now)
      .run();

    await env.DB.prepare(`INSERT INTO support_messages
      (id, recipient_user_id, sender_user_id, case_id, subject, body, message_kind,
       reply_to_message_id, created_at, read_at, ticket_id)
      VALUES (?, ?, ?, NULL, ?, ?, 'reply', NULL, ?, NULL, ?)`)
      .bind(
        crypto.randomUUID(),
        recipient.id,
        auth.user.id,
        topic,
        messageBody,
        now,
        id,
      )
      .run();

    await addSupportTicketEventV73(env, id, auth.user.id, 'created', { topic, ticketNumber });

    const detail = await supportTicketDetailForUserV73(env, auth.user, ticketNumber);
    return json(detail, 201);
}

async function reopenSupportTicketV73(request, env, ticketNumber) {
    const auth = await requireUser(request, env);
    if ('response' in auth) return auth.response;

    const row = await supportTicketRowV73(env, ticketNumber);
    if (!row || row.user_id !== auth.user.id) return fail('Support ticket not found.', 404);
    if (row.status !== 'resolved') return fail('That ticket is already active.', 409);
    if (row.transcript_deleted_at) return fail('That ticket can no longer be reopened. Start a new topic instead.', 409);
    if (row.delete_after && Number(row.delete_after) <= Date.now()) {
        return fail('That ticket has expired. Start a new topic instead.', 409);
    }

    const now = Date.now();
    await env.DB.prepare(`UPDATE support_tickets
      SET status = 'waiting',
          assigned_to = NULL,
          updated_at = ?,
          resolved_at = NULL,
          resolved_by = NULL,
          last_activity_at = ?,
          delete_after = NULL,
          reopened_at = ?
      WHERE id = ?`)
      .bind(now, now, now, row.id)
      .run();
    await env.DB.prepare(`DELETE FROM support_ticket_collaborators WHERE ticket_id = ?`)
      .bind(row.id)
      .run();
    await addSupportTicketEventV73(env, row.id, auth.user.id, 'reopened', { ticketNumber });

    const detail = await supportTicketDetailForUserV73(env, auth.user, ticketNumber);
    return json(detail);
}

async function sendSupportTicketMessageV73(request, env, ticketNumber) {
    const auth = await requireUser(request, env);
    if ('response' in auth) return auth.response;
    await enforceRateLimit(request, env, 'support-ticket-message-v73', 120, 1000 * 60 * 60, auth.user.id);

    const row = await supportTicketRowV73(env, ticketNumber);
    if (!row) return fail('Support ticket not found.', 404);

    const staff = isSupportTeamUserV73(auth.user);
    if (!staff && row.user_id !== auth.user.id) return fail('Support ticket not found.', 404);
    if (row.status === 'resolved') return fail('Choose Current Topic or New Topic before sending another message.', 409);
    if (row.transcript_deleted_at) return fail('This ticket transcript was deleted. Start a new topic.', 409);

    if (staff) {
        const support = await requireSupportCapability(request, env, 'send_support_dms');
        if ('response' in support) return support.response;
    }

    const body = await readJson(request);
    const messageBody = String(body.body ?? '').trim().slice(0, 2400);
    if (!messageBody) return fail('Write a message first.');

    const now = Date.now();
    let recipientUserId = row.user_id;
    let messageKind = 'official';

    if (!staff) {
        const recipient = row.assigned_to
          ? { id: row.assigned_to }
          : await supportTicketDefaultRecipientV73(env);
        if (!recipient?.id) return fail('Spaces Support is not available yet.', 503);
        recipientUserId = recipient.id;
        messageKind = 'reply';
    } else if (!row.assigned_to) {
        await env.DB.prepare(`UPDATE support_tickets
          SET assigned_to = ?, status = 'taken', updated_at = ?
          WHERE id = ?`)
          .bind(auth.user.id, now, row.id)
          .run();
        await addSupportTicketEventV73(env, row.id, auth.user.id, 'taken', {
            displayName: auth.user.display_name,
        });
    } else if (row.assigned_to !== auth.user.id) {
        await env.DB.prepare(`INSERT OR IGNORE INTO support_ticket_collaborators
          (ticket_id, user_id, added_by, added_at)
          VALUES (?, ?, ?, ?)`)
          .bind(row.id, auth.user.id, auth.user.id, now)
          .run();
    }

    await env.DB.prepare(`INSERT INTO support_messages
      (id, recipient_user_id, sender_user_id, case_id, subject, body, message_kind,
       reply_to_message_id, created_at, read_at, ticket_id)
      VALUES (?, ?, ?, NULL, ?, ?, ?, NULL, ?, NULL, ?)`)
      .bind(
        crypto.randomUUID(),
        recipientUserId,
        auth.user.id,
        row.topic,
        messageBody,
        messageKind,
        now,
        row.id,
      )
      .run();

    await env.DB.prepare(`UPDATE support_tickets
      SET updated_at = ?, last_activity_at = ?
      WHERE id = ?`)
      .bind(now, now, row.id)
      .run();

    const detail = await supportTicketDetailForUserV73(env, auth.user, ticketNumber);
    return json(detail);
}

async function resolveSupportTeamUserV73(env, queryValue) {
    const clean = String(queryValue ?? '').trim().replace(/^[@#]/, '');
    if (!clean) return null;
    return env.DB.prepare(`SELECT id, display_name, username, public_user_id, platform_role
      FROM users
      WHERE platform_role IN ('creator', 'staff', 'support')
        AND (id = ? OR public_user_id = ? OR username = ? COLLATE NOCASE)
      ORDER BY CASE WHEN id = ? THEN 0 WHEN public_user_id = ? THEN 1 ELSE 2 END
      LIMIT 1`)
      .bind(clean, clean, clean, clean, clean)
      .first();
}

async function updateSupportTicketV73(request, env, ticketNumber) {
    const support = await requireSupportCapability(request, env, 'send_support_dms');
    if ('response' in support) return support.response;

    const row = await supportTicketRowV73(env, ticketNumber);
    if (!row) return fail('Support ticket not found.', 404);

    const body = await readJson(request);
    const now = Date.now();
    let status = row.status;
    let assignedTo = row.assigned_to ?? null;
    let topic = row.topic;
    let resolvedAt = row.resolved_at ?? null;
    let resolvedBy = row.resolved_by ?? null;
    let deleteAfter = row.delete_after ?? null;
    let reopenedAt = row.reopened_at ?? null;

    if (body.take === true) {
        assignedTo = support.user.id;
        status = 'taken';
        await addSupportTicketEventV73(env, row.id, support.user.id, 'taken', {
            displayName: support.user.display_name,
        });
    }

    if (body.assignToMe === true) {
        assignedTo = support.user.id;
        if (status === 'waiting') status = 'taken';
        await addSupportTicketEventV73(env, row.id, support.user.id, 'assigned', {
            displayName: support.user.display_name,
            username: support.user.username,
        });
    }

    if (body.assigneeQuery) {
        const nextAssignee = await resolveSupportTeamUserV73(env, body.assigneeQuery);
        if (!nextAssignee) return fail('That Staff or Support account was not found.', 404);
        assignedTo = nextAssignee.id;
        if (status === 'waiting') status = 'taken';
        await addSupportTicketEventV73(env, row.id, support.user.id, 'assigned', {
            displayName: nextAssignee.display_name,
            username: nextAssignee.username,
        });
    }

    if (body.unassign === true) {
        assignedTo = null;
        if (status !== 'resolved') status = 'waiting';
        await addSupportTicketEventV73(env, row.id, support.user.id, 'unassigned', {});
    }

    if (body.topic !== undefined) {
        const nextTopic = String(body.topic ?? '').trim().slice(0, 120);
        if (nextTopic.length < 2) return fail('Ticket topic is too short.');
        if (nextTopic !== topic) {
            topic = nextTopic;
            await addSupportTicketEventV73(env, row.id, support.user.id, 'topic_changed', {
                topic: nextTopic,
            });
        }
    }

    if (body.status !== undefined) {
        const nextStatus = String(body.status);
        if (!SUPPORT_TICKET_STATUSES_V73.has(nextStatus)) return fail('Invalid ticket status.');
        if (nextStatus === 'waiting' && row.transcript_deleted_at) {
            return fail('A deleted ticket transcript cannot be reopened.', 409);
        }

        if (nextStatus === 'resolved' && row.status !== 'resolved') {
            status = 'resolved';
            resolvedAt = now;
            resolvedBy = support.user.id;
            deleteAfter = now + SUPPORT_TICKET_RETENTION_MS_V73;
            await addSupportTicketEventV73(env, row.id, support.user.id, 'resolved', {
                displayName: support.user.display_name,
            });
            await env.DB.prepare(`INSERT INTO support_messages
              (id, recipient_user_id, sender_user_id, case_id, subject, body, message_kind,
               reply_to_message_id, created_at, read_at, ticket_id)
              VALUES (?, ?, ?, NULL, ?, ?, 'official', NULL, ?, NULL, ?)`)
              .bind(
                crypto.randomUUID(),
                row.user_id,
                support.user.id,
                `Ticket ${row.ticket_number} resolved`,
                `Ticket ${row.ticket_number} has been resolved by Spaces Support.`,
                now,
                row.id,
              )
              .run();
        } else if (nextStatus !== 'resolved') {
            if (row.status === 'resolved') {
                resolvedAt = null;
                resolvedBy = null;
                deleteAfter = null;
                reopenedAt = now;
                if (nextStatus === 'waiting') assignedTo = null;
                await addSupportTicketEventV73(env, row.id, support.user.id, 'reopened', {
                    ticketNumber: row.ticket_number,
                });
            } else if (nextStatus !== status) {
                await addSupportTicketEventV73(env, row.id, support.user.id, 'status_changed', {
                    status: nextStatus,
                });
            }
            status = nextStatus;
        }
    }

    await env.DB.prepare(`UPDATE support_tickets
      SET topic = ?,
          status = ?,
          assigned_to = ?,
          updated_at = ?,
          last_activity_at = ?,
          resolved_at = ?,
          resolved_by = ?,
          delete_after = ?,
          reopened_at = ?
      WHERE id = ?`)
      .bind(
        topic,
        status,
        assignedTo,
        now,
        now,
        resolvedAt,
        resolvedBy,
        deleteAfter,
        reopenedAt,
        row.id,
      )
      .run();

    const detail = await supportTicketDetailForUserV73(env, support.user, ticketNumber);
    return json(detail);
}

async function addSupportTicketCollaboratorV73(request, env, ticketNumber) {
    const support = await requireSupportCapability(request, env, 'send_support_dms');
    if ('response' in support) return support.response;

    const row = await supportTicketRowV73(env, ticketNumber);
    if (!row) return fail('Support ticket not found.', 404);

    const body = await readJson(request);
    const person = await resolveSupportTeamUserV73(env, body.userQuery);
    if (!person) return fail('That Staff or Support account was not found.', 404);
    if (person.id === row.assigned_to) {
        const detail = await supportTicketDetailForUserV73(env, support.user, ticketNumber);
        return json(detail);
    }

    const now = Date.now();
    await env.DB.prepare(`INSERT OR IGNORE INTO support_ticket_collaborators
      (ticket_id, user_id, added_by, added_at)
      VALUES (?, ?, ?, ?)`)
      .bind(row.id, person.id, support.user.id, now)
      .run();
    await addSupportTicketEventV73(env, row.id, support.user.id, 'collaborator_added', {
        userId: person.id,
        displayName: person.display_name,
        username: person.username,
    });

    const detail = await supportTicketDetailForUserV73(env, support.user, ticketNumber);
    return json(detail);
}

async function removeSupportTicketCollaboratorV73(request, env, ticketNumber, userId) {
    const support = await requireSupportCapability(request, env, 'send_support_dms');
    if ('response' in support) return support.response;

    const row = await supportTicketRowV73(env, ticketNumber);
    if (!row) return fail('Support ticket not found.', 404);

    const person = await env.DB.prepare(`SELECT display_name, username
      FROM users WHERE id = ? LIMIT 1`).bind(userId).first();

    await env.DB.prepare(`DELETE FROM support_ticket_collaborators
      WHERE ticket_id = ? AND user_id = ?`)
      .bind(row.id, userId)
      .run();

    await addSupportTicketEventV73(env, row.id, support.user.id, 'collaborator_removed', {
        userId,
        displayName: person?.display_name ?? 'Team member',
        username: person?.username ?? '',
    });

    const detail = await supportTicketDetailForUserV73(env, support.user, ticketNumber);
    return json(detail);
}

async function deleteSupportTicketTranscriptV73(request, env, ticketNumber) {
    const support = await requireSupportCapability(request, env, 'send_support_dms');
    if ('response' in support) return support.response;

    const row = await supportTicketRowV73(env, ticketNumber);
    if (!row) return fail('Support ticket not found.', 404);

    const now = Date.now();
    await env.DB.prepare(`DELETE FROM support_messages WHERE ticket_id = ?`)
      .bind(row.id)
      .run();

    await env.DB.prepare(`UPDATE support_tickets
      SET status = 'resolved',
          resolved_at = COALESCE(resolved_at, ?),
          resolved_by = COALESCE(resolved_by, ?),
          delete_after = COALESCE(delete_after, ?),
          transcript_deleted_at = ?,
          updated_at = ?,
          last_activity_at = ?
      WHERE id = ?`)
      .bind(
        now,
        support.user.id,
        now + SUPPORT_TICKET_RETENTION_MS_V73,
        now,
        now,
        now,
        row.id,
      )
      .run();

    await addSupportTicketEventV73(env, row.id, support.user.id, 'closed', {
        displayName: support.user.display_name,
    });
    await addSupportTicketEventV73(env, row.id, support.user.id, 'transcript_deleted', {});

    await env.DB.prepare(`INSERT INTO support_messages
      (id, recipient_user_id, sender_user_id, case_id, subject, body, message_kind,
       reply_to_message_id, created_at, read_at, ticket_id)
      VALUES (?, ?, ?, NULL, ?, ?, 'official', NULL, ?, NULL, NULL)`)
      .bind(
        crypto.randomUUID(),
        row.user_id,
        support.user.id,
        `Ticket ${row.ticket_number} closed`,
        `Ticket ${row.ticket_number} has been closed by Spaces Support.`,
        now,
      )
      .run();

    return new Response(null, { status: 204, headers: corsHeaders() });
}

async function listSupportMessages(request, env) {
    const support = await requireSupportCapability(request, env, 'send_support_dms');
    if ('response' in support) return support.response;
    const result = await env.DB.prepare(`SELECT m.*,
      recipient.display_name AS recipient_name, recipient.username AS recipient_username,
      sender.display_name AS sender_name, sender.username AS sender_username
      FROM support_messages m
      JOIN users recipient ON recipient.id = m.recipient_user_id
      JOIN users sender ON sender.id = m.sender_user_id
      ORDER BY m.created_at DESC LIMIT 500`).all();
    return json((result.results ?? []).map(row => ({
      id: row.id, recipientUserId: row.recipient_user_id, recipientName: row.recipient_name,
      recipientUsername: row.recipient_username, senderUserId: row.sender_user_id,
      senderName: row.sender_name, senderUsername: row.sender_username, caseId: row.case_id ?? null,
      subject: row.subject, body: row.body, messageKind: row.message_kind ?? 'official',
      replyToMessageId: row.reply_to_message_id ?? null, createdAt: Number(row.created_at),
      readAt: row.read_at ? Number(row.read_at) : null,
    })));
}

async function sendSupportMessage(request, env) {
    const support = await requireSupportCapability(request, env, 'send_support_dms');
    if ('response' in support) return support.response;
    const body = await readJson(request);
    const recipientUserId = String(body.recipientUserId ?? '');
    const subject = String(body.subject ?? '').trim().slice(0, 120);
    const messageBody = String(body.body ?? '').trim().slice(0, 2400);
    const caseId = body.caseId ? String(body.caseId) : null;
    if (!recipientUserId || subject.length < 2 || messageBody.length < 2) return fail('Recipient, subject and message are required.');
    const recipient = await env.DB.prepare(`SELECT id, display_name, username FROM users WHERE id = ? LIMIT 1`).bind(recipientUserId).first();
    if (!recipient) return fail('Recipient account not found.', 404);
    const id = crypto.randomUUID(); const now = Date.now();
    await env.DB.prepare(`INSERT INTO support_messages
      (id, recipient_user_id, sender_user_id, case_id, subject, body, message_kind, reply_to_message_id, created_at, read_at)
      VALUES (?, ?, ?, ?, ?, ?, 'official', NULL, ?, NULL)`)
      .bind(id, recipientUserId, support.user.id, caseId, subject, messageBody, now).run();
    await env.DB.prepare(`INSERT INTO platform_moderation_actions (id, moderator_id, target_user_id, action, reason, metadata_json, created_at)
      VALUES (?, ?, ?, 'support.dm', ?, ?, ?)`).bind(crypto.randomUUID(), support.user.id, recipientUserId, subject, JSON.stringify({caseId}), now).run();
    return json({ id, recipientUserId, recipientName: recipient.display_name, recipientUsername: recipient.username,
      senderUserId: support.user.id, senderName: support.user.display_name, senderUsername: support.user.username,
      caseId, subject, body: messageBody, messageKind: 'official', replyToMessageId: null, createdAt: now, readAt: null });
}

async function supportCaseManagerV53(request, env, caseId) {
    const existing = await env.DB.prepare(`SELECT id, kind, reporter_id, subject FROM support_cases WHERE id = ? LIMIT 1`).bind(caseId).first();
    if (!existing) return { response: fail('Support case not found.', 404) };
    const support = existing.kind === 'bug'
      ? await requireSupportCapabilityAnyV53(request, env, ['manage_bugs', 'manage_reports'])
      : await requireSupportCapability(request, env, 'manage_reports');
    if ('response' in support) return support;
    return { user: support.user, permissions: support.permissions, existing };
}

async function archivePlayerReportV53(request, env, reportId) {
    const support = await requireSupportCapability(request, env, 'manage_reports');
    if ('response' in support) return support.response;
    const existing = await env.DB.prepare(`SELECT id, reported_user_id FROM reports WHERE id = ? LIMIT 1`).bind(reportId).first();
    if (!existing) return fail('Player report not found.', 404);
    const body = await readJson(request);
    const archived = body.archived !== false;
    const now = Date.now();
    await env.DB.prepare(`UPDATE reports SET archived_at = ?, archived_by = ? WHERE id = ?`)
      .bind(archived ? now : null, archived ? support.user.id : null, reportId).run();
    await supportAuditV48(env, support.user.id, existing.reported_user_id,
      archived ? 'support.report.archived' : 'support.report.restored',
      archived ? 'Player report archived.' : 'Player report restored.', { reportId });
    return json({ ok: true, archivedAt: archived ? now : null });
}

async function deletePlayerReportV53(request, env, reportId) {
    const support = await requireSupportCapability(request, env, 'manage_reports');
    if ('response' in support) return support.response;
    const existing = await env.DB.prepare(`SELECT id, reported_user_id, archived_at FROM reports WHERE id = ? LIMIT 1`).bind(reportId).first();
    if (!existing) return fail('Player report not found.', 404);
    if (!existing.archived_at) return fail('Archive the report before permanently deleting it.', 409);
    await env.DB.prepare(`DELETE FROM reports WHERE id = ?`).bind(reportId).run();
    await supportAuditV48(env, support.user.id, existing.reported_user_id, 'support.report.deleted', 'Player report permanently deleted.', { reportId });
    return new Response(null, { status: 204, headers: corsHeaders() });
}

async function archiveSupportCaseV53(request, env, caseId) {
    const manager = await supportCaseManagerV53(request, env, caseId);
    if ('response' in manager) return manager.response;
    const body = await readJson(request);
    const archived = body.archived !== false;
    const now = Date.now();
    await env.DB.prepare(`UPDATE support_cases SET archived_at = ?, archived_by = ?, updated_at = ? WHERE id = ?`)
      .bind(archived ? now : null, archived ? manager.user.id : null, now, caseId).run();
    await supportAuditV48(env, manager.user.id, manager.existing.reporter_id,
      archived ? 'support.case.archived' : 'support.case.restored',
      archived ? 'Support report archived.' : 'Support report restored.', { caseId, kind: manager.existing.kind });
    return getSupportCaseById(env, caseId);
}

async function deleteSupportCaseV53(request, env, caseId) {
    const manager = await supportCaseManagerV53(request, env, caseId);
    if ('response' in manager) return manager.response;
    const archived = await env.DB.prepare(`SELECT archived_at FROM support_cases WHERE id = ? LIMIT 1`).bind(caseId).first();
    if (!archived?.archived_at) return fail('Archive the report before permanently deleting it.', 409);
    const sourceKind = manager.existing.kind === 'bug' ? 'bug' : 'space';
    await env.DB.prepare(`DELETE FROM support_cases WHERE id = ?`).bind(caseId).run();
    await supportAuditV48(env, manager.user.id, manager.existing.reporter_id, 'support.case.deleted', 'Support report permanently deleted.', { caseId, kind: sourceKind });
    return new Response(null, { status: 204, headers: corsHeaders() });
}

async function listSupportInboxV53(request, env) {
    const auth = await requireUser(request, env);
    if ('response' in auth) return auth.response;
    const url = new URL(request.url);
    const markRead = url.searchParams.get('markRead') === '1';
    const now = Date.now();
    if (markRead) {
      await upsertNotificationReadCursorV72(env, auth.user.id, 'support', 'support', now);
      await env.DB.prepare(`UPDATE support_messages SET read_at = COALESCE(read_at, ?) WHERE recipient_user_id = ? AND read_at IS NULL`)
        .bind(now, auth.user.id).run();
    }
    const result = await env.DB.prepare(`SELECT m.*,
      recipient.display_name AS recipient_name, sender.display_name AS sender_name
      FROM support_messages m
      JOIN users recipient ON recipient.id = m.recipient_user_id
      JOIN users sender ON sender.id = m.sender_user_id
      WHERE m.recipient_user_id = ? OR m.sender_user_id = ?
      ORDER BY m.created_at ASC LIMIT 500`).bind(auth.user.id, auth.user.id).all();
    return json((result.results ?? []).map(row => ({
      id: row.id, recipientUserId: row.recipient_user_id, recipientName: row.recipient_name,
      senderUserId: row.sender_user_id, senderName: row.sender_name, caseId: row.case_id ?? null,
      subject: row.subject, body: row.body, messageKind: row.message_kind ?? 'official',
      createdAt: Number(row.created_at), readAt: row.read_at ? Number(row.read_at) : null,
      direction: row.recipient_user_id === auth.user.id ? 'incoming' : 'outgoing',
    })));
}

async function sendSupportReplyV53(request, env) {
    const auth = await requireUser(request, env);
    if ('response' in auth) return auth.response;
    await enforceRateLimit(request, env, 'support-reply', 40, 1000 * 60 * 60, auth.user.id);
    const body = await readJson(request);
    const messageBody = String(body.body ?? '').trim().slice(0, 2400);
    const replyToMessageId = String(body.replyToMessageId ?? '');
    if (messageBody.length < 1 || !replyToMessageId) return fail('A Support reply and source message are required.');
    const original = await env.DB.prepare(`SELECT m.*, sender.display_name AS sender_name
      FROM support_messages m JOIN users sender ON sender.id = m.sender_user_id
      WHERE m.id = ? AND m.recipient_user_id = ? AND COALESCE(m.message_kind, 'official') = 'official' LIMIT 1`)
      .bind(replyToMessageId, auth.user.id).first();
    if (!original) return fail('That Support message is not available for reply.', 404);
    const id = crypto.randomUUID(); const now = Date.now();
    await env.DB.prepare(`INSERT INTO support_messages
      (id, recipient_user_id, sender_user_id, case_id, subject, body, message_kind, reply_to_message_id, created_at, read_at)
      VALUES (?, ?, ?, ?, 'SUPPORT REPLY', ?, 'reply', ?, ?, NULL)`)
      .bind(id, original.sender_user_id, auth.user.id, original.case_id ?? null, messageBody, original.id, now).run();
    return json({ id, recipientUserId: original.sender_user_id, recipientName: original.sender_name,
      senderUserId: auth.user.id, senderName: auth.user.display_name, caseId: original.case_id ?? null,
      subject: 'SUPPORT REPLY', body: messageBody, messageKind: 'reply', createdAt: now, readAt: null, direction: 'outgoing' }, 201);
}

async function searchSupportUsers(request, env) {
    const support = await requireSupportCapability(request, env, 'view_accounts');
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
    const support = await requireSupportCapability(request, env, 'staff_chat');
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
    const support = await requireSupportCapability(request, env, 'staff_chat');
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
    const support = await requireSupportCapability(request, env, 'space_restrict');
    if ('response' in support) return support.response;
    if (workspaceId === SPACES_HUB_ID) return fail('Spaces - Hub cannot be restricted.', 403);

    const space = await env.DB.prepare(
        `SELECT s.id, s.name, s.owner_user_id, u.platform_role AS owner_platform_role
         FROM spaces s
         JOIN users u ON u.id = s.owner_user_id
         WHERE s.id = ? LIMIT 1`
    ).bind(workspaceId).first();
    if (!space) return fail('Space not found.', 404);
    if (!supportRoleCanActOn(support.user.platform_role, space.owner_platform_role)) {
        return fail('Your Support role cannot restrict a Space owned by that platform role.', 403);
    }

    const now = Date.now();
    if (request.method === 'DELETE') {
        await env.DB.prepare(
            `UPDATE space_restrictions SET active = 0 WHERE space_id = ? AND active = 1`
        ).bind(workspaceId).run();
        await supportAuditV48(
            env, support.user.id, space.owner_user_id, 'restriction.space.revoked',
            'Space restriction removed.', { workspaceId },
        );
        return new Response(null, { status: 204, headers: corsHeaders() });
    }

    const body = await readJson(request);
    const reason = String(body.reason ?? 'Support review').trim().slice(0, 1200);
    if (!reason) return fail('A restriction reason is required.');
    const durationMinutes = supportDurationMinutesV48(body.durationMinutes);
    const expiresAt = durationMinutes ? now + durationMinutes * 60_000 : null;
    const id = crypto.randomUUID();

    await env.DB.prepare(
        `UPDATE space_restrictions SET active = 0 WHERE space_id = ? AND active = 1`
    ).bind(workspaceId).run();
    await env.DB.prepare(
        `INSERT INTO space_restrictions
          (id, space_id, restricted_by, reason, created_at, expires_at, active)
         VALUES (?, ?, ?, ?, ?, ?, 1)`
    ).bind(id, workspaceId, support.user.id, reason, now, expiresAt).run();
    await supportAuditV48(
        env, support.user.id, space.owner_user_id, 'restriction.space', reason,
        { restrictionId: id, workspaceId, expiresAt },
    );
    return json({ id, workspaceId, reason, createdAt: now, expiresAt, active: true }, 201);
}

async function supportDeleteSpace(request, env, workspaceId) {
    const support = await requireSupportCapability(request, env, 'delete_space');
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




function isLegacyBetaPlaceholderAccount(account, access = null) {
    if (!account) return false;

    const legacyUsername =
        /^invite_[a-z0-9]{6,}$/u
            .test(String(account.username ?? ''));

    const linkedToAccess =
        !access?.user_id ||
        String(access.user_id) === String(account.id);

    return (
        legacyUsername &&
        Boolean(account.beta_profile_pending) &&
        !Boolean(account.public_profile) &&
        !account.platform_role &&
        linkedToAccess
    );
}

function betaAccessPayload(row) {
    const username = String(row.username ?? '');
    const visibleUsername =
        /^invite_[a-z0-9]{6,}$/u.test(username)
            ? null
            : username || null;

    return {
        id: row.id,
        email: row.email,
        status: row.status,
        invitedByName: row.invited_by_name ?? 'Spaces',
        createdAt: Number(row.created_at),
        claimedAt: row.claimed_at
            ? Number(row.claimed_at)
            : null,
        username: visibleUsername,
    };
}

async function betaAccessById(env, id) {
    const row = await env.DB.prepare(
        `SELECT
           b.*,
           inviter.display_name AS invited_by_name,
           account.username AS username
         FROM beta_access b
         LEFT JOIN users inviter ON inviter.id = b.invited_by
         LEFT JOIN users account ON account.id = b.user_id
         WHERE b.id = ?
         LIMIT 1`
    ).bind(id).first();

    return row ? betaAccessPayload(row) : null;
}

async function listBetaAccess(request, env) {
    const support = await requireSupportCapability(request, env, 'manage_beta_access');
    if ('response' in support) return support.response;

    try {
        const result = await env.DB.prepare(
            `SELECT
               b.*,
               inviter.display_name AS invited_by_name,
               account.username AS username
             FROM beta_access b
             LEFT JOIN users inviter ON inviter.id = b.invited_by
             LEFT JOIN users account ON account.id = b.user_id
             ORDER BY b.created_at DESC
             LIMIT 500`
        ).all();

        return json(
            (result.results ?? []).map(betaAccessPayload),
        );
    } catch (error) {
        console.error('Beta access list failed.', error);
        return fail(
            'Beta access storage is unavailable right now.',
            503,
        );
    }
}


async function inviteBetaAccess(request, env) {
    const support = await requireSupportCapability(request, env, 'manage_beta_access');
    if ('response' in support) return support.response;

    await enforceRateLimit(
        request,
        env,
        'beta-access-invite',
        40,
        1000 * 60 * 60,
        support.user.id,
    );

    const body = await readJson(request);
    const email = normalizeEmail(body.email ?? '');
    const subject =
        String(body.subject ?? 'You’re in Spaces')
            .trim()
            .slice(0, 120);
    const message =
        String(body.message ?? '')
            .trim()
            .slice(0, 1800);

    if (!validEmail(email)) {
        return fail('Enter a valid email address.');
    }

    if (!subject || !message) {
        return fail('Invite subject and message are required.');
    }

    if (!env.EMAIL || typeof env.EMAIL.send !== 'function') {
        return fail('Cloudflare Email Service is not configured yet.', 503);
    }

    const sender = String(env.SPACES_EMAIL_FROM ?? '').trim();
    if (!sender) {
        return fail('SPACES_EMAIL_FROM is not configured yet.', 503);
    }

    const existingAccess = await env.DB.prepare(
        `SELECT * FROM beta_access
         WHERE email = ? COLLATE NOCASE
         LIMIT 1`
    ).bind(email).first();

    if (existingAccess?.status === 'claimed') {
        return fail('That email has already claimed beta access.', 409);
    }

    const existingUser = await env.DB.prepare(
        `SELECT * FROM users
         WHERE email = ? COLLATE NOCASE
         LIMIT 1`
    ).bind(email).first();

    const legacyPlaceholder =
        isLegacyBetaPlaceholderAccount(
            existingUser,
            existingAccess,
        );

    if (existingUser && !legacyPlaceholder) {
        return fail(
            'That email already belongs to a Spaces account.',
            409,
        );
    }

    const now = Date.now();
    const accessId =
        existingAccess?.id ??
        crypto.randomUUID();
    const legacyUserId =
        legacyPlaceholder
            ? existingUser.id
            : null;

    if (legacyUserId) {
        await env.DB.prepare(
            `DELETE FROM sessions WHERE user_id = ?`
        ).bind(legacyUserId).run();

        await env.DB.prepare(
            `UPDATE users
             SET spaces_access = 0,
                 email_verified = 0,
                 beta_profile_pending = 1,
                 updated_at = ?
             WHERE id = ?`
        ).bind(now, legacyUserId).run();
    }

    if (existingAccess) {
        await env.DB.prepare(
            `UPDATE beta_access
             SET status = 'invited',
                 invited_by = ?,
                 user_id = ?,
                 created_at = ?,
                 claimed_at = NULL,
                 revoked_at = NULL
             WHERE id = ?`
        ).bind(
            support.user.id,
            legacyUserId,
            now,
            accessId,
        ).run();
    } else {
        await env.DB.prepare(
            `INSERT INTO beta_access (
                id, email, status, invited_by, user_id,
                created_at, claimed_at, revoked_at
             )
             VALUES (?, ?, 'invited', ?, ?, ?, NULL, NULL)`
        ).bind(
            accessId,
            email,
            support.user.id,
            legacyUserId,
            now,
        ).run();
    }

    // Support Console owns the invitation subject/body. Send exactly what the
    // Founder or Support team wrote instead of appending old onboarding copy.
    const emailText = message;

    try {
        await env.EMAIL.send({
            to: email,
            from: { email: sender, name: 'Spaces' },
            replyTo:
                String(env.SPACES_EMAIL_REPLY_TO ?? '').trim() ||
                sender,
            subject,
            text: emailText,
        });
    } catch (error) {
        console.error('Beta invite send failed.', error);

        await env.DB.prepare(
            `UPDATE beta_access
             SET status = 'revoked',
                 revoked_at = ?
             WHERE id = ?`
        ).bind(Date.now(), accessId).run();

        return fail('Could not send the beta invitation email.', 502);
    }

    const entry = await betaAccessById(env, accessId);

    return json({
        entry,
        delivery: 'sent',
    }, 201);
}

async function revokeBetaAccess(request, env, accessId) {
    const support = await requireSupportCapability(request, env, 'manage_beta_access');
    if ('response' in support) return support.response;

    const entry = await env.DB.prepare(
        `SELECT * FROM beta_access
         WHERE id = ?
         LIMIT 1`
    ).bind(accessId).first();

    if (!entry) {
        return fail('Beta access entry not found.', 404);
    }

    if (entry.status === 'claimed') {
        return fail(
            'Claimed access cannot be revoked here. Use account moderation tools.',
            409,
        );
    }

    const now = Date.now();

    await env.DB.prepare(
        `UPDATE beta_access
         SET status = 'revoked',
             revoked_at = ?
         WHERE id = ?`
    ).bind(now, accessId).run();

    if (entry.user_id) {
        await env.DB.prepare(
            `UPDATE users
             SET spaces_access = 0,
                 updated_at = ?
             WHERE id = ?`
        ).bind(now, entry.user_id).run();

        await env.DB.prepare(
            `DELETE FROM sessions
             WHERE user_id = ?`
        ).bind(entry.user_id).run();
    }

    return new Response(
        null,
        {
            status: 204,
            headers: corsHeaders(),
        },
    );
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
        betaEmailClaim: true,
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
        directThreadPreferences: true,
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
// SPACES_V80_3_PARTNER_EMAIL_ARCHIVES_START
// These APIs never derive authorization, sender identity or Partner status from
// the public trust registry or from client-submitted role fields.
const SPACES_V803_EMAIL_TEMPLATES = Object.freeze({
  'ticket-reply': { sender: 'support', group: 'ticket', subject: 'Spaces Support — Update on ticket {{ticket.id}}', body: 'Hi {{user.displayName}},\n\nA Spaces Support agent replied to your ticket.\n\n{{ticket.reply}}\n\nView your ticket: {{support.url}}\n\n— Spaces Support' },
  'ticket-created': { sender: 'support', group: 'ticket', subject: 'Spaces Support — Ticket {{ticket.id}} received', body: 'Hi {{user.displayName}},\n\nWe received your support request and created ticket {{ticket.id}}.\n\nCategory: {{ticket.category}}\n\nView ticket: {{support.url}}' },
  'ticket-closed': { sender: 'support', group: 'ticket', subject: 'Spaces Support — Ticket {{ticket.id}} closed', body: 'Hi {{user.displayName}},\n\nTicket {{ticket.id}} has been closed.\n\nReason: {{ticket.closeReason}}\n\nIf you still need help, open a new request through Spaces Support.' },
  'security-alert': { sender: 'security', group: 'founder', subject: 'Spaces Security — Account security alert', body: 'Hi {{user.displayName}},\n\nWe detected a security event on your account.\n\nEvent: {{security.event}}\nTime: {{security.time}}\nLocation/device: {{security.context}}\n\nIf this was not you, secure your account: {{security.url}}\n\nSpaces Security will never ask for your password or one-time code.' },
  'moderation-action': { sender: 'support', group: 'moderation', subject: 'Spaces — Moderation notice for your account', body: 'Hi {{user.displayName}},\n\nA moderation action was applied to your account.\n\nAction: {{action.type}}\nReason: {{action.reason}}\nDuration: {{action.duration}}\nCase: {{case.id}}\n\nIf an appeal is available, contact Spaces Support: {{support.url}}' },
  'partner-approved': { sender: 'support', group: 'partner', subject: 'Spaces Partners — {{space.name}} is now a Partner', body: 'Hi {{user.displayName}},\n\n{{space.name}} has been approved for the Spaces Partner Program.\n\nReview the Partner Code of Conduct: {{partner.codeUrl}}\n\nWelcome to the Spaces Partner community.' },
  'partner-warning': { sender: 'support', group: 'partner', subject: 'Spaces Partners — Action required for {{space.name}}', body: 'Hi {{user.displayName}},\n\nYour Partner Space {{space.name}} needs attention.\n\nIssue: {{partner.issue}}\nRequired action: {{partner.action}}\nDeadline: {{partner.deadline}}\n\nPartner policies: {{partner.policyUrl}}' },
  'partner-removed': { sender: 'support', group: 'partner', subject: 'Spaces Partners — Partner status update for {{space.name}}', body: 'Hi {{user.displayName}},\n\nPartner status for {{space.name}} has been removed.\n\nReason: {{partner.reason}}\n\nContact Spaces Support if an appeal is available: {{support.url}}' },
  'partner-application': { sender: 'support', group: 'partner', subject: 'Spaces Partners — Application received', body: 'Hi {{user.displayName}},\n\nWe received your Partner Program application for {{space.name}}.\n\nApplication: {{application.id}}\n\nOur team will review the application.' },
  'beta-invite': { sender: 'noreply', group: 'founder', subject: 'Spaces Beta — You are invited', body: 'Hi {{user.displayName}},\n\nYou have been invited to the Spaces beta.\n\nStart here: {{beta.url}}\n\nReview the Beta Program Terms: {{beta.termsUrl}}' },
});

function spacesV803Short(value, limit = 240) {
  return String(value ?? '').replace(/[\u0000-\u001f\u007f]/gu, ' ').trim().slice(0, limit);
}
function spacesV803Escape(value) {
  return String(value ?? '').replace(/[&<>"']/gu, character => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' })[character]);
}
function spacesV803Render(template, variables) {
  return template.replace(/\{\{([a-zA-Z0-9.]+)\}\}/gu, (_, name) => String(variables[name] ?? ''));
}
function spacesV803EmailConfigured(env) {
  return Boolean(env.EMAIL && typeof env.EMAIL.send === 'function' && validEmail(String(env.SPACES_EMAIL_FROM ?? '')));
}
function spacesV803Sender(env, sender) {
  const fallback = normalizeEmail(env.SPACES_EMAIL_FROM);
  if (!validEmail(fallback)) throw new ApiRequestError('Email sender is not configured.', 503);
  const key = { support:'SPACES_EMAIL_SUPPORT_FROM', noreply:'SPACES_EMAIL_NOREPLY_FROM', security:'SPACES_EMAIL_SECURITY_FROM' }[sender];
  const candidate = normalizeEmail(env[key] || fallback);
  if (!validEmail(candidate) || candidate.split('@')[1] !== fallback.split('@')[1]) {
    throw new ApiRequestError('Email sender must be an approved address on the Spaces domain.', 503);
  }
  return candidate;
}
function spacesV803ImageUrl(value, env) {
  const raw = String(value ?? '').trim();
  if (!raw) return '';
  let parsed;
  try { parsed = new URL(raw); } catch { throw new ApiRequestError('Invalid email image URL.', 400); }
  const allowedHosts = new Set(['yourspaces.net', 'www.yourspaces.net',
    ...String(env.SPACES_EMAIL_IMAGE_HOSTS ?? '').split(',').map(host => host.trim().toLowerCase()).filter(Boolean)]);
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password || !allowedHosts.has(parsed.hostname.toLowerCase()) || raw.length > 600) {
    throw new ApiRequestError('Email images must use an approved HTTPS host.', 400);
  }
  return parsed.href;
}
function spacesV803EmailHtml(subject, text, heroUrl, footerUrl, replyTo) {
  const image = (url, alt) => url ? `<img src="${spacesV803Escape(url)}" alt="${alt}" width="580" style="display:block;max-width:100%;height:auto;margin:18px auto;border:0">` : '';
  const lines = spacesV803Escape(text).replace(/\n/gu, '<br>');
  return `<!doctype html><html><body style="margin:0;background:#09080d;color:#f4f1f7;font-family:Arial,sans-serif"><table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="padding:24px 10px"><tr><td align="center"><table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:620px;background:#141019;border:1px solid #32283b;border-radius:16px"><tr><td style="padding:25px 30px;background:#21182b;font-weight:800;font-size:20px;letter-spacing:.14em">◈ SPACES</td></tr><tr><td style="padding:28px 30px"><h1 style="font-size:22px;line-height:1.3;margin:0 0 22px;color:#faf6fc">${spacesV803Escape(subject)}</h1>${image(heroUrl,'Spaces announcement')}<div style="font-size:14px;line-height:1.75;color:#d8cfe0">${lines}</div>${image(footerUrl,'Spaces footer')}</td></tr><tr><td style="padding:17px 30px;border-top:1px solid #32283b;font-size:11px;color:#a69ab0">Spaces · ${spacesV803Escape(replyTo)}<br>Spaces Support will never ask for passwords or verification codes.</td></tr></table></td></tr></table></body></html>`;
}
function spacesV803PublicTrust(row) {
  return { classification: row.classification, verified: Boolean(row.verified), featured: Boolean(row.featured), beta: Boolean(row.beta), staffOwned: Boolean(row.staff_owned) };
}
async function spacesV803PartnerPublic(request, env, spaceId = '') {
  if (spaceId) {
    const row = await env.DB.prepare(`SELECT classification,verified,featured,beta,staff_owned FROM partner_space_status_v80 WHERE space_id=? LIMIT 1`).bind(spaceId).first();
    return json({ spaceId, ...(row ? spacesV803PublicTrust(row) : { classification:'community', verified:false, featured:false, beta:false, staffOwned:false }) });
  }
  const rows = await env.DB.prepare(`SELECT space_id,classification,verified,featured,beta,staff_owned FROM partner_space_status_v80 WHERE classification<>'community' OR verified=1 OR featured=1 OR beta=1 OR staff_owned=1 LIMIT 2000`).all();
  const spaces = {};
  for (const row of rows.results ?? []) spaces[row.space_id] = spacesV803PublicTrust(row);
  return json({ version: 1, spaces });
}
async function spacesV803PartnerApplications(request, env) {
  const auth = await requireUser(request, env);
  if ('response' in auth) return auth.response;
  if (request.method === 'GET') {
    const rows = await env.DB.prepare(`SELECT a.id,a.space_id,a.status,a.message,a.updated_at,s.name AS space_name FROM partner_program_applications_v80 a JOIN spaces s ON s.id=a.space_id WHERE a.applicant_user_id=? ORDER BY a.updated_at DESC LIMIT 100`).bind(auth.user.id).all();
    return json({ applications: (rows.results ?? []).map(row => ({ id:row.id,spaceId:row.space_id,spaceName:row.space_name,status:row.status,message:row.message,updatedAt:Number(row.updated_at) })) });
  }
  await enforceRateLimit(request, env, 'partner-apply-v80', 5, 24*60*60*1000, auth.user.id);
  const body = await readJson(request);
  const spaceId = spacesV803Short(body.spaceId, 128);
  const message = spacesV803Short(body.message, 1800);
  if (!spaceId || message.length < 20) return fail('Choose a Space and describe your Partner application (at least 20 characters).', 400);
  const space = await env.DB.prepare(`SELECT id,owner_user_id FROM spaces WHERE id=? LIMIT 1`).bind(spaceId).first();
  if (!space || space.owner_user_id !== auth.user.id) return fail('Only the Space owner can apply.', 403);
  const prior = await env.DB.prepare(`SELECT id,status FROM partner_program_applications_v80 WHERE space_id=?`).bind(spaceId).first();
  if (prior && ['pending','approved'].includes(prior.status)) return fail('This Space already has an active Partner application.', 409);
  const now = Date.now();
  const id = prior?.id ?? crypto.randomUUID();
  await env.DB.batch([
    env.DB.prepare(`INSERT INTO partner_program_applications_v80 (id,space_id,applicant_user_id,status,message,created_at,updated_at) VALUES (?,?,?,'pending',?,?,?) ON CONFLICT(space_id) DO UPDATE SET status='pending',message=excluded.message,applicant_user_id=excluded.applicant_user_id,reviewer_user_id=NULL,review_note='',reviewed_at=NULL,updated_at=excluded.updated_at`).bind(id,spaceId,auth.user.id,message,now,now),
    env.DB.prepare(`INSERT INTO partner_program_events_v80 (id,space_id,actor_user_id,event_type,note,created_at) VALUES (?,?,?,'applied',?,?)`).bind(crypto.randomUUID(),spaceId,auth.user.id,message.slice(0,600),now),
  ]);
  return json({ applied:true, applicationId:id, spaceId, status:'pending' }, 201);
}
async function spacesV803PartnerStaff(request, env) {
  const auth = await requireSupportConsole(request, env);
  if ('response' in auth) return auth.response;
  if (!['creator','staff'].includes(auth.user.platform_role)) return fail('Staff or Founder role required for Partner decisions.', 403);
  if (request.method === 'GET') {
    const status = new URL(request.url).searchParams.get('status') ?? '';
    if (status && !['pending','approved','denied','revoked'].includes(status)) return fail('Invalid Partner status.', 400);
    const result = await env.DB.prepare(`SELECT a.id,a.space_id,a.applicant_user_id,a.status,a.message,a.review_note,a.updated_at,s.name AS space_name,s.owner_user_id,u.display_name AS owner_name FROM partner_program_applications_v80 a JOIN spaces s ON s.id=a.space_id JOIN users u ON u.id=s.owner_user_id WHERE (?='' OR a.status=?) ORDER BY a.updated_at DESC LIMIT 200`).bind(status,status).all();
    return json({ canReview:true, applications:(result.results ?? []).map(row => ({ id:row.id,spaceId:row.space_id,spaceName:row.space_name,ownerId:row.owner_user_id,ownerName:row.owner_name,status:row.status,message:row.message,reviewNote:row.review_note,updatedAt:Number(row.updated_at) })) });
  }
  await enforceRateLimit(request, env, 'partner-review-v80', 40, 60*60*1000, auth.user.id);
  const body = await readJson(request);
  const spaceId = spacesV803Short(body.spaceId, 128);
  const action = spacesV803Short(body.action, 20);
  const note = spacesV803Short(body.note, 1000);
  if (!spaceId || !['approve','deny','revoke'].includes(action)) return fail('Valid Space ID and Partner action required.', 400);
  if (action !== 'approve' && note.length < 8) return fail('Provide a reason for this Partner decision.', 400);
  const space = await env.DB.prepare(`SELECT s.id,s.name,s.owner_user_id,u.platform_role AS owner_role FROM spaces s JOIN users u ON u.id=s.owner_user_id WHERE s.id=? LIMIT 1`).bind(spaceId).first();
  if (!space) return fail('Space not found.', 404);
  if (body.ownerId && String(body.ownerId) !== space.owner_user_id) return fail('Space owner changed; refresh the review.', 409);
  if (auth.user.platform_role !== 'creator' && auth.user.id === space.owner_user_id) return fail('Staff cannot approve their own Space.', 403);
  if (action === 'approve') {
    if (await activeSupportRestrictionV77(env,'space',spaceId,'join_space')) return fail('Resolve the active Space restriction before Partner approval.', 409);
    if (await activePlatformBan(env,space.owner_user_id)) return fail('Space owner has an active platform ban.', 409);
  }
  const prior = await env.DB.prepare(`SELECT id,status,created_at,applicant_user_id FROM partner_program_applications_v80 WHERE space_id=?`).bind(spaceId).first();
  const previousTrust = await env.DB.prepare(`SELECT classification FROM partner_space_status_v80 WHERE space_id=?`).bind(spaceId).first();
  if (action === 'revoke' && previousTrust?.classification !== 'partner') return fail('Space is not an active Partner.', 409);
  if (action === 'deny' && previousTrust?.classification === 'partner') return fail('Revoke Partner status instead of denying an active Partner.', 409);
  if (action === 'approve' && previousTrust?.classification === 'partner') return fail('This Space is already a Partner.', 409);
  if (action === 'approve' && previousTrust?.classification === 'official') return fail('Official Space status must be managed separately by the Founder.', 409);
  const status = {approve:'approved',deny:'denied',revoke:'revoked'}[action];
  const now = Date.now();
  const nextClass = action === 'approve' ? 'partner' : 'community';
  const auditId = crypto.randomUUID();
  const statements = [
    env.DB.prepare(`INSERT INTO partner_program_applications_v80 (id,space_id,applicant_user_id,status,message,reviewer_user_id,review_note,created_at,updated_at,reviewed_at) VALUES (?,?,?,?,'',?,?,?, ?,?) ON CONFLICT(space_id) DO UPDATE SET status=excluded.status,reviewer_user_id=excluded.reviewer_user_id,review_note=excluded.review_note,updated_at=excluded.updated_at,reviewed_at=excluded.reviewed_at`).bind(prior?.id ?? crypto.randomUUID(),spaceId,prior?.applicant_user_id ?? space.owner_user_id,status,auth.user.id,note,prior?.created_at ?? now,now,now),
    env.DB.prepare(`INSERT INTO partner_space_status_v80 (space_id,classification,verified,featured,beta,staff_owned,approved_by,approved_at,updated_at) VALUES (?,?,0,0,0,0,?,?,?) ON CONFLICT(space_id) DO UPDATE SET classification=excluded.classification,verified=CASE WHEN excluded.classification='community' THEN 0 ELSE partner_space_status_v80.verified END,featured=CASE WHEN excluded.classification='community' THEN 0 ELSE partner_space_status_v80.featured END,approved_by=excluded.approved_by,approved_at=excluded.approved_at,updated_at=excluded.updated_at`).bind(spaceId,nextClass,action==='approve'?auth.user.id:null,action==='approve'?now:null,now),
    env.DB.prepare(`INSERT INTO partner_program_events_v80 (id,space_id,actor_user_id,event_type,note,created_at) VALUES (?,?,?,?,?,?)`).bind(crypto.randomUUID(),spaceId,auth.user.id,status,note,now),
    env.DB.prepare(`INSERT INTO support_audit_v77 (id,actor_id,actor_role,action,target_type,target_id,case_id,reason_category,note,before_json,after_json,expires_at,created_at) VALUES (?,?,?,?,?,?,NULL,'Partner Program',?,?,?,NULL,?)`).bind(auditId,auth.user.id,auth.user.platform_role,`partner.${action}`,'space',spaceId,note,JSON.stringify({status:prior?.status ?? null,classification:previousTrust?.classification ?? 'community'}),JSON.stringify({status,classification:nextClass}),now),
  ];
  await env.DB.batch(statements);
  return json({ approved:action==='approve',spaceId,spaceName:space.name,status,classification:nextClass,auditId });
}
async function spacesV803EmailCapabilities(request, env) {
  const auth = await requireSupportConsole(request, env);
  if ('response' in auth) return auth.response;
  const permissions = await supportPermissionsForUserV48(env, auth.user);
  let migrationReady = false;
  try { await env.DB.prepare(`SELECT id FROM support_email_deliveries_v80 LIMIT 1`).first(); migrationReady = true; } catch {}
  const canSend = permissions.includes('send_support_dms') && spacesV803EmailConfigured(env) && migrationReady;
  return json({ canSend, migrationReady, senderNames:canSend ? {support:'Spaces Support',noreply:'Spaces',security:'Spaces Security'} : {}, requiresAuthorization:true });
}
async function spacesV803ResolveTicket(env, ticketId) {
  if (!ticketId) return null;
  const v77 = await env.DB.prepare(`SELECT id,case_number,reporter_id,target_user_id,target_space_id,status,case_type FROM support_cases_v77 WHERE id=? OR case_number=? LIMIT 1`).bind(ticketId,ticketId).first();
  if (v77) return { id:v77.id,displayId:v77.case_number,recipientId:v77.reporter_id,status:v77.status,spaceId:v77.target_space_id,kind:'v77',targetUserId:v77.target_user_id,caseType:v77.case_type };
  const legacy = await env.DB.prepare(`SELECT id,ticket_number,user_id,status FROM support_tickets WHERE id=? OR ticket_number=? LIMIT 1`).bind(ticketId,ticketId).first();
  if (legacy) return { id:legacy.id,displayId:legacy.ticket_number,recipientId:legacy.user_id,status:legacy.status,spaceId:null,kind:'v73',targetUserId:null,caseType:'request' };
  return null;
}
async function spacesV803EmailSend(request, env) {
  const auth = await requireSupportCapability(request, env, 'send_support_dms');
  if ('response' in auth) return auth.response;
  if (!spacesV803EmailConfigured(env)) return fail('Cloudflare Email Service or Spaces sender is not configured.', 503);
  await enforceRateLimit(request, env, 'support-email-v80', 20, 60*60*1000, auth.user.id);
  const body = await readJson(request);
  const templateId = spacesV803Short(body.templateId, 60);
  const template = SPACES_V803_EMAIL_TEMPLATES[templateId];
  if (!template) return fail('Unapproved email template.', 400);
  const founder = auth.user.platform_role === 'creator';
  const staff = founder || auth.user.platform_role === 'staff';
  if (template.group === 'founder' && !founder) return fail('Founder approval required for this email type.', 403);
  if (['partner','moderation'].includes(template.group) && !staff) return fail('Staff or Founder role required for this email type.', 403);
  const ticketId = spacesV803Short(body.ticketId, 128);
  const ticket = await spacesV803ResolveTicket(env,ticketId);
  if (ticketId && !ticket) return fail('Ticket or case not found.', 404);
  if (template.group === 'ticket' && !ticket) return fail('Select an existing Support ticket.', 400);
  if (templateId === 'ticket-closed' && !['resolved','archived'].includes(ticket.status)) return fail('Close or resolve the ticket before sending this email.', 409);
  const explicitId = spacesV803Short(body.userId, 128);
  let recipientId = explicitId || (templateId === 'moderation-action' ? ticket?.targetUserId : ticket?.recipientId);
  if (!recipientId) return fail('Select a recipient or ticket.', 400);
  let recipient = await env.DB.prepare(`SELECT id,display_name,email,email_verified FROM users WHERE id=? OR public_user_id=? LIMIT 1`).bind(recipientId,recipientId).first();
  if (!recipient) return fail('Recipient not found.', 404);
  recipientId = recipient.id;
  if (ticket && (templateId === 'moderation-action' ? ticket.targetUserId !== recipientId : ticket.recipientId !== recipientId)) return fail('Ticket does not belong to the selected recipient.', 403);
  if (!staff && (!ticket || ticket.recipientId !== recipientId)) return fail('Support can only email the member associated with a ticket.', 403);
  if (!recipient.email_verified || !validEmail(recipient.email)) return fail('Recipient needs a verified email address.', 409);
  if (templateId === 'moderation-action') {
    if (!ticket || ticket.kind !== 'v77' || !ticket.targetUserId || !['resolved','archived'].includes(ticket.status)) return fail('Select a resolved case with a moderation target.', 400);
    const action = await env.DB.prepare(`SELECT id FROM support_audit_v77 WHERE case_id=? AND action LIKE 'restriction.%' LIMIT 1`).bind(ticket.id).first();
    if (!action) return fail('Record a moderation action on this case before sending a notice.', 409);
  }
  if (templateId === 'beta-invite') {
    const invite = await env.DB.prepare(`SELECT id FROM beta_access WHERE email=? COLLATE NOCASE AND status IN ('invited','claimed') LIMIT 1`).bind(recipient.email).first();
    if (!invite) return fail('This member does not have a recorded beta invitation.', 409);
  }
  let space = null;
  let application = null;
  let trust = null;
  if (template.group === 'partner') {
    const requestedSpaceId = spacesV803Short(body.spaceId,128) || ticket?.spaceId || '';
    if (requestedSpaceId) space = await env.DB.prepare(`SELECT id,name,owner_user_id FROM spaces WHERE id=? LIMIT 1`).bind(requestedSpaceId).first();
    if (!space) {
      const hint = spacesV803Short(body.variables?.['space.name'],120);
      if (hint) space = await env.DB.prepare(`SELECT id,name,owner_user_id FROM spaces WHERE owner_user_id=? AND name=? COLLATE NOCASE LIMIT 1`).bind(recipientId,hint).first();
      else {
        const all = await env.DB.prepare(`SELECT id,name,owner_user_id FROM spaces WHERE owner_user_id=? LIMIT 2`).bind(recipientId).all();
        if ((all.results ?? []).length === 1) space = all.results[0];
      }
    }
    if (!space || space.owner_user_id !== recipientId) return fail('Select a Space owned by the email recipient.', 403);
    application = await env.DB.prepare(`SELECT id,status,review_note FROM partner_program_applications_v80 WHERE space_id=?`).bind(space.id).first();
    trust = await env.DB.prepare(`SELECT classification FROM partner_space_status_v80 WHERE space_id=?`).bind(space.id).first();
    if (['partner-approved','partner-warning'].includes(templateId) && trust?.classification !== 'partner') return fail('The Space is not an approved Partner.', 409);
    if (templateId === 'partner-removed' && application?.status !== 'revoked') return fail('Partner removal must be recorded before this notice.', 409);
    if (templateId === 'partner-application' && application?.status !== 'pending') return fail('No pending Partner application exists.', 409);
  }
  const raw = body.variables && typeof body.variables === 'object' && !Array.isArray(body.variables) ? body.variables : {};
  const safe = (key,limit=350) => spacesV803Short(raw[key],limit);
  const site = 'https://yourspaces.net';
  const variables = {
    'user.displayName':spacesV803Short(recipient.display_name,100),
    'ticket.id':ticket?.displayId ?? '',
    'ticket.reply':String(raw['ticket.reply'] ?? '').replace(/[\u0000-\u0009\u000b-\u001f\u007f]/gu,' ').trim().slice(0,2000),
    'ticket.category':ticket?.caseType ?? 'Support',
    'ticket.closeReason':safe('ticket.closeReason',350) || 'Resolved',
    'case.id':ticket?.displayId ?? '',
    'action.type':safe('action.type',150),
    'action.reason':safe('action.reason',500),
    'action.duration':safe('action.duration',100),
    'security.event':safe('security.event',250),
    'security.time':new Date().toISOString(),
    'security.context':safe('security.context',250),
    'space.name':space?.name ?? '',
    'partner.issue':safe('partner.issue',350),
    'partner.action':safe('partner.action',350),
    'partner.deadline':safe('partner.deadline',100),
    'partner.reason':application?.review_note || 'Partner status changed',
    'application.id':application?.id ?? '',
    'support.url':`${site}/support`,
    'security.url':`${site}/security`,
    'partner.codeUrl':`${site}/partner/code-of-conduct/`,
    'partner.policyUrl':`${site}/partner/`,
    'beta.url':`${site}/beta`,
    'beta.termsUrl':`${site}/tos/beta/`,
  };
  if (templateId === 'ticket-reply' && variables['ticket.reply'].length < 3) return fail('Write a Support reply first.', 400);
  if (templateId === 'partner-warning' && (!variables['partner.issue'] || !variables['partner.action'])) return fail('Partner warning needs an issue and required action.', 400);
  if (templateId === 'moderation-action' && (!variables['action.type'] || !variables['action.reason'])) return fail('Moderation notice needs an action and reason.', 400);
  if (templateId === 'security-alert' && !variables['security.event']) return fail('Security alert needs an event description.', 400);
  const image = body.image && typeof body.image === 'object' ? body.image : {};
  const heroUrl = spacesV803ImageUrl(image.heroUrl, env);
  const footerUrl = spacesV803ImageUrl(image.footerUrl, env);
  const subject = spacesV803Render(template.subject, variables).slice(0,180);
  const text = spacesV803Render(template.body, variables).slice(0,5000);
  const from = spacesV803Sender(env, template.sender);
  const replyTo = validEmail(String(env.SPACES_EMAIL_REPLY_TO ?? '')) ? String(env.SPACES_EMAIL_REPLY_TO) : from;
  const dedupeInput = `${auth.user.id}|${recipientId}|${templateId}|${ticket?.id ?? space?.id ?? ''}|${Math.floor(Date.now()/60000)}`;
  const dedupeKey = await sha256Base64(dedupeInput);
  const now = Date.now();
  const deliveryId = crypto.randomUUID();
  const claim = await env.DB.prepare(`INSERT OR IGNORE INTO support_email_deliveries_v80 (id,actor_user_id,recipient_user_id,ticket_id,template_id,sender_address,dedupe_key,status,created_at) VALUES (?,?,?,?,?,?,?,'sending',?)`).bind(deliveryId,auth.user.id,recipientId,ticket?.id ?? null,templateId,from,dedupeKey,now).run();
  if (Number(claim?.meta?.changes ?? 0) !== 1) return fail('A matching email was already requested recently.', 409);
  try {
    const provider = await env.EMAIL.send({ to:{email:recipient.email,name:recipient.display_name}, from:{email:from,name:template.sender==='security'?'Spaces Security':template.sender==='support'?'Spaces Support':'Spaces'}, replyTo, subject, text, html:spacesV803EmailHtml(subject,text,heroUrl,footerUrl,replyTo) });
    await env.DB.prepare(`UPDATE support_email_deliveries_v80 SET status='sent',provider_message_id=?,completed_at=? WHERE id=?`).bind(String(provider?.messageId ?? ''),Date.now(),deliveryId).run();
    return json({ sent:true, deliveryId, providerMessageId:provider?.messageId ?? null });
  } catch (caught) {
    await env.DB.prepare(`UPDATE support_email_deliveries_v80 SET status='failed',error_code=?,completed_at=? WHERE id=?`).bind(spacesV803Short(caught?.code ?? 'SEND_FAILED',80),Date.now(),deliveryId).run();
    console.error('Spaces V80 Support email provider rejected send.', caught?.code ?? 'SEND_FAILED');
    return fail('Email provider rejected delivery. Check Email Service configuration.', 502);
  }
}
async function spacesV803MemberArchives(request, env, caseId = '') {
  const auth = await requireUser(request, env);
  if ('response' in auth) return auth.response;
  if (request.method === 'GET') {
    const rows = await env.DB.prepare(`SELECT c.id,c.case_number,c.subject,c.status,c.case_type,c.last_activity_at,a.archived_at FROM support_member_case_archives_v80 a JOIN support_cases_v77 c ON c.id=a.case_id WHERE a.user_id=? AND c.reporter_id=? ORDER BY a.archived_at DESC LIMIT 200`).bind(auth.user.id,auth.user.id).all();
    return json({ archives:(rows.results ?? []).map(row => ({ id:row.id,caseNumber:row.case_number,subject:row.subject,status:row.status,caseType:row.case_type,lastActivityAt:Number(row.last_activity_at),archivedAt:Number(row.archived_at) })) });
  }
  const row = await env.DB.prepare(`SELECT id,reporter_id FROM support_cases_v77 WHERE id=? LIMIT 1`).bind(caseId).first();
  if (!row || row.reporter_id !== auth.user.id) return fail('Support case not found.', 404);
  const body = await readJson(request);
  if (typeof body.archived !== 'boolean') return fail('archived must be true or false.', 400);
  const now = Date.now();
  if (body.archived) await env.DB.prepare(`INSERT INTO support_member_case_archives_v80 (case_id,user_id,archived_at) VALUES (?,?,?) ON CONFLICT(case_id,user_id) DO NOTHING`).bind(caseId,auth.user.id,now).run();
  else await env.DB.prepare(`DELETE FROM support_member_case_archives_v80 WHERE case_id=? AND user_id=?`).bind(caseId,auth.user.id).run();
  return json({ caseId, archived:body.archived });
}
async function spacesV803ArchiveHealth(request, env) {
  const auth = await requireSupportCapability(request, env, 'view_reports');
  if ('response' in auth) return auth.response;
  const cases = await env.DB.prepare(`SELECT status,COUNT(*) AS count FROM support_cases_v77 GROUP BY status`).all();
  const memberArchives = await env.DB.prepare(`SELECT COUNT(*) AS count FROM support_member_case_archives_v80`).first();
  const legacy = await env.DB.prepare(`SELECT status,COUNT(*) AS count FROM support_tickets GROUP BY status`).all();
  return json({ v77:Object.fromEntries((cases.results ?? []).map(row => [row.status,Number(row.count)])), legacyTickets:Object.fromEntries((legacy.results ?? []).map(row => [row.status,Number(row.count)])), memberArchiveCount:Number(memberArchives?.count ?? 0), note:'Counts are diagnostic only. Verify archive, restore, reopen and delete with real test accounts.' });
}
// SPACES_V80_3_PARTNER_EMAIL_ARCHIVES_END

// SPACES_V81_2_DM_SIGNALING_START
// Only accepted DM participants can signal. All payloads are size/type checked.
const SPACES_V81_RING_MS = 90_000;
const SPACES_V81_ACTIVE_MS = 2 * 60 * 60 * 1000;
const SPACES_V81_END_GRACE_MS = 60_000;

async function spacesV812VoiceAccess(request, env) {
  const auth = await requireUser(request, env);
  if ('response' in auth) return auth;
  return auth;
}
async function spacesV812VoiceAllowed(env, row, userId) {
  const conversation = await directConversationForUser(env, row.conversation_id, userId);
  if (!conversation || conversation.status !== 'accepted') return false;
  return !(await accountBlockExists(env, row.caller_user_id, row.callee_user_id));
}
async function spacesV812VoiceCall(request, env, callId, operation) {
  const auth = await spacesV812VoiceAccess(request, env);
  if ('response' in auth) return auth.response;
  if (!/^[a-f0-9]{32}$/u.test(callId)) return fail('Call not found.', 404);
  await finalizeExpiredDmCallsV85(env);
  const row = await env.DB.prepare(`SELECT * FROM voice_dm_calls_v81 WHERE id=? LIMIT 1`).bind(callId).first();
  const now = Date.now();
  if (!row || (row.caller_user_id !== auth.user.id && row.callee_user_id !== auth.user.id)) return fail('Call not found.', 404);
  if (!await spacesV812VoiceAllowed(env,row,auth.user.id)) return fail('Call unavailable.', 403);
  if (operation === 'read') {
    if (row.expires_at < now && row.status !== 'ended') return json({status:'ended',signals:[],lastSeq:0});
    const url = new URL(request.url);
    const after = Number(url.searchParams.get('after') ?? 0);
    if (!Number.isSafeInteger(after) || after < 0) return fail('Invalid cursor.',400);
    const records = await env.DB.prepare(`SELECT id,kind,payload,created_at FROM voice_dm_signals_v81 WHERE call_id=? AND target_user_id=? AND id>? ORDER BY id ASC LIMIT 100`).bind(callId,auth.user.id,after).all();
    const signals = (records.results ?? []).map(item => ({seq:item.id,signal:{callId,type:item.kind,...(item.payload?JSON.parse(item.payload):{})},createdAt:item.created_at}));
    return json({status:row.expires_at < now?'ended':row.status,signals,lastSeq:signals.length?signals[signals.length-1].seq:after});
  }
  if (row.status === 'ended' || row.expires_at < now) return fail('Call has ended.',409);
  const body = await readJson(request);
  const kind = String(body?.type ?? '');
  if (!['offer','answer','ice','decline','hangup'].includes(kind)) return fail('Invalid signal type.',400);
  if (kind === 'offer' && (auth.user.id !== row.caller_user_id || row.status !== 'ringing')) return fail('Only the caller can offer.',403);
  if (kind === 'answer' && (auth.user.id !== row.callee_user_id || row.status !== 'ringing')) return fail('Only the recipient can answer.',403);
  if (kind === 'decline' && auth.user.id !== row.callee_user_id) return fail('Only the recipient can decline.',403);
  if (kind === 'ice') {
    const count = await env.DB.prepare(`SELECT COUNT(*) AS n FROM voice_dm_signals_v81 WHERE call_id=? AND sender_user_id=? AND kind='ice'`).bind(callId,auth.user.id).first();
    if (Number(count?.n??0)>=120) return fail('Too many ICE candidates.',429);
    const offer = await env.DB.prepare(`SELECT id FROM voice_dm_signals_v81 WHERE call_id=? AND kind='offer' LIMIT 1`).bind(callId).first();
    if (!offer) return fail('Call offer is not ready.',409);
  }
  if (kind === 'answer') {
    const offer = await env.DB.prepare(`SELECT id FROM voice_dm_signals_v81 WHERE call_id=? AND kind='offer' LIMIT 1`).bind(callId).first();
    if (!offer) return fail('Call offer is not ready.',409);
  }
  if (kind === 'offer' || kind === 'answer') {
    const existing = await env.DB.prepare(`SELECT id FROM voice_dm_signals_v81 WHERE call_id=? AND kind=? LIMIT 1`).bind(callId,kind).first();
    if (existing) return fail('Session description already submitted.',409);
    if (!body.description || body.description.type !== kind || typeof body.description.sdp !== 'string' || body.description.sdp.length < 10 || body.description.sdp.length > 20_000) return fail('Invalid SDP description.',400);
  }
  if (kind === 'ice' && (!body.candidate || typeof body.candidate.candidate !== 'string' || body.candidate.candidate.length > 2048 || JSON.stringify(body.candidate).length > 3000)) return fail('Invalid ICE candidate.',400);
  const payload = kind === 'offer' || kind === 'answer' ? JSON.stringify({description:{type:kind,sdp:body.description.sdp}}) : kind === 'ice' ? JSON.stringify({candidate:body.candidate}) : null;
  const other = auth.user.id === row.caller_user_id ? row.callee_user_id : row.caller_user_id;
  await env.DB.prepare(`INSERT INTO voice_dm_signals_v81(call_id,sender_user_id,target_user_id,kind,payload,created_at) VALUES(?,?,?,?,?,?)`).bind(callId,auth.user.id,other,kind,payload,now).run();
  const ended = kind === 'decline' || kind === 'hangup';
  const active = kind === 'answer' || row.status === 'active';
  await env.DB.prepare(`UPDATE voice_dm_calls_v81 SET status=?,updated_at=?,expires_at=? WHERE id=?`).bind(ended?'ended':active?'active':'ringing',now,ended?now+SPACES_V81_END_GRACE_MS:active?now+SPACES_V81_ACTIVE_MS:row.expires_at,callId).run();
  if (kind === 'answer') await env.DB.prepare('UPDATE voice_dm_calls_v81 SET connected_at = COALESCE(connected_at,?) WHERE id=?').bind(now,callId).run();
  if (ended) await finishDmCallV85(env,row,kind,now);
  return json({ok:true,status:ended?'ended':active?'active':'ringing'});
}
async function spacesV812VoiceCreate(request,env) {
  const auth = await spacesV812VoiceAccess(request,env);
  if ('response' in auth) return auth.response;
  const body = await readJson(request);
  const conversationId = typeof body?.conversationId === 'string' ? body.conversationId : '';
  if (!/^[a-zA-Z0-9_-]{3,128}$/u.test(conversationId)) return fail('Invalid conversation.',400);
  const conversation = await directConversationForUser(env,conversationId,auth.user.id);
  if (!conversation || conversation.status !== 'accepted') return fail('An accepted DM is required.',403);
  const other = conversation.user_low_id === auth.user.id ? conversation.user_high_id : conversation.user_low_id;
  if (await accountBlockExists(env,auth.user.id,other)) return fail('Calling is unavailable for this conversation.',403);
  const restriction = auth.user.platform_role === 'creator' ? null : (await activeSupportRestrictionV77(env,'user',auth.user.id,'direct_messages'));
  if (restriction) return fail('Direct calls are restricted for this account.',403);
  const now = Date.now();
  // Retain ended/expired signaling briefly for the peer, then prune on call creation.
  await env.DB.prepare(`DELETE FROM voice_dm_calls_v81 WHERE expires_at<?`).bind(now-24*60*60*1000).run();
  const count = await env.DB.prepare(`SELECT COUNT(*) AS n FROM voice_dm_calls_v81 WHERE caller_user_id=? AND created_at>?`).bind(auth.user.id,now-15*60_000).first();
  if (Number(count?.n??0)>=8) return fail('Too many calls. Please wait before calling again.',429);
  const busy = await env.DB.prepare(`SELECT id FROM voice_dm_calls_v81 WHERE status IN ('ringing','active') AND expires_at>? AND (caller_user_id IN (?,?) OR callee_user_id IN (?,?)) LIMIT 1`).bind(now,auth.user.id,other,auth.user.id,other).first();
  if (busy) return fail('One of you is already in a call.',409);
  const id = crypto.randomUUID().replace(/-/gu,'');
  await env.DB.prepare(`INSERT INTO voice_dm_calls_v81(id,conversation_id,caller_user_id,callee_user_id,status,created_at,updated_at,expires_at) VALUES(?,?,?,?,'ringing',?,?,?)`).bind(id,conversationId,auth.user.id,other,now,now,now+SPACES_V81_RING_MS).run();
  return json({callId:id,conversationId,status:'ringing',expiresAt:now+SPACES_V81_RING_MS},201);
}
async function spacesV812VoiceInbox(request,env) {
  const auth = await spacesV812VoiceAccess(request,env);
  if ('response' in auth) return auth.response;
  const now=Date.now();
  await finalizeExpiredDmCallsV85(env,now);
  const rows=await env.DB.prepare(`SELECT * FROM voice_dm_calls_v81 WHERE status IN ('ringing','active') AND expires_at>? AND (caller_user_id=? OR callee_user_id=?) ORDER BY created_at DESC LIMIT 5`).bind(now,auth.user.id,auth.user.id).all();
  const calls=[];
  for(const row of rows.results??[]){
    if(!await spacesV812VoiceAllowed(env,row,auth.user.id))continue;
    const otherId=auth.user.id===row.caller_user_id?row.callee_user_id:row.caller_user_id;
    const other=await env.DB.prepare(`SELECT id,display_name,username FROM users WHERE id=? LIMIT 1`).bind(otherId).first();
    if(!other)continue;
    calls.push({callId:row.id,conversationId:row.conversation_id,direction:auth.user.id===row.caller_user_id?'outgoing':'incoming',status:row.status,person:{id:other.id,displayName:other.display_name,username:other.username},createdAt:row.created_at,expiresAt:row.expires_at});
  }
  return json({calls});
}
async function spacesV812VoiceIce(request,env){
  const auth=await spacesV812VoiceAccess(request,env);
  if('response' in auth)return auth.response;
  const servers=[{urls:['stun:stun.l.google.com:19302']}];
  const urls=String(env.VOICE_TURN_URLS??'').split(',').map(s=>s.trim()).filter(s=>/^turns?:[^\s]+$/u.test(s)).slice(0,4);
  if(urls.length && env.VOICE_TURN_SECRET){
    const expires=Math.floor(Date.now()/1000)+600;
    const username=`${expires}:spaces-${auth.user.id}`;
    const key=await crypto.subtle.importKey('raw',encoder.encode(String(env.VOICE_TURN_SECRET)),{name:'HMAC',hash:'SHA-1'},false,['sign']);
    const sig=await crypto.subtle.sign('HMAC',key,encoder.encode(username));
    const credential=btoa(String.fromCharCode(...new Uint8Array(sig)));
    servers.push({urls,username,credential});
  }
  return json({iceServers:servers,turnConfigured:servers.length>1});
}
// SPACES_V81_2_DM_SIGNALING_END


// SPACES_V83_BROADCAST_API: authenticated, persisted across web, desktop and Android.
function broadcastV83AsClient(row) {
    return {
        id: row.id, format: row.format, title: row.title, body: row.body,
        imageUrl: row.image_url || null, actionLabel: row.action_label || null,
        actionUrl: row.action_url || null, publishedAt: Number(row.published_at),
        published: Boolean(row.published), expiresAt: row.expires_at === null ? null : Number(row.expires_at),
    };
}
function broadcastV83Writer(user) {
    return user && (user.platform_role === 'creator' || user.platform_role === 'staff');
}
async function broadcastV83RequireWriter(request, env) {
    const auth = await requireUser(request, env);
    if ('response' in auth) return auth;
    if (!broadcastV83Writer(auth.user)) return { response: fail('Spaces platform Staff or Founder access is required.', 403) };
    return auth;
}
function broadcastV83Https(raw) {
    if (typeof raw !== 'string' || !raw.trim()) return null;
    try {
        const u = new URL(raw.trim());
        if (u.protocol !== 'https:' || u.username || u.password || raw.length > 1200) return null;
        return u.toString();
    } catch { return null; }
}
async function broadcastV83ListActive(request, env) {
    const auth = await requireUser(request, env);
    if ('response' in auth) return auth.response;
    const now = Date.now();
    const result = await env.DB.prepare(`SELECT b.* FROM platform_broadcasts_v83 b
       LEFT JOIN platform_broadcast_receipts_v83 r ON r.broadcast_id = b.id AND r.user_id = ?
       WHERE b.published = 1 AND b.published_at <= ? AND (b.expires_at IS NULL OR b.expires_at > ?)
       AND r.broadcast_id IS NULL
       ORDER BY b.published_at DESC LIMIT 12`).bind(auth.user.id, now, now).all();
    const distinct = new Set();
    const broadcasts = [];
    for (const row of result.results || []) {
        if (distinct.has(row.format)) continue;
        distinct.add(row.format);
        broadcasts.push(broadcastV83AsClient(row));
    }
    return json({ broadcasts });
}
async function broadcastV83Dismiss(request, env, id) {
    const auth = await requireUser(request, env);
    if ('response' in auth) return auth.response;
    if (!/^[0-9a-f-]{36}$/i.test(id)) return fail('Invalid broadcast ID.', 400);
    const exists = await env.DB.prepare('SELECT id FROM platform_broadcasts_v83 WHERE id = ?').bind(id).first();
    if (!exists) return fail('Broadcast not found.', 404);
    await env.DB.prepare(`INSERT OR IGNORE INTO platform_broadcast_receipts_v83(user_id, broadcast_id, dismissed_at)
      VALUES (?, ?, ?)`).bind(auth.user.id, id, Date.now()).run();
    return json({ dismissed: true });
}
async function broadcastV83ListStaff(request, env) {
    const auth = await broadcastV83RequireWriter(request, env);
    if ('response' in auth) return auth.response;
    const result = await env.DB.prepare(`SELECT * FROM platform_broadcasts_v83
      ORDER BY created_at DESC LIMIT 60`).all();
    return json({ broadcasts: (result.results || []).map(broadcastV83AsClient) });
}
async function broadcastV83Publish(request, env) {
    const auth = await broadcastV83RequireWriter(request, env);
    if ('response' in auth) return auth.response;
    const value = await readJson(request);
    const format = String(value?.format || '');
    const title = String(value?.title || '').trim();
    const body = String(value?.body || '').trim();
    const imageInput = String(value?.imageUrl || '').trim();
    const actionInput = String(value?.actionUrl || '').trim();
    const actionLabel = String(value?.actionLabel || '').trim();
    if (!['banner', 'modal'].includes(format)) return fail('Select a banner or popup announcement.');
    if (title.length < 2 || title.length > 120) return fail('Title must contain 2–120 characters.');
    if (body.length > 4000) return fail('Description cannot exceed 4000 characters.');
    if (format === 'banner' && body.length > 220) return fail('Top banner description must be 220 characters or fewer.');
    if (imageInput && !broadcastV83Https(imageInput)) return fail('Images must use a valid HTTPS URL.');
    if (actionInput && (!broadcastV83Https(actionInput) || !actionLabel)) return fail('Link needs a secure HTTPS URL and button label.');
    if (actionLabel.length > 50) return fail('Button label must be 50 characters or fewer.');
    if (format === 'banner' && imageInput) return fail('Images are only available in popup announcements.');
    const now = Date.now(), id = crypto.randomUUID();
    // Only one active announcement of each format: no stack of old popups.
    await env.DB.batch([
        env.DB.prepare('UPDATE platform_broadcasts_v83 SET published = 0 WHERE format = ? AND published = 1').bind(format),
        env.DB.prepare(`INSERT INTO platform_broadcasts_v83
           (id,format,title,body,image_url,action_label,action_url,published,created_by,created_at,published_at,expires_at)
           VALUES (?,?,?,?,?,?,?,1,?,?,?,NULL)`).bind(id, format, title, body, imageInput || null, actionLabel || null, actionInput || null, auth.user.id, now, now),
    ]);
    return json({ broadcast: { id, format, title, body, imageUrl: imageInput || null, actionLabel: actionLabel || null, actionUrl: actionInput || null, published: true, publishedAt: now } }, 201);
}
async function broadcastV83Unpublish(request, env, id) {
    const auth = await broadcastV83RequireWriter(request, env);
    if ('response' in auth) return auth.response;
    if (!/^[0-9a-f-]{36}$/i.test(id)) return fail('Invalid broadcast ID.');
    const result = await env.DB.prepare('UPDATE platform_broadcasts_v83 SET published = 0 WHERE id = ?').bind(id).run();
    return json({ unpublished: Number(result.meta?.changes || 0) > 0 });
}
async function broadcastV83UploadImage(request, env) {
    const auth = await broadcastV83RequireWriter(request, env);
    if ('response' in auth) return auth.response;
    if (!env.DESKTOP_RELEASES) return fail('Broadcast image storage is not configured.', 503);
    const contentType = (request.headers.get('Content-Type') || '').split(';')[0].trim().toLowerCase();
    const suffix = { 'image/png': 'png', 'image/jpeg': 'jpg', 'image/webp': 'webp' }[contentType];
    if (!suffix) return fail('Upload a PNG, JPEG or WebP image.', 415);
    const claimed = Number(request.headers.get('Content-Length') || 0);
    if (claimed > 1024 * 1024) return fail('Image must be at most 1 MB.', 413);
    const data = new Uint8Array(await request.arrayBuffer());
    if (data.byteLength < 12 || data.byteLength > 1024 * 1024) return fail('Image must be 1 MB or smaller.', 413);
    const isPng = data[0]===137 && data[1]===80 && data[2]===78 && data[3]===71;
    const isJpeg = data[0]===255 && data[1]===216 && data[2]===255;
    const isWebp = String.fromCharCode(...data.slice(0,4))==='RIFF' && String.fromCharCode(...data.slice(8,12))==='WEBP';
    if (!(suffix === 'png' && isPng || suffix === 'jpg' && isJpeg || suffix === 'webp' && isWebp)) return fail('Image content does not match its type.', 415);
    const name = `${crypto.randomUUID()}.${suffix}`;
    await env.DESKTOP_RELEASES.put(`broadcast/images/${name}`, data, { httpMetadata: { contentType } });
    return json({ imageUrl: `https://spaces.spagotei.workers.dev/v1/broadcast-images/${name}` }, 201);
}
async function broadcastV83GetImage(env, filename, method) {
    if (!/^[0-9a-f-]{36}\.(?:png|jpg|webp)$/i.test(filename)) return fail('Not found.',404);
    if (!env.DESKTOP_RELEASES) return fail('Not found.',404);
    const object = await env.DESKTOP_RELEASES.get(`broadcast/images/${filename}`);
    if (!object) return fail('Not found.',404);
    const h = new Headers(corsHeaders());
    h.set('Content-Type', object.httpMetadata?.contentType || 'image/png');
    h.set('Cache-Control', 'public, max-age=604800, immutable');
    h.set('X-Content-Type-Options','nosniff');
    return new Response(method === 'HEAD' ? null : object.body, { status: 200, headers: h });
}


// SPACES_V84_EMAIL_STUDIO_API: verified-account one-to-one email, staff access, safe formatted HTML.
// Sender is decided entirely by the server; client cannot submit arbitrary From headers.
const spacesV84SenderAddresses = Object.freeze({
  noreply: 'noreply@yourspaces.net',
  support: 'support@yourspaces.net',
  hello: 'hello@yourspaces.net',
  security: 'security@yourspaces.net',
});
function spacesV84Error(message, status = 400) { return fail(message, status); }
function spacesV84Escape(s) {
  return String(s ?? '').replace(/[&<>"']/gu, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
function spacesV84Plain(s, max) { return String(s ?? '').replace(/[\u0000-\u001f\u007f]/gu, ' ').trim().slice(0,max); }
function spacesV84Sender(env, key, user) {
  const names = {support:'Spaces Support',hello:'Spaces',noreply:'Spaces Notifications',security:'Spaces Security'};
  if (!Object.hasOwn(spacesV84SenderAddresses,key)) throw new Error('Unknown email sender.');
  if (key === 'security' && user.platform_role !== 'creator') throw new Error('Security sender is Founder-only.');
  const addr = spacesV84SenderAddresses[key];
  const root = String(env.SPACES_EMAIL_FROM || '');
  if (!validEmail(root) || root.toLowerCase().split('@')[1] !== 'yourspaces.net') throw new Error('Verified Spaces email domain is not configured.');
  if (!env.EMAIL || typeof env.EMAIL.send !== 'function') throw new Error('Cloudflare email sending is not configured.');
  return { email:addr, name:names[key] };
}
async function spacesV84Access(request, env) {
  const auth = await spacesV924EmailAccess(request, env, 'view');
  if ('response' in auth) return auth;
  if (!['creator','staff'].includes(auth.user.platform_role)) return {response:spacesV84Error('Custom email is restricted to Founder and platform Staff.',403)};
  return auth;
}
function spacesV84Url(value) {
  try { const u = new URL(value); if (u.protocol !== 'https:' || u.username || u.password || value.length > 1200) return null; return u.href; }
  catch { return null; }
}
function spacesV84Inline(input) {
  const s = String(input ?? '');
  const regex = /\[color=(#[0-9a-fA-F]{6})\]([^\n]*?)\[\/color\]|\[bg=(#[0-9a-fA-F]{6})\]([^\n]*?)\[\/bg\]|\[([^\]\n]{1,100})\]\((https:\/\/[^\s)]+)\)|\*\*([^*\n]+)\*\*|__([^_\n]+)__|~~([^~\n]+)~~|\*([^*\n]+)\*|`([^`\n]+)`/gu;
  let out = '', cursor = 0, found;
  while ((found = regex.exec(s))) {
    out += spacesV84Escape(s.slice(cursor,found.index));
    if (found[1]) out += `<span style="color:${found[1]}">${spacesV84Escape(found[2])}</span>`;
    else if (found[3]) out += `<span style="background-color:${found[3]};padding:1px 3px;border-radius:3px">${spacesV84Escape(found[4])}</span>`;
    else if (found[5]) {
      const url = spacesV84Url(found[6]);
      out += url ? `<a href="${spacesV84Escape(url)}" style="color:#c6a4ff;text-decoration:underline">${spacesV84Escape(found[5])}</a>` : spacesV84Escape(found[0]);
    }
    else if (found[7]) out += `<strong>${spacesV84Escape(found[7])}</strong>`;
    else if (found[8]) out += `<u>${spacesV84Escape(found[8])}</u>`;
    else if (found[9]) out += `<s>${spacesV84Escape(found[9])}</s>`;
    else if (found[10]) out += `<em>${spacesV84Escape(found[10])}</em>`;
    else if (found[11]) out += `<code style="font-family:monospace;background:#f0eaf7;padding:2px 4px;border-radius:4px">${spacesV84Escape(found[11])}</code>`;
    cursor = regex.lastIndex;
  }
  return out + spacesV84Escape(s.slice(cursor));
}
function spacesV84RichBody(body) {
  const lines = String(body ?? '').replace(/\r\n?/gu,'\n').split('\n');
  const out=[]; let list=[]; let ordered = false;
  const flush = () => { if(list.length){out.push(`<${ordered?'ol':'ul'} style="margin:8px 0 16px;padding-left:24px">${list.join('')}</${ordered?'ol':'ul'}>`);list=[];} };
  for (const line of lines) {
    if (/^\s*$/.test(line)) { flush();out.push('<div style="height:11px"></div>');continue; }
    const bullet = line.match(/^\s{0,3}([-*]|\d+\.)\s+(.+)$/u);
    if(bullet){const nextOrdered=/\d/.test(bullet[1]);if(list.length && ordered!==nextOrdered)flush();ordered=nextOrdered;list.push(`<li style="margin:4px 0">${spacesV84Inline(bullet[2])}</li>`);continue;}
    flush();
    const h=line.match(/^(#{1,3})\s+(.+)$/u);
    if(h){const level=h[1].length;out.push(`<h${level} style="margin:12px 0 8px;color:#17121f;font-family:Arial,sans-serif;font-size:${level===1?28:level===2?22:18}px;line-height:1.3">${spacesV84Inline(h[2])}</h${level}>`);continue;}
    if(/^\s*---+\s*$/.test(line)){out.push('<hr style="border:0;border-top:1px solid #e8e2ee;margin:17px 0">');continue;}
    if(/^>\s?/.test(line)){out.push(`<blockquote style="margin:10px 0;padding:10px 14px;border-left:3px solid #ac85dd;background:#f6f1fa;color:#4a3e54">${spacesV84Inline(line.replace(/^>\s?/,''))}</blockquote>`);continue;}
    out.push(`<p style="margin:0;line-height:1.7">${spacesV84Inline(line)}</p>`);
  }
  flush();return out.join('\n');
}
function spacesV84Html(title,subject,body,bannerUrl,replyTo) {
  const header = bannerUrl ? `<img src="${spacesV84Escape(bannerUrl)}" width="600" alt="Spaces" style="display:block;width:100%;max-width:600px;height:auto;border:0">` : `<div style="background:linear-gradient(120deg,#221832,#684c8c);padding:37px 34px;color:#f8f4ff;font:700 30px Arial,sans-serif">Spaces</div>`;
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${spacesV84Escape(subject)}</title></head><body style="margin:0;padding:30px 10px;background:#f3f0f6;color:#30283a;font-family:Arial,Helvetica,sans-serif"><table role="presentation" cellpadding="0" cellspacing="0" style="margin:0 auto;width:100%;max-width:600px;border-collapse:collapse;background:#fff;border-radius:12px;overflow:hidden"><tr><td>${header}</td></tr><tr><td style="padding:32px 36px 35px"><div style="color:#8360ad;font-size:11px;font-weight:700;letter-spacing:2px;margin-bottom:12px">SPACES OFFICIAL MESSAGE</div><h1 style="color:#17121f;font-size:25px;line-height:1.25;margin:0 0 20px">${spacesV84Escape(title||subject)}</h1><div style="color:#342c3f;font-size:15px;line-height:1.7">${spacesV84RichBody(body)}</div></td></tr><tr><td style="padding:23px 36px;background:#f8f5fb;color:#786c82;font-size:11px;line-height:1.7">Sent by Spaces. Questions? Reply to <a href="mailto:${spacesV84Escape(replyTo)}" style="color:#694a92">${spacesV84Escape(replyTo)}</a>.<br>Never share your password or verification codes over email.</td></tr></table></body></html>`;
}
function spacesV84Payload(raw) {
  const body=String(raw?.body ?? '').replace(/\r\n?/gu,'\n').trim();
  const subject=spacesV84Plain(raw?.subject,180);
  const heading=spacesV84Plain(raw?.heading,120);
  if (!subject || subject.length < 3 || subject.length > 180) throw new Error('Subject must be 3–180 characters.');
  if (body.length < 3 || body.length > 8000) throw new Error('Message must be 3–8000 characters.');
  const sender=String(raw?.sender ?? 'support');
  if(!Object.hasOwn(spacesV84SenderAddresses,sender)) throw new Error('Unsupported sender address.');
  const bannerId=String(raw?.bannerId ?? '');
  if(bannerId && !/^[0-9a-f-]{36}\.(?:png|jpg|webp)$/i.test(bannerId)) throw new Error('Select an uploaded banner from Spaces.');
  return {subject,heading,body,sender,bannerId};
}
const spacesV84BannerPrefix='mail/banners/';
const spacesV84ImageBase='https://spaces.spagotei.workers.dev/v1/mail-images/';
async function spacesV84EnsureBanner(env, bannerId) {
  if (!bannerId) return '';
  if (!env.DESKTOP_RELEASES) throw new Error('Email banner storage is unavailable.');
  const asset=await env.DESKTOP_RELEASES.head(spacesV84BannerPrefix+bannerId);
  if(!asset) throw new Error('Selected banner could not be found.');
  return spacesV84ImageBase+bannerId;
}
async function spacesV84Preview(request,env) {
  const auth=await spacesV84Access(request,env);if('response'in auth)return auth.response;
  try {
    const item=spacesV84Payload(await readJson(request));
    spacesV84Sender(env,item.sender,auth.user);
    const banner=await spacesV84EnsureBanner(env,item.bannerId);
    return json({html:spacesV84Html(item.heading,item.subject,item.body,banner,'support@yourspaces.net')});
  } catch(e){return spacesV84Error(e.message,400)}
}
async function spacesV84Capabilities(request,env) {
  const auth=await spacesV84Access(request,env);if('response'in auth)return auth.response;
  return json({canSend:Boolean(env.EMAIL&&typeof env.EMAIL.send==='function'),senders:auth.user.platform_role==='creator'?['support','hello','noreply','security']:['support','hello','noreply'],requiresVerifiedMember:true,maxRecipients:20,audiences:[{id:"selected",label:"Selected members"},{id:"platform_staff",label:"Platform Staff and Support"},{id:"beta_members",label:"Claimed beta members"}]});
}
async function spacesV84ListBanners(request,env) {
  const auth=await spacesV84Access(request,env);if('response'in auth)return auth.response;
  if(!env.DESKTOP_RELEASES)return spacesV84Error('Email image storage unavailable.',503);
  const objects=await env.DESKTOP_RELEASES.list({prefix:spacesV84BannerPrefix,limit:100});
  return json({banners:(objects.objects||[]).filter(obj=>/^[0-9a-f-]{36}\.(?:png|jpg|webp)$/i.test(obj.key.slice(spacesV84BannerPrefix.length))).map(obj=>({id:obj.key.slice(spacesV84BannerPrefix.length),url:spacesV84ImageBase+obj.key.slice(spacesV84BannerPrefix.length),createdAt:obj.uploaded?.getTime?.()||0})).reverse()});
}
async function spacesV84UploadBanner(request,env) {
  const auth=await spacesV84Access(request,env);if('response'in auth)return auth.response;
  if(!env.DESKTOP_RELEASES)return spacesV84Error('Email image storage unavailable.',503);
  await enforceRateLimit(request,env,'staff-email-asset-v84',15,60*60*1000,auth.user.id);
  const type=(request.headers.get('Content-Type')||'').split(';')[0].toLowerCase();
  const ext=({'image/png':'png','image/jpeg':'jpg','image/webp':'webp'})[type];
  if(!ext)return spacesV84Error('Choose a PNG, JPEG or WebP banner.',415);
  if(Number(request.headers.get('Content-Length')||0)>1536*1024)return spacesV84Error('Banner cannot exceed 1.5 MB.',413);
  const data=new Uint8Array(await request.arrayBuffer());
  if(data.length<12||data.length>1536*1024)return spacesV84Error('Banner cannot exceed 1.5 MB.',413);
  const png=data[0]===137&&data[1]===80&&data[2]===78&&data[3]===71;
  const jpg=data[0]===255&&data[1]===216&&data[2]===255;
  const webp=String.fromCharCode(...data.slice(0,4))==='RIFF'&&String.fromCharCode(...data.slice(8,12))==='WEBP';
  if(!(ext==='png'&&png||ext==='jpg'&&jpg||ext==='webp'&&webp))return spacesV84Error('Image bytes do not match upload type.',415);
  const id=crypto.randomUUID()+'.'+ext;
  await env.DESKTOP_RELEASES.put(spacesV84BannerPrefix+id,data,{httpMetadata:{contentType:type}});
  return json({banner:{id,url:spacesV84ImageBase+id,createdAt:Date.now()}},201);
}
async function spacesV84GetBanner(env,id,method) {
  if(!/^[0-9a-f-]{36}\.(?:png|jpg|webp)$/i.test(id)||!env.DESKTOP_RELEASES)return spacesV84Error('Not found.',404);
  const obj=await env.DESKTOP_RELEASES.get(spacesV84BannerPrefix+id);
  if(!obj)return spacesV84Error('Not found.',404);
  const headers=new Headers(corsHeaders());
  headers.set('Content-Type',obj.httpMetadata?.contentType||'image/png');
  headers.set('X-Content-Type-Options','nosniff');
  headers.set('Cache-Control','public,max-age=86400');
  return new Response(method==='HEAD'?null:obj.body,{status:200,headers});
}
async function spacesV84History(request,env) {
  const auth=await spacesV84Access(request,env);if('response'in auth)return auth.response;
  const result=await env.DB.prepare('SELECT id,recipient_email,sender_address,subject,status,created_at,completed_at,campaign_id FROM platform_email_deliveries_v84 WHERE actor_user_id=? ORDER BY created_at DESC LIMIT 80').bind(auth.user.id).all();
  return json({deliveries:(result.results||[]).map(r=>({id:r.id,recipientEmail:r.recipient_email,sender:r.sender_address,subject:r.subject,status:r.status,campaignId:r.campaign_id,createdAt:Number(r.created_at),completedAt:r.completed_at?Number(r.completed_at):null}))});
}
// Audiences are resolved on the server. Never accept recipient addresses from client-side preview data.
const spacesV84MaxRecipients = 20;
async function spacesV84ResolveAudience(env, audience, selected, actorId='') {
  const rows=[];
  if (audience === 'self') {
    const own=await env.DB.prepare('SELECT id,email,email_verified,display_name FROM users WHERE id=? LIMIT 1').bind(actorId).first();
    if(!own || !Number(own.email_verified) || !validEmail(own.email))throw Error('Your own Spaces account must have a verified email to send a test.');
    rows.push(own);
  } else if (audience === 'selected') {
    const values=String(selected||'').split(/[\r\n,;]+/u).map(v=>v.trim()).filter(Boolean);
    const unique=[...new Set(values.map(v=>v.toLowerCase()))];
    if (!unique.length || unique.length>spacesV84MaxRecipients) throw Error('Select 1–20 Spaces members (separate emails or user IDs with commas or new lines).');
    for (const value of unique) {
      if (value.length>254) throw Error('A recipient entry is too long.');
      const row=await env.DB.prepare('SELECT id,email,email_verified,display_name FROM users WHERE email=? COLLATE NOCASE OR public_user_id=? OR id=? LIMIT 1').bind(value,value,value).first();
      if(!row || !Number(row.email_verified) || !validEmail(row.email)) throw Error('Each recipient must have a verified Spaces account: '+value);
      rows.push(row);
    }
  } else if (audience === 'platform_staff') {
    const result=await env.DB.prepare("SELECT id,email,email_verified,display_name FROM users WHERE email_verified=1 AND platform_role IN ('creator','staff','support') ORDER BY id ASC LIMIT 21").all();
    rows.push(...(result.results||[]));
  } else if (audience === 'beta_members') {
    const result=await env.DB.prepare("SELECT DISTINCT u.id,u.email,u.email_verified,u.display_name FROM users u JOIN beta_access b ON b.user_id=u.id AND b.status='claimed' WHERE u.email_verified=1 ORDER BY u.id ASC LIMIT 21").all();
    rows.push(...(result.results||[]));
  } else throw Error('Invalid audience.');
  if(rows.length>spacesV84MaxRecipients) throw Error('This group exceeds the safe 20-recipient limit. Use a smaller selected list; automated batch queues can be added in a future release.');
  const unique=new Map();for(const row of rows)if(row?.id && validEmail(row.email))unique.set(row.id,row);
  const eligible=[];let optedOut=0;
  for(const row of unique.values()) {
    const pref=await env.DB.prepare('SELECT opted_out FROM platform_email_preferences_v84 WHERE user_id=?').bind(row.id).first();
    if(Number(pref?.opted_out||0)){optedOut++;continue;}
    eligible.push(row);
  }
  return {eligible,optedOut};
}
async function spacesV84AudiencePreview(request,env) {
  const auth=await spacesV84Access(request,env);if('response'in auth)return auth.response;
  try {
    const raw=await readJson(request);
    const audience=String(raw?.audience||'selected');
    const selection=String(raw?.recipient||'');
    const result=await spacesV84ResolveAudience(env,audience,selection,auth.user.id);
    return json({audience,count:result.eligible.length,excluded:result.optedOut,recipients:result.eligible.map(row=>({name:row.display_name,email:row.email}))});
  } catch(e){return spacesV84Error(e.message,400);}
}
async function spacesV84GetOrCreateUnsub(env,userId) {
  const existing=await env.DB.prepare('SELECT token FROM platform_email_preferences_v84 WHERE user_id=?').bind(userId).first();
  if(existing?.token)return existing.token;
  const token=crypto.randomUUID()+crypto.randomUUID().replace(/-/g,'');
  await env.DB.prepare('INSERT OR IGNORE INTO platform_email_preferences_v84(user_id,token,opted_out,updated_at) VALUES(?,?,0,?)').bind(userId,token,Date.now()).run();
  const fresh=await env.DB.prepare('SELECT token FROM platform_email_preferences_v84 WHERE user_id=?').bind(userId).first();
  return fresh?.token||token;
}
async function spacesV84Unsubscribe(request,env,token) {
  if(!/^[a-f0-9-]{68}$/i.test(token))return new Response('Invalid link.',{status:400,headers:{'Content-Type':'text/plain'}});
  const row=await env.DB.prepare('SELECT user_id FROM platform_email_preferences_v84 WHERE token=?').bind(token).first();
  if(!row)return new Response('Link not found.',{status:404,headers:{'Content-Type':'text/plain'}});
  if(request.method==='POST') {
    await env.DB.prepare('UPDATE platform_email_preferences_v84 SET opted_out=1,updated_at=? WHERE user_id=?').bind(Date.now(),row.user_id).run();
  }
  const done=request.method==='POST';
  return new Response(`<!doctype html><html><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Spaces email preferences</title><body style="font:16px system-ui;background:#100e17;color:white;display:grid;place-items:center;min-height:80vh"><main style="padding:30px;max-width:440px"><h1>Spaces</h1><p>${done?'You have unsubscribed from nonessential Spaces staff emails.':'Stop receiving nonessential Spaces staff emails? Account security emails may still be delivered.'}</p>${done?'':'<form method="post"><button style="padding:12px 20px;border:0;border-radius:10px;cursor:pointer">Unsubscribe</button></form>'}</main></body></html>`,{status:200,headers:{'Content-Type':'text/html;charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer'}});
}
async function spacesV84Send(request,env) {
  const auth=await spacesV924EmailAccess(request,env,'send');if('response'in auth)return auth.response;
  if(!env.EMAIL||typeof env.EMAIL.send!=='function')return spacesV84Error('Spaces email sending is not configured.',503);
  try {
    await enforceRateLimit(request,env,'staff-composed-email-v84',4,60*60*1000,auth.user.id);
    const raw=await readJson(request);
    const payload=spacesV84Payload(raw);
    const sender=spacesV84Sender(env,payload.sender,auth.user);
    const bannerUrl=await spacesV84EnsureBanner(env,payload.bannerId);
    const audience=raw?.testOnly===true?'self':String(raw?.audience||'selected');
    const resolved=await spacesV84ResolveAudience(env,audience,raw?.recipient,auth.user.id);
    const recipients=resolved.eligible;
    if(!recipients.length)return spacesV84Error('No eligible, subscribed recipients in this audience.',409);
    if(Number(raw?.confirmedCount)!==recipients.length)return spacesV84Error('Audience changed since preview. Review recipients and confirm again.',409);
    const sendId=String(raw?.sendId||'');
    if(!/^[0-9a-f-]{36}$/i.test(sendId))return spacesV84Error('Invalid send confirmation.',400);
    const now=Date.now();
    const campaignId=crypto.randomUUID();
    const claim=await env.DB.prepare("INSERT OR IGNORE INTO platform_email_campaigns_v84(id,actor_user_id,audience,recipient_count,subject,send_id,created_at) VALUES (?,?,?,?,?,?,?)").bind(campaignId,auth.user.id,audience,recipients.length,payload.subject,sendId,now).run();
    if(Number(claim?.meta?.changes||0)!==1)return spacesV84Error('This campaign has already been submitted. Check sent history.',409);
    const replyTo=validEmail(String(env.SPACES_EMAIL_REPLY_TO||''))?String(env.SPACES_EMAIL_REPLY_TO):'support@yourspaces.net';
    let succeeded=0,failed=0;
    for(const user of recipients) {
      const deliveryId=crypto.randomUUID();
      // Claim each recipient before contacting the provider. Failed or interrupted sends are not silently retried.
      const inserted=await env.DB.prepare("INSERT OR IGNORE INTO platform_email_deliveries_v84(id,campaign_id,actor_user_id,recipient_user_id,recipient_email,sender_address,subject,status,send_id,created_at) VALUES (?,?,?,?,?,?,?,'sending',?,?)").bind(deliveryId,campaignId,auth.user.id,user.id,user.email,sender.email,payload.subject,sendId,Date.now()).run();
      if(Number(inserted?.meta?.changes||0)!==1)continue;
      try {
        const unsubToken=await spacesV84GetOrCreateUnsub(env,user.id);
        const unsubUrl='https://spaces.spagotei.workers.dev/v1/email/unsubscribe/'+unsubToken;
        const html=spacesV84Html(payload.heading,payload.subject,payload.body,bannerUrl,replyTo)
          .replace('</body>',`<div style="text-align:center;padding:12px;font:11px Arial;color:#777">Nonessential staff notices: <a href="${spacesV84Escape(unsubUrl)}">unsubscribe</a></div></body>`);
        const plain=`${payload.heading||payload.subject}\n\n${payload.body}\n\nSpaces — ${replyTo}\nUnsubscribe from nonessential notices: ${unsubUrl}`;
        const result=await env.EMAIL.send({to:user.email,from:sender,replyTo,subject:payload.subject,text:plain,html});
        await env.DB.prepare("UPDATE platform_email_deliveries_v84 SET status='sent',provider_message_id=?,completed_at=? WHERE id=?").bind(String(result?.messageId||''),Date.now(),deliveryId).run();
        succeeded++;
      } catch(e) {
        console.error('Spaces mail delivery failed:',e?.code||'SEND_FAILED');
        await env.DB.prepare("UPDATE platform_email_deliveries_v84 SET status='failed',error_code=?,completed_at=? WHERE id=?").bind(spacesV84Plain(e?.code||'EMAIL_PROVIDER_ERROR',80),Date.now(),deliveryId).run();
        failed++;
      }
    }
    return json({campaignId,sent:succeeded,failed,total:recipients.length,excluded:resolved.optedOut},failed?207:201);
  } catch(e){return spacesV84Error(e?.message||'Email campaign failed.',400);}
}


// SPACES_V84_2_STAFF_CENTER_API
// Read-only support overview: Staff/Founder only, authenticated on EVERY request.
// Account email addresses are sensitive; server side authorization is mandatory.
async function spacesV842CenterAccess(request, env) {
  // Reuse V84 role+capability check; browser Developer Mode only controls visibility.
  const auth = await spacesV84Access(request, env);
  if ('response' in auth) return auth;
  await enforceRateLimit(request, env, 'staff-center-read-v842', 60, 3600000, auth.user.id);
  return auth;
}
async function spacesV842CenterAudit(env, actor, operation, count) {
  // Audit data access without storing searched names or email addresses.
  await env.DB.prepare('INSERT INTO platform_staff_access_audit_v84_2 (id,actor_user_id,action,row_count,created_at) VALUES (?,?,?,?,?)')
    .bind(crypto.randomUUID(),actor,operation,count,Date.now()).run();
}
async function spacesV842CenterAccounts(request, env) {
  const auth = await spacesV842CenterAccess(request,env);
  if ('response' in auth) return auth.response;
  const query = String(new URL(request.url).searchParams.get('q')||'').trim().slice(0,80);
  if (query.length < 2) return json({accounts:[],hint:'Search at least two characters to look up a member.'});
  // Literal search: escape SQL LIKE wildcard operators; bound value prevents injection.
  const q = '%'+query.replace(/[\\%_]/g,'\\$&')+'%';
  const {results=[]} = await env.DB.prepare("SELECT id,public_user_id,username,display_name,email,email_verified,platform_role FROM users WHERE username LIKE ? ESCAPE '\\' OR display_name LIKE ? ESCAPE '\\' OR email LIKE ? ESCAPE '\\' OR public_user_id LIKE ? ESCAPE '\\' ORDER BY username LIMIT 30")
    .bind(q,q,q,q).all();
  await spacesV842CenterAudit(env,auth.user.id,'member_email_lookup',results.length);
  return json({accounts:results.map(u=>({id:u.id,publicUserId:u.public_user_id,username:u.username,displayName:u.display_name,email:u.email,verified:Boolean(u.email_verified),platformRole:u.platform_role==='creator'?'founder':u.platform_role||null}))});
}
async function spacesV842CenterSent(request,env) {
  const auth=await spacesV842CenterAccess(request,env);
  if('response' in auth)return auth.response;
  const {results=[]}=await env.DB.prepare('SELECT d.id,d.sender_address,d.recipient_email,d.subject,d.status,d.created_at,d.completed_at,d.campaign_id,coalesce(u.username,\'\') AS recipient_username,coalesce(a.username,\'\') AS staff_username FROM platform_email_deliveries_v84 d LEFT JOIN users u ON u.id=d.recipient_user_id LEFT JOIN users a ON a.id=d.actor_user_id ORDER BY d.created_at DESC LIMIT 100').all();
  await spacesV842CenterAudit(env,auth.user.id,'outbound_delivery_history',results.length);
  return json({deliveries:results.map(r=>({id:r.id,from:r.sender_address,to:r.recipient_email,subject:r.subject,status:r.status,createdAt:Number(r.created_at),completedAt:r.completed_at?Number(r.completed_at):null,campaignId:r.campaign_id,recipientUsername:r.recipient_username,staffUsername:r.staff_username})),inboundConfigured:false});
}


const staffCenterV843 = createStaffCenter({authorize:spacesV84Access,json,rateLimit:enforceRateLimit});

// SPACES_V913_EXTERNAL_EMAIL: one-to-one, authenticated, rate-limited, audited external mail.
// No raw HTML, arbitrary From headers, bulk lists, or recipient emails from ticket identifiers.
function spacesV913EmailTarget(value) {
  const email = String(value ?? '').trim().toLowerCase();
  if (email.length > 254 || /[,;\s<>\r\n]/u.test(email) || !validEmail(email)) throw Error('Enter one valid email address. Lists and headers are not allowed.');
  return email;
}
async function spacesV913ExternalCheck(request, env) {
  const auth=await spacesV84Access(request,env);if('response' in auth)return auth.response;
  try {
    const data=await readJson(request);
    spacesV84Sender(env,String(data?.sender||'support'),auth.user);
    return json({email:spacesV913EmailTarget(data?.recipientEmail)});
  } catch(error) {return spacesV84Error(error.message||'Invalid destination.',400)}
}
async function spacesV913ResolveTicket(request,env) {
  const auth=await spacesV84Access(request,env);if('response' in auth)return auth.response;
  try {
    await enforceRateLimit(request,env,'staff-email-ticket-lookup-v913',30,60*60*1000,auth.user.id);
    const data=await readJson(request);const ticketId=String(data?.ticketId||'').trim();
    if(ticketId.length<2||ticketId.length>90)throw Error('Enter a valid ticket or case ID.');
    const row=await env.DB.prepare('SELECT c.reporter_id AS user_id, u.email_verified, u.email FROM support_cases_v77 c JOIN users u ON u.id=c.reporter_id WHERE c.id=? OR c.case_number=? LIMIT 1').bind(ticketId,ticketId).first();
    if(!row||!Number(row.email_verified)||!validEmail(row.email))return spacesV84Error('No verified account email is available for that ticket.',404);
    return json({userId:row.user_id});
  }catch(error){return spacesV84Error(error.message||'Could not resolve ticket.',400)}
}
async function spacesV913ExternalSend(request,env) {
  const auth=await spacesV924EmailAccess(request,env,'send');if('response' in auth)return auth.response;
  if(!env.EMAIL||typeof env.EMAIL.send!=='function')return spacesV84Error('Spaces email sending is not configured.',503);
  try {
    await enforceRateLimit(request,env,'staff-one-recipient-external-v913',auth.founder?20:3,60*60*1000,auth.user.id);
    const data=await readJson(request);
    const payload=spacesV84Payload(data);
    const sender=spacesV84Sender(env,payload.sender,auth.user);
    const email=spacesV913EmailTarget(data?.recipientEmail);
    if(email!==spacesV913EmailTarget(data?.confirmedEmail))throw Error('Recipient changed after review. Review again.');
    const sendId=String(data?.sendId||'');
    if(!/^[0-9a-f-]{36}$/i.test(sendId))throw Error('Invalid send ID.');
    if(payload.body.length<3)throw Error('Write a message first.');
    const bannerUrl=await spacesV84EnsureBanner(env,payload.bannerId);
    const recordId=crypto.randomUUID(),now=Date.now();
    const claimed=await env.DB.prepare("INSERT OR IGNORE INTO platform_email_external_v913 (id,actor_user_id,recipient_email,sender_address,subject,status,send_id,created_at) VALUES (?,?,?,?,?,'sending',?,?)").bind(recordId,auth.user.id,email,sender.email,payload.subject,sendId,now).run();
    if(Number(claimed?.meta?.changes||0)!==1)return spacesV84Error('This send has already been submitted. Check sent history.',409);
    const configuredReply=String(env.SPACES_EMAIL_REPLY_TO||'');
    const replyTo=validEmail(configuredReply)?configuredReply:'support@yourspaces.net';
    const plain=`${payload.heading||payload.subject}\n\n${payload.body}\n\nSpaces — ${replyTo}`;
    try {
      const result=await env.EMAIL.send({to:email,from:sender,replyTo,subject:payload.subject,text:plain,html:spacesV84Html(payload.heading,payload.subject,payload.body,bannerUrl,replyTo)});
      await env.DB.prepare("UPDATE platform_email_external_v913 SET status='sent',provider_message_id=?,completed_at=? WHERE id=?").bind(String(result?.messageId||''),Date.now(),recordId).run();
      return json({sent:1,failed:0,deliveryId:recordId},201);
    } catch(error) {
      console.error('Spaces external mail provider rejected a send:',error?.code||'EMAIL_PROVIDER_ERROR');
      await env.DB.prepare("UPDATE platform_email_external_v913 SET status='failed',error_code=?,completed_at=? WHERE id=?").bind(spacesV84Plain(error?.code||'EMAIL_PROVIDER_ERROR',80),Date.now(),recordId).run();
      return spacesV84Error('Provider did not accept email. Check sender verification and sent history.',502);
    }
  }catch(error){return spacesV84Error(error?.message||'External email failed.',400)}
}
async function spacesV913History(request,env) {
  const auth=await spacesV84Access(request,env);if('response' in auth)return auth.response;
  const rows=await env.DB.prepare('SELECT id,recipient_email,sender_address,subject,status,created_at FROM platform_email_external_v913 WHERE actor_user_id=? ORDER BY created_at DESC LIMIT 100').bind(auth.user.id).all();
  return json({deliveries:(rows.results||[]).map(row=>({id:row.id,recipientEmail:row.recipient_email,sender:row.sender_address,subject:row.subject,status:row.status,createdAt:Number(row.created_at)}))});
}


// SPACES_V924_EMAIL_GOVERNANCE — separate Founder-configurable email permissions.
// No client-provided recipient lists or From addresses are trusted in global sends.
const spacesV924IsFounder = user => user?.platform_role === 'creator';
const spacesV924SafeText = (v,n=500) => String(v??'').trim().slice(0,n);
const spacesV924True = v => Number(v) === 1;
async function spacesV924EmailAccess(request,env,action='view') {
  const auth=await requireSupportConsole(request,env);
  if('response' in auth)return auth;
  if(!['creator','staff'].includes(auth.user.platform_role))return {response:spacesV84Error('Platform Staff access required.',403)};
  const founder=spacesV924IsFounder(auth.user);
  const row=founder?null:await env.DB.prepare('SELECT can_view,can_compose,can_send,can_global_updates FROM platform_email_grants_v924 WHERE user_id=?').bind(auth.user.id).first();
  const canView=founder||spacesV924True(row?.can_view);
  const canCompose=founder||(canView&&spacesV924True(row?.can_compose));
  const canSend=founder||(canCompose&&spacesV924True(row?.can_send));
  const canGlobalUpdates=founder||(canSend&&spacesV924True(row?.can_global_updates));
  const allowed={view:canView,compose:canCompose,send:canSend,global_updates:canGlobalUpdates,global_critical:founder,manage:founder};
  if(!allowed[action])return {response:spacesV84Error('Email permission required: '+action+'.',403)};
  return {...auth,founder,allowed};
}
async function spacesV924Capabilities(request,env) {
  const auth=await spacesV924EmailAccess(request,env,'view');if('response' in auth)return auth.response;
  return json({founder:auth.founder,canView:true,canCompose:auth.allowed.compose,canSend:auth.allowed.send,canGlobalUpdates:auth.allowed.global_updates,canGlobalCritical:auth.allowed.global_critical,canManage:auth.allowed.manage,externalBatchLimit:auth.founder?20:3});
}
async function spacesV924Audit(env,actor,action,target=null,campaign=null,detail='') {
  await env.DB.prepare('INSERT INTO platform_email_actions_v924(id,actor_user_id,action,target_user_id,campaign_id,detail,created_at) VALUES(?,?,?,?,?,?,?)').bind(crypto.randomUUID(),actor,action,target,campaign,spacesV924SafeText(detail,240),Date.now()).run();
}
async function spacesV924ListGrants(request,env) {
  const auth=await spacesV924EmailAccess(request,env,'manage');if('response' in auth)return auth.response;
  const rows=await env.DB.prepare("SELECT g.user_id,u.display_name,u.platform_role,g.can_view,g.can_compose,g.can_send,g.can_global_updates FROM platform_email_grants_v924 g JOIN users u ON u.id=g.user_id WHERE u.platform_role='staff' ORDER BY u.display_name LIMIT 300").all();
  return json({grants:rows.results||[]});
}
async function spacesV924SaveGrant(request,env) {
  const auth=await spacesV924EmailAccess(request,env,'manage');if('response' in auth)return auth.response;
  try {
    await enforceRateLimit(request,env,'v924-founder-permissions',30,60*60*1000,auth.user.id);
    const raw=await readJson(request);const userId=spacesV924SafeText(raw.userId,80);
    const user=await env.DB.prepare('SELECT id,platform_role,display_name FROM users WHERE id=? LIMIT 1').bind(userId).first();
    if(!user||user.platform_role!=='staff')return spacesV84Error('Choose an existing platform Staff account.',400);
    const view=raw.view===true?1:0,compose=view&&raw.compose===true?1:0,send=compose&&raw.send===true?1:0,globalUpdates=send&&raw.globalUpdates===true?1:0;
    await env.DB.prepare('INSERT INTO platform_email_grants_v924(user_id,can_view,can_compose,can_send,can_global_updates,updated_by,updated_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET can_view=excluded.can_view,can_compose=excluded.can_compose,can_send=excluded.can_send,can_global_updates=excluded.can_global_updates,updated_by=excluded.updated_by,updated_at=excluded.updated_at').bind(user.id,view,compose,send,globalUpdates,auth.user.id,Date.now()).run();
    await spacesV924Audit(env,auth.user.id,'email.permission.update',user.id,null,JSON.stringify({view,compose,send,globalUpdates}));
    return json({ok:true,userId:user.id,displayName:user.display_name});
  }catch(e){return spacesV84Error(e.message||'Could not change permissions.',400)}
}
// Personal email settings are available to any authenticated Spaces account, not just Staff.
async function spacesV924MyPreferences(request,env) {
  const auth=await requireUser(request,env);if('response' in auth)return auth.response;
  if(request.method==='GET') {
    const row=await env.DB.prepare('SELECT updates_opt_in FROM platform_email_subscriptions_v924 WHERE user_id=?').bind(auth.user.id).first();
    return json({updates:spacesV924True(row?.updates_opt_in)});
  }
  try {
    const raw=await readJson(request);if(typeof raw?.updates!=='boolean')return spacesV84Error('Choose whether to receive Spaces updates.',400);
    const now=Date.now(),token=crypto.randomUUID()+crypto.randomUUID().replace(/-/g,'');
    await env.DB.prepare('INSERT INTO platform_email_subscriptions_v924(user_id,updates_opt_in,unsubscribe_token,updated_at) VALUES(?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET updates_opt_in=excluded.updates_opt_in,updated_at=excluded.updated_at').bind(auth.user.id,raw.updates?1:0,token,now).run();
    return json({updates:raw.updates});
  }catch(e){return spacesV84Error('Could not save email preferences.',400)}
}
async function spacesV924Unsubscribe(request,env,token) {
  if(!/^[a-f0-9-]{68}$/i.test(token))return new Response('Invalid link.',{status:400});
  const row=await env.DB.prepare('SELECT user_id,updates_opt_in FROM platform_email_subscriptions_v924 WHERE unsubscribe_token=?').bind(token).first();
  if(!row)return new Response('Link not found.',{status:404});
  if(request.method==='POST')await env.DB.prepare('UPDATE platform_email_subscriptions_v924 SET updates_opt_in=0,updated_at=? WHERE user_id=?').bind(Date.now(),row.user_id).run();
  const done=request.method==='POST';
  return new Response(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Spaces email preferences</title><body style="background:#0c0d13;color:#eee;font:16px system-ui;min-height:80vh;display:grid;place-items:center"><main style="padding:30px;max-width:480px"><h1>Spaces</h1><p>${done?'You are unsubscribed from Spaces Updates.':'Unsubscribe from Spaces Updates? Security and necessary account notices may still be delivered.'}</p>${done?'':'<form method="post"><button style="padding:12px 20px;border-radius:10px">Unsubscribe</button></form>'}</main></body></html>`,{status:200,headers:{'Content-Type':'text/html;charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer'}});
}
// Counts and snapshots are calculated in D1, never submitted as arbitrary client email lists.
const spacesV924Where = cat => cat==='updates' ? "u.email_verified=1 AND u.email IS NOT NULL AND COALESCE(s.updates_opt_in,0)=1 AND COALESCE(p.opted_out,0)=0" : "u.email_verified=1 AND u.email IS NOT NULL";
function spacesV924EligibleSQL(category,countOnly=false) {
  return `SELECT ${countOnly?'COUNT(DISTINCT LOWER(u.email)) AS n':'u.id,LOWER(u.email) AS email'} FROM users u LEFT JOIN platform_email_subscriptions_v924 s ON s.user_id=u.id LEFT JOIN platform_email_preferences_v84 p ON p.user_id=u.id WHERE ${spacesV924Where(category)}`+(countOnly?'':' ORDER BY u.id');
}
async function spacesV924GlobalPreview(request,env) {
  const auth=await spacesV924EmailAccess(request,env,'global_updates');if('response' in auth)return auth.response;
  const counts=await Promise.all(['updates','service','critical'].map(async kind=>{
    if(kind!=='updates'&&!auth.founder)return {category:kind,count:null};
    const x=await env.DB.prepare(spacesV924EligibleSQL(kind,true)).first();return {category:kind,count:Number(x?.n||0)};
  }));return json({audiences:counts});
}
async function spacesV924CreateCampaign(request,env) {
  const auth=await spacesV924EmailAccess(request,env,'global_updates');if('response' in auth)return auth.response;
  if(!env.EMAIL||typeof env.EMAIL.send!=='function')return spacesV84Error('Sending unavailable.',503);
  try {
    await enforceRateLimit(request,env,'v924-campaign-create',6,60*60*1000,auth.user.id);
    const raw=await readJson(request),category=String(raw.category||'');
    if(!['updates','service','critical'].includes(category))return spacesV84Error('Invalid email category.',400);
    if(category!=='updates'&&!auth.founder)return spacesV84Error('Only Founder may send global service and critical notices.',403);
    const payload=spacesV84Payload(raw),reason=spacesV924SafeText(raw.reason,600);
    if(reason.length<15)return spacesV84Error('Provide a clear reason for this global email.',400);
    const sender=category==='critical'?'security':'hello';
    if(payload.sender!==sender)return spacesV84Error('Choose the official sender for this category.',400);
    spacesV84Sender(env,sender,auth.user);
    const sendId=spacesV924SafeText(raw.sendId,40);
    if(!/^[0-9a-f-]{36}$/i.test(sendId))return spacesV84Error('Invalid campaign confirmation ID.',400);
    const countRow=await env.DB.prepare(spacesV924EligibleSQL(category,true)).first();const count=Number(countRow?.n||0);
    if(!count)return spacesV84Error('No eligible verified accounts for this category.',409);
    if(count>20000)return spacesV84Error('Campaign exceeds the 20,000-account safety cap. Contact engineering to raise it.',409);
    if(Number(raw.confirmedCount)!==count)return spacesV84Error('Audience changed. Review the count again.',409);
    const id=crypto.randomUUID();
    const claim=await env.DB.prepare("INSERT OR IGNORE INTO platform_email_campaigns_v924(id,actor_user_id,category,sender_key,subject,heading,body,reason,send_id,status,recipient_count,created_at) VALUES(?,?,?,?,?,?,?,?,?,'queued',?,?)").bind(id,auth.user.id,category,sender,payload.subject,payload.heading,payload.body,reason,sendId,count,Date.now()).run();
    if(Number(claim.meta?.changes||0)!==1)return spacesV84Error('This campaign was already requested; check status.',409);
    // Snapshot only account IDs and verified destinations. Duplicate email addresses are ignored.
    await env.DB.prepare(`INSERT OR IGNORE INTO platform_email_campaign_recipients_v924(campaign_id,user_id,recipient_email,status) SELECT ?, u.id, LOWER(u.email),'queued' FROM users u LEFT JOIN platform_email_subscriptions_v924 s ON s.user_id=u.id LEFT JOIN platform_email_preferences_v84 p ON p.user_id=u.id WHERE ${spacesV924Where(category)} ORDER BY u.id`).bind(id).run();
    await spacesV924Audit(env,auth.user.id,'email.global.create',null,id,category+' eligible='+count);
    return json({id,status:'queued',count},201);
  }catch(e){return spacesV84Error(e.message||'Campaign could not be created.',400)}
}
async function spacesV924CampaignStatus(request,env,id) {
  const auth=await spacesV924EmailAccess(request,env,'global_updates');if('response' in auth)return auth.response;
  const campaign=await env.DB.prepare('SELECT id,actor_user_id,category,subject,status,recipient_count,created_at FROM platform_email_campaigns_v924 WHERE id=?').bind(id).first();
  if(!campaign)return spacesV84Error('Campaign not found.',404);
  if(!auth.founder&&campaign.actor_user_id!==auth.user.id)return spacesV84Error('This campaign belongs to another sender.',403);
  const result=await env.DB.prepare('SELECT status,COUNT(*) AS n FROM platform_email_campaign_recipients_v924 WHERE campaign_id=? GROUP BY status').bind(id).all();
  const totals=Object.fromEntries((result.results||[]).map(x=>[x.status,Number(x.n)]));
  return json({campaign:{id:campaign.id,category:campaign.category,subject:campaign.subject,status:campaign.status,total:campaign.recipient_count,createdAt:campaign.created_at,queued:totals.queued||0,sending:totals.sending||0,sent:totals.sent||0,failed:totals.failed||0,skipped:totals.skipped||0}});
}
async function spacesV924ListCampaigns(request,env) {
  const auth=await spacesV924EmailAccess(request,env,'global_updates');if('response' in auth)return auth.response;
  const result=auth.founder
    ? await env.DB.prepare('SELECT id,category,subject,status,recipient_count,created_at FROM platform_email_campaigns_v924 ORDER BY created_at DESC LIMIT 20').all()
    : await env.DB.prepare('SELECT id,category,subject,status,recipient_count,created_at FROM platform_email_campaigns_v924 WHERE actor_user_id=? ORDER BY created_at DESC LIMIT 20').bind(auth.user.id).all();
  return json({campaigns:(result.results||[]).map(row=>({id:row.id,category:row.category,subject:row.subject,status:row.status,total:row.recipient_count,createdAt:row.created_at}))});
}
async function spacesV924ProcessBatch(request,env,id) {
  const auth=await spacesV924EmailAccess(request,env,'global_updates');if('response' in auth)return auth.response;
  try {
    await enforceRateLimit(request,env,'v924-global-send-batch',20,60*60*1000,auth.user.id);
    const campaign=await env.DB.prepare('SELECT * FROM platform_email_campaigns_v924 WHERE id=?').bind(id).first();
    if(!campaign)return spacesV84Error('Campaign not found.',404);
    if(!auth.founder&&campaign.actor_user_id!==auth.user.id)return spacesV84Error('This campaign belongs to another sender.',403);
    if(campaign.category!=='updates'&&!auth.founder)return spacesV84Error('Only Founder may process global service and critical campaigns.',403);
    if(campaign.status==='completed')return await spacesV924CampaignStatus(request,env,id);
    const ready=await env.DB.prepare("SELECT user_id,recipient_email FROM platform_email_campaign_recipients_v924 WHERE campaign_id=? AND status='queued' ORDER BY user_id LIMIT 5").bind(id).all();
    const sender=spacesV84Sender(env,campaign.sender_key,auth.user),replyTo=validEmail(String(env.SPACES_EMAIL_REPLY_TO||''))?String(env.SPACES_EMAIL_REPLY_TO):'support@yourspaces.net';
    for(const row of ready.results||[]) {
      const claim=await env.DB.prepare("UPDATE platform_email_campaign_recipients_v924 SET status='sending' WHERE campaign_id=? AND user_id=? AND status='queued'").bind(id,row.user_id).run();
      if(Number(claim.meta?.changes||0)!==1)continue;
      // Recheck current verification and consent immediately before sending.
      const stillEligible=await env.DB.prepare(`SELECT u.email FROM users u LEFT JOIN platform_email_subscriptions_v924 s ON s.user_id=u.id LEFT JOIN platform_email_preferences_v84 p ON p.user_id=u.id WHERE u.id=? AND LOWER(u.email)=? AND ${spacesV924Where(campaign.category)}`).bind(row.user_id,row.recipient_email).first();
      if(!stillEligible||!validEmail(row.recipient_email)) {await env.DB.prepare("UPDATE platform_email_campaign_recipients_v924 SET status='skipped',completed_at=? WHERE campaign_id=? AND user_id=?").bind(Date.now(),id,row.user_id).run();continue;}
      try {
        const unsub=campaign.category==='updates' ? await spacesV924EnsureUnsub(env,row.user_id) : null;
        const footer=unsub?'\n\nUnsubscribe from Spaces Updates: https://spaces.spagotei.workers.dev/v1/email/v924/unsubscribe/'+unsub:'';
        const html=spacesV84Html(campaign.heading,campaign.subject,campaign.body,'',replyTo).replace('</body>',(unsub?`<div style="text-align:center;padding:16px"><a href="https://spaces.spagotei.workers.dev/v1/email/v924/unsubscribe/${unsub}">Unsubscribe from Updates</a></div>`:'')+'</body>');
        const result=await env.EMAIL.send({to:row.recipient_email,from:sender,replyTo,subject:campaign.subject,text:(campaign.heading||campaign.subject)+'\n\n'+campaign.body+'\n\nSpaces'+footer,html});
        await env.DB.prepare("UPDATE platform_email_campaign_recipients_v924 SET status='sent',provider_message_id=?,completed_at=? WHERE campaign_id=? AND user_id=?").bind(String(result?.messageId||''),Date.now(),id,row.user_id).run();
      }catch(error){console.error('Spaces campaign send error',error?.code||'SEND_FAILED');await env.DB.prepare("UPDATE platform_email_campaign_recipients_v924 SET status='failed',error_code=?,completed_at=? WHERE campaign_id=? AND user_id=?").bind(spacesV84Plain(error?.code||'EMAIL_PROVIDER_ERROR',80),Date.now(),id,row.user_id).run();}
    }
    const pending=await env.DB.prepare("SELECT COUNT(*) AS n FROM platform_email_campaign_recipients_v924 WHERE campaign_id=? AND status='queued'").bind(id).first();
    if(!Number(pending?.n||0))await env.DB.prepare("UPDATE platform_email_campaigns_v924 SET status='completed',completed_at=?,body='' WHERE id=?").bind(Date.now(),id).run();
    else await env.DB.prepare("UPDATE platform_email_campaigns_v924 SET status='running' WHERE id=?").bind(id).run();
    return spacesV924CampaignStatus(request,env,id);
  }catch(e){return spacesV84Error(e.message||'Batch could not be processed.',400)}
}
async function spacesV924EnsureUnsub(env,userId) {
  const current=await env.DB.prepare('SELECT unsubscribe_token FROM platform_email_subscriptions_v924 WHERE user_id=?').bind(userId).first();
  if(current?.unsubscribe_token)return current.unsubscribe_token;
  const token=crypto.randomUUID()+crypto.randomUUID().replace(/-/g,'');
  await env.DB.prepare('INSERT OR IGNORE INTO platform_email_subscriptions_v924(user_id,updates_opt_in,unsubscribe_token,updated_at) VALUES(?,?,?,?)').bind(userId,0,token,Date.now()).run();
  const stored=await env.DB.prepare('SELECT unsubscribe_token FROM platform_email_subscriptions_v924 WHERE user_id=?').bind(userId).first();
  return stored?.unsubscribe_token||token;
}


export default {
    async email(message, env) { return receiveStaffEmail(message, env); },
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
            // V90 authenticated recognition workflow (no public application endpoint).
            if (url.pathname.includes('/program-applications') || url.pathname.includes('/program-badges')) {
              const replyV90 = await handleSpacesProgramsV90(request,env,url,{requireWorkspaceMembership,requireSupportConsole,supportPermissionsForUserV48,fail,json,readJson,enforceRateLimit});
              if (replyV90) return replyV90;
            }
            // SPACES_V81_2_ROUTES_START
            if (url.pathname === '/v1/voice/v85/events' && request.method === 'GET') return await getDmCallEventsV85(request,env,{requireUser,directConversationForUser,json,fail});
            if (url.pathname === '/v1/voice/v81/ice' && request.method === 'GET') return await spacesV812VoiceIce(request,env);
            if (url.pathname === '/v1/voice/v81/inbox' && request.method === 'GET') return await spacesV812VoiceInbox(request,env);
            if (url.pathname === '/v1/voice/v81/calls' && request.method === 'POST') return await spacesV812VoiceCreate(request,env);
            const spacesV812SignalRoute = url.pathname.match(/^\/v1\/voice\/v81\/calls\/([^/]+)\/signals$/u);
            if (spacesV812SignalRoute && ['GET','POST'].includes(request.method)) return await spacesV812VoiceCall(request,env,decodeURIComponent(spacesV812SignalRoute[1]),request.method==='GET'?'read':'send');
            // SPACES_V81_2_ROUTES_END
            // SPACES_V80_3_ROUTES_START
            if (url.pathname === '/v1/spaces/trust' && request.method === 'GET') return await spacesV803PartnerPublic(request,env);
            const spacesV803TrustRoute = url.pathname.match(/^\/v1\/spaces\/([^/]+)\/trust$/u);
            if (spacesV803TrustRoute && request.method === 'GET') return await spacesV803PartnerPublic(request,env,decodeURIComponent(spacesV803TrustRoute[1]));
            if (url.pathname === '/v1/partners/applications' && ['GET','POST'].includes(request.method)) return await spacesV803PartnerApplications(request,env);
            if (url.pathname === '/v1/support/partners' && ['GET','POST'].includes(request.method)) return await spacesV803PartnerStaff(request,env);
            if (url.pathname === '/v1/support/email/capabilities' && request.method === 'GET') return await spacesV803EmailCapabilities(request,env);
            if (url.pathname === '/v1/support/email' && request.method === 'POST') return await spacesV803EmailSend(request,env);
            if (url.pathname === '/v1/support/v80/my-archives' && request.method === 'GET') return await spacesV803MemberArchives(request,env);
            if (url.pathname === '/v1/support/v80/archive-health' && request.method === 'GET') return await spacesV803ArchiveHealth(request,env);
            const spacesV803ArchiveRoute = url.pathname.match(/^\/v1\/support\/v80\/cases\/([^/]+)\/archive$/u);
            if (spacesV803ArchiveRoute && request.method === 'PATCH') return await spacesV803MemberArchives(request,env,decodeURIComponent(spacesV803ArchiveRoute[1]));
            // SPACES_V80_3_ROUTES_END
            if (request.method === 'GET' &&
                (url.pathname === '/' ||
                    url.pathname === '/health')) {
                return health(env);
            }


            // SPACES_V83_BROADCAST_ROUTES: unchanged legacy API routes below.
            if (url.pathname === '/v1/broadcasts/active' && request.method === 'GET') return broadcastV83ListActive(request, env);
            const broadcastDismissV83 = url.pathname.match(/^\/v1\/broadcasts\/([^/]+)\/dismiss$/u);
            if (broadcastDismissV83 && request.method === 'POST') return broadcastV83Dismiss(request,env,broadcastDismissV83[1]);
            if (url.pathname === '/v1/staff/broadcasts' && request.method === 'GET') return broadcastV83ListStaff(request,env);
            if (url.pathname === '/v1/staff/broadcasts' && request.method === 'POST') return broadcastV83Publish(request,env);
            if (url.pathname === '/v1/staff/broadcasts/image' && request.method === 'POST') return broadcastV83UploadImage(request,env);
            const broadcastUnpublishV83 = url.pathname.match(/^\/v1\/staff\/broadcasts\/([^/]+)\/unpublish$/u);
            if (broadcastUnpublishV83 && request.method === 'POST') return broadcastV83Unpublish(request,env,broadcastUnpublishV83[1]);
            const broadcastImageV83 = url.pathname.match(/^\/v1\/broadcast-images\/([^/]+)$/u);
            if (broadcastImageV83 && (request.method === 'GET' || request.method === 'HEAD')) return broadcastV83GetImage(env,broadcastImageV83[1],request.method);

            // SPACES_V84_EMAIL_ROUTES
            if (url.pathname === '/v1/staff/email/capabilities' && request.method === 'GET') return spacesV84Capabilities(request,env);
            if (url.pathname === '/v1/staff/email/preview' && request.method === 'POST') return spacesV84Preview(request,env);
            if (url.pathname === '/v1/staff/email/audience-preview' && request.method === 'POST') return spacesV84AudiencePreview(request,env);
            if (url.pathname === '/v1/staff/email/v913/external-check' && request.method === 'POST') return spacesV913ExternalCheck(request,env);
if (url.pathname === '/v1/staff/email/v913/external-send' && request.method === 'POST') return spacesV913ExternalSend(request,env);
if (url.pathname === '/v1/staff/email/v913/resolve-ticket' && request.method === 'POST') return spacesV913ResolveTicket(request,env);
if (url.pathname === '/v1/staff/email/v913/history' && request.method === 'GET') return spacesV913History(request,env);
if (url.pathname === '/v1/staff/email/v924/capabilities' && request.method === 'GET') return spacesV924Capabilities(request,env);
            if (url.pathname === '/v1/staff/email/v924/grants' && request.method === 'GET') return spacesV924ListGrants(request,env);
            if (url.pathname === '/v1/staff/email/v924/grants' && request.method === 'PUT') return spacesV924SaveGrant(request,env);
            if (url.pathname === '/v1/email/v924/preferences' && ['GET','PATCH'].includes(request.method)) return spacesV924MyPreferences(request,env);
            const spacesV924UnsubMatch=url.pathname.match(/^\/v1\/email\/v924\/unsubscribe\/([^/]+)$/u);
            if (spacesV924UnsubMatch && ['GET','POST'].includes(request.method)) return spacesV924Unsubscribe(request,env,spacesV924UnsubMatch[1]);
            if (url.pathname === '/v1/staff/email/v924/global-preview' && request.method === 'GET') return spacesV924GlobalPreview(request,env);
            if (url.pathname === '/v1/staff/email/v924/campaigns' && request.method === 'POST') return spacesV924CreateCampaign(request,env);
            if (url.pathname === '/v1/staff/email/v924/campaigns' && request.method === 'GET') return spacesV924ListCampaigns(request,env);
            const spacesV924CampaignMatch=url.pathname.match(/^\/v1\/staff\/email\/v924\/campaigns\/([a-f0-9-]{36})(\/process)?$/iu);
            if (spacesV924CampaignMatch && request.method === 'GET' && !spacesV924CampaignMatch[2]) return spacesV924CampaignStatus(request,env,spacesV924CampaignMatch[1]);
            if (spacesV924CampaignMatch && request.method === 'POST' && spacesV924CampaignMatch[2]) return spacesV924ProcessBatch(request,env,spacesV924CampaignMatch[1]);
            if (url.pathname === '/v1/staff/email/send' && request.method === 'POST') return spacesV84Send(request,env);
            if (url.pathname === '/v1/staff/email/history' && request.method === 'GET') return spacesV84History(request,env);
            if (url.pathname === '/v1/staff/email/banners' && request.method === 'GET') return spacesV84ListBanners(request,env);
            if (url.pathname === '/v1/staff/email/banners' && request.method === 'POST') return spacesV84UploadBanner(request,env);
            const spacesV84PublicImage = url.pathname.match(/^\/v1\/mail-images\/([^/]+)$/u);
            if(spacesV84PublicImage && ['GET','HEAD'].includes(request.method)) return spacesV84GetBanner(env,spacesV84PublicImage[1],request.method);
            const spacesV84Optout = url.pathname.match(/^\/v1\/email\/unsubscribe\/([^/]+)$/u);
            if(spacesV84Optout && ['GET','POST'].includes(request.method)) return spacesV84Unsubscribe(request,env,spacesV84Optout[1]);
            // SPACES_V84_3_INBOX_ROUTES: the new gate owns every Center request, including legacy paths.
            if (url.pathname.startsWith('/v1/staff/center/')) {
              const response = await staffCenterV843(request,env);
              if (response.status === 401 || response.status === 403) await recordStaffDeniedV85(env,request,response.status);
              return response;
            }
            // SPACES_V84_2_STAFF_CENTER_ROUTES
            if (url.pathname === '/v1/staff/center/sent' && request.method === 'GET') return spacesV842CenterSent(request,env);
            if (url.pathname === '/v1/staff/center/accounts' && request.method === 'GET') return spacesV842CenterAccounts(request,env);
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
            if (request.method === 'GET' && url.pathname === '/v1/auth/beta/status') {
                return betaClaimStatus(request, env);
            }
            if (request.method === 'POST' && url.pathname === '/v1/auth/beta/start') {
                return startBetaClaim(request, env);
            }
            if (request.method === 'POST' && url.pathname === '/v1/auth/beta/verify') {
                return verifyBetaClaim(request, env);
            }
            if (request.method === 'POST' && url.pathname === '/v1/auth/beta/claim') {
                return claimBetaAccount(request, env);
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
            if (request.method === 'POST' &&
                url.pathname ===
                    '/v1/account/complete-beta-profile') {
                return completeBetaProfile(request, env);
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

            if (request.method === 'PATCH' && url.pathname === '/v1/account/presence') {
                return updateMyPresence(request, env);
            }
            if (request.method === 'GET' && url.pathname === '/v1/account/blocks') {
                return listBlockedUsers(request, env);
            }
            const accountBlockRoute = url.pathname.match(/^\/v1\/account\/blocks\/([^/]+)$/u);
            if (accountBlockRoute && request.method === 'PUT') {
                return blockAccountUser(request, env, decodeURIComponent(accountBlockRoute[1] ?? ''));
            }
            if (accountBlockRoute && request.method === 'DELETE') {
                return unblockAccountUser(request, env, decodeURIComponent(accountBlockRoute[1] ?? ''));
            }

            const directGroupInviteRouteV67 = url.pathname.match(/^\/v1\/direct\/groups\/([^/]+)\/members$/u);
            if (request.method === 'POST' && directGroupInviteRouteV67) {
                return addDirectGroupMemberV67(
                    request,
                    env,
                    decodeURIComponent(directGroupInviteRouteV67[1] ?? ''),
                );
            }

            if (request.method === 'GET' && url.pathname === '/v1/direct/center') {
                return getDirectCenter(request, env);
            }
            const directPreferenceRoute = url.pathname.match(/^\/v1\/direct\/preferences\/(dm|group|support)\/([^/]+)$/u);
            if (request.method === 'PATCH' && directPreferenceRoute) {
                return updateDirectThreadPreference(
                    request,
                    env,
                    decodeURIComponent(directPreferenceRoute[1] ?? ''),
                    decodeURIComponent(directPreferenceRoute[2] ?? ''),
                );
            }
            const directPinsListRoute = url.pathname.match(/^\/v1\/direct\/pins\/(dm|group)\/([^/]+)$/u);
            if (request.method === 'GET' && directPinsListRoute) {
                return listDirectPinnedMessages(
                    request,
                    env,
                    decodeURIComponent(directPinsListRoute[1] ?? ''),
                    decodeURIComponent(directPinsListRoute[2] ?? ''),
                );
            }
            const directPinItemRoute = url.pathname.match(/^\/v1\/direct\/pins\/(dm|group)\/([^/]+)\/([^/]+)$/u);
            if ((request.method === 'PUT' || request.method === 'DELETE') && directPinItemRoute) {
                return updateDirectPinnedMessage(
                    request,
                    env,
                    decodeURIComponent(directPinItemRoute[1] ?? ''),
                    decodeURIComponent(directPinItemRoute[2] ?? ''),
                    decodeURIComponent(directPinItemRoute[3] ?? ''),
                    request.method === 'PUT',
                );
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

            if (request.method === 'PUT' &&
                url.pathname === '/v1/notifications/read') {
                return markNotificationReadV72(request, env);
            }
            const typingRouteV72 = url.pathname.match(/^\/v1\/typing\/(channel|dm|group|support)\/([^/]+)$/u);
            if (typingRouteV72 && ['GET', 'PUT', 'DELETE'].includes(request.method)) {
                return typingPresenceV72(
                    request,
                    env,
                    decodeURIComponent(typingRouteV72[1] ?? ''),
                    decodeURIComponent(typingRouteV72[2] ?? ''),
                );
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

            // SPACES_V89_NOTE_FOLDERS_ROUTES: auth and permissions on every request.
            const noteFolderRouteV89=url.pathname.match(/^\/v1\/workspaces\/([^/]+)\/notes-folders(?:\/([^/]+))?$/u);
            if(noteFolderRouteV89 && ['GET','POST','PUT','PATCH','DELETE'].includes(request.method)){
              return routeNotesFoldersV89(request,env,decodeURIComponent(noteFolderRouteV89[1]??''),decodeURIComponent(noteFolderRouteV89[2]??''),{requireWorkspaceMembership,fail,json,readJson,channelPermissionRows,channelPermissionAllowed,roleMeetsPermission,normalizeChannelPermission,accessHas,enforceRateLimit});
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

            // Spaces V77 Support Operations routes
            if (url.pathname === '/v1/support/v77/my-cases' && request.method === 'GET') return listMySupportCasesV77(request, env);
            if (url.pathname === '/v1/support/v77/cases') {
                if (request.method === 'GET') return listSupportCasesV77(request, env);
                if (request.method === 'POST') return createSupportCaseV77(request, env);
            }
            const supportV77CaseEventsRoute = url.pathname.match(/^\/v1\/support\/v77\/cases\/([^/]+)\/events$/u);
            if (supportV77CaseEventsRoute && request.method === 'POST') return addSupportCaseEventV77(request, env, decodeURIComponent(supportV77CaseEventsRoute[1] ?? ''));
            const supportV77CaseRoute = url.pathname.match(/^\/v1\/support\/v77\/cases\/([^/]+)$/u);
            if (supportV77CaseRoute) {
                const caseIdV77 = decodeURIComponent(supportV77CaseRoute[1] ?? '');
                if (request.method === 'GET') return getSupportCaseV77(request, env, caseIdV77);
                if (request.method === 'PATCH') return updateSupportCaseV77(request, env, caseIdV77);
                if (request.method === 'DELETE') return deleteSupportCaseV77(request, env, caseIdV77);
            }
            const supportV77ProfileRoute = url.pathname.match(/^\/v1\/support\/v77\/profiles\/([^/]+)$/u);
            if (supportV77ProfileRoute && request.method === 'GET') return supportProfileV77(request, env, decodeURIComponent(supportV77ProfileRoute[1] ?? ''));
            if (url.pathname === '/v1/support/v77/notices' && request.method === 'POST') return sendSupportNoticeV77(request, env);
            if (url.pathname === '/v1/support/v77/restrictions') {
                if (request.method === 'GET') return listSupportRestrictionsV77(request, env);
                if (request.method === 'POST') return createSupportRestrictionV77(request, env);
            }
            const supportV77RestrictionRoute = url.pathname.match(/^\/v1\/support\/v77\/restrictions\/([^/]+)$/u);
            if (supportV77RestrictionRoute && request.method === 'DELETE') return revokeSupportRestrictionV77(request, env, decodeURIComponent(supportV77RestrictionRoute[1] ?? ''));
            if (url.pathname === '/v1/support/v77/audit' && request.method === 'GET') return listSupportAuditV77(request, env);

            if (url.pathname === '/v1/support/me' && request.method === 'GET') {
                return supportMeV48(request, env);
            }
            if (url.pathname === '/v1/support/team' && request.method === 'GET') {
                return listSupportTeamV48(request, env);
            }
            const supportTeamPermissionsRoute = url.pathname.match(/^\/v1\/support\/team\/([^/]+)\/permissions$/u);
            if (request.method === 'PATCH' && supportTeamPermissionsRoute) {
                return updateSupportTeamPermissionsV48(request, env, decodeURIComponent(supportTeamPermissionsRoute[1] ?? ''));
            }
            const supportTeamPublicIdRoute = url.pathname.match(/^\/v1\/support\/team\/([^/]+)\/public-id$/u);
            if (request.method === 'PATCH' && supportTeamPublicIdRoute) {
                return updateSupportPublicIdV48(request, env, decodeURIComponent(supportTeamPublicIdRoute[1] ?? ''));
            }
            const supportTeamRouteV48 = url.pathname.match(/^\/v1\/support\/team\/([^/]+)$/u);
            if (request.method === 'PATCH' && supportTeamRouteV48) {
                return updateSupportTeamMemberV48(request, env, decodeURIComponent(supportTeamRouteV48[1] ?? ''));
            }
            const supportUserInspectorRouteV48 = url.pathname.match(/^\/v1\/support\/users\/([^/]+)$/u);
            if (request.method === 'GET' && supportUserInspectorRouteV48) {
                return supportAccountInspectorV48(request, env, decodeURIComponent(supportUserInspectorRouteV48[1] ?? ''));
            }
            const supportUserRestrictionRouteV48 = url.pathname.match(/^\/v1\/support\/users\/([^/]+)\/restrictions$/u);
            if (request.method === 'POST' && supportUserRestrictionRouteV48) {
                return applySupportRestrictionV48(request, env, decodeURIComponent(supportUserRestrictionRouteV48[1] ?? ''));
            }
            if (url.pathname === '/v1/support/restrictions' && request.method === 'GET') {
                return listSupportRestrictionsV48(request, env);
            }
            const supportRestrictionRouteV48 = url.pathname.match(/^\/v1\/support\/restrictions\/(ban|restriction|space)\/([^/]+)$/u);
            if (request.method === 'DELETE' && supportRestrictionRouteV48) {
                return revokeSupportRestrictionV48(
                    request,
                    env,
                    supportRestrictionRouteV48[1],
                    decodeURIComponent(supportRestrictionRouteV48[2] ?? ''),
                );
            }

            const supportPlayerArchiveRouteV53 = url.pathname.match(/^\/v1\/support\/player-reports\/([^/]+)\/archive$/u);
            if (request.method === 'PATCH' && supportPlayerArchiveRouteV53) {
                return archivePlayerReportV53(request, env, decodeURIComponent(supportPlayerArchiveRouteV53[1] ?? ''));
            }
            const supportPlayerRouteV53 = url.pathname.match(/^\/v1\/support\/player-reports\/([^/]+)$/u);
            if (request.method === 'DELETE' && supportPlayerRouteV53) {
                return deletePlayerReportV53(request, env, decodeURIComponent(supportPlayerRouteV53[1] ?? ''));
            }
            if (url.pathname === '/v1/support/cases') {
                if (request.method === 'GET') return listSupportCases(request, env);
                if (request.method === 'POST') return createSupportCase(request, env);
            }
            const supportCaseArchiveRouteV53 = url.pathname.match(/^\/v1\/support\/cases\/([^/]+)\/archive$/u);
            if (request.method === 'PATCH' && supportCaseArchiveRouteV53) {
                return archiveSupportCaseV53(request, env, decodeURIComponent(supportCaseArchiveRouteV53[1] ?? ''));
            }
            const supportCaseRoute = url.pathname.match(/^\/v1\/support\/cases\/([^/]+)$/u);
            if (request.method === 'PATCH' && supportCaseRoute) {
                return updateSupportCase(request, env, decodeURIComponent(supportCaseRoute[1] ?? ''));
            }
            if (request.method === 'DELETE' && supportCaseRoute) {
                return deleteSupportCaseV53(request, env, decodeURIComponent(supportCaseRoute[1] ?? ''));
            }
            if (url.pathname === '/v1/support/beta-access') {
                if (request.method === 'GET') return await listBetaAccess(request, env);
                if (request.method === 'POST') return await inviteBetaAccess(request, env);
            }
            const betaAccessRoute =
                url.pathname.match(/^\/v1\/support\/beta-access\/([^/]+)$/u);
            if (request.method === 'DELETE' && betaAccessRoute) {
                return await revokeBetaAccess(
                    request,
                    env,
                    decodeURIComponent(betaAccessRoute[1] ?? ''),
                );
            }


            if (url.pathname === '/v1/support/tickets') {
                if (request.method === 'GET') return listSupportTicketsV73(request, env);
                if (request.method === 'POST') return createSupportTicketV73(request, env);
            }

            const supportTicketCollaboratorMemberRouteV73 =
                url.pathname.match(/^\/v1\/support\/tickets\/([^/]+)\/collaborators\/([^/]+)$/u);
            if (request.method === 'DELETE' && supportTicketCollaboratorMemberRouteV73) {
                return removeSupportTicketCollaboratorV73(
                    request,
                    env,
                    decodeURIComponent(supportTicketCollaboratorMemberRouteV73[1] ?? ''),
                    decodeURIComponent(supportTicketCollaboratorMemberRouteV73[2] ?? ''),
                );
            }

            const supportTicketCollaboratorsRouteV73 =
                url.pathname.match(/^\/v1\/support\/tickets\/([^/]+)\/collaborators$/u);
            if (request.method === 'POST' && supportTicketCollaboratorsRouteV73) {
                return addSupportTicketCollaboratorV73(
                    request,
                    env,
                    decodeURIComponent(supportTicketCollaboratorsRouteV73[1] ?? ''),
                );
            }

            const supportTicketMessagesRouteV73 =
                url.pathname.match(/^\/v1\/support\/tickets\/([^/]+)\/messages$/u);
            if (request.method === 'POST' && supportTicketMessagesRouteV73) {
                return sendSupportTicketMessageV73(
                    request,
                    env,
                    decodeURIComponent(supportTicketMessagesRouteV73[1] ?? ''),
                );
            }

            const supportTicketReopenRouteV73 =
                url.pathname.match(/^\/v1\/support\/tickets\/([^/]+)\/reopen$/u);
            if (request.method === 'POST' && supportTicketReopenRouteV73) {
                return reopenSupportTicketV73(
                    request,
                    env,
                    decodeURIComponent(supportTicketReopenRouteV73[1] ?? ''),
                );
            }

            const supportTicketRouteV73 =
                url.pathname.match(/^\/v1\/support\/tickets\/([^/]+)$/u);
            if (supportTicketRouteV73) {
                const ticketNumber = decodeURIComponent(supportTicketRouteV73[1] ?? '');
                if (request.method === 'GET') return getSupportTicketV73(request, env, ticketNumber);
                if (request.method === 'PATCH') return updateSupportTicketV73(request, env, ticketNumber);
                if (request.method === 'DELETE') return deleteSupportTicketTranscriptV73(request, env, ticketNumber);
            }

            if (url.pathname === '/v1/support/inbox' && request.method === 'GET') {
                return listSupportInboxV53(request, env);
            }
            if (url.pathname === '/v1/support/reply' && request.method === 'POST') {
                return sendSupportReplyV53(request, env);
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
