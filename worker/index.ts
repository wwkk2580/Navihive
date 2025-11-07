import {
    NavigationAPI,
    type LoginRequest,
    type ExportData,
    type Group,
    type Site,
} from "../src/API/http";

/**
 * 生成唯一错误 ID
 */
function generateErrorId(): string {
    return crypto.randomUUID();
}

/**
 * 结构化日志
 */
interface LogData {
    timestamp: string;
    level: 'info' | 'warn' | 'error';
    message: string;
    errorId?: string;
    path?: string;
    method?: string;
    details?: unknown;
}

function log(data: LogData): void {
    console.log(JSON.stringify({
        ...data,
        timestamp: data.timestamp || new Date().toISOString(),
    }));
}

/**
 * 创建错误响应
 */
function createErrorResponse(
    error: unknown,
    request: Request,
    context?: string
): Response {
    const errorId = generateErrorId();
    const url = new URL(request.url);

    // 记录详细错误日志
    log({
        timestamp: new Date().toISOString(),
        level: 'error',
        message: error instanceof Error ? error.message : '未知错误',
        errorId,
        path: url.pathname,
        method: request.method,
        details: error instanceof Error ? {
            name: error.name,
            stack: error.stack,
        } : error,
    });

    // 返回用户友好的错误信息
    return createJsonResponse(
        {
            success: false,
            message: context ? `${context}失败` : '处理请求时发生错误',
            errorId,
        },
        request,
        { status: 500 }
    );
}

// 请求体大小限制配置
const MAX_BODY_SIZE = 1024 * 1024; // 1MB

/**
 * 验证请求体大小并解析 JSON
 */
async function validateRequestBody(request: Request): Promise<unknown> {
    const contentLength = request.headers.get('Content-Length');

    // 检查 Content-Length 头
    if (contentLength && parseInt(contentLength, 10) > MAX_BODY_SIZE) {
        throw new Error('请求体过大，最大允许 1MB');
    }

    // 读取并验证实际大小
    const bodyText = await request.text();

    if (bodyText.length > MAX_BODY_SIZE) {
        throw new Error('请求体过大，最大允许 1MB');
    }

    try {
        return JSON.parse(bodyText);
    } catch {
        throw new Error('无效的 JSON 格式');
    }
}

/**
 * 深度验证导出数据
 */
function validateExportData(data: unknown): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (!data || typeof data !== 'object') {
        errors.push('数据必须是对象');
        return { valid: false, errors };
    }

    const d = data as Record<string, unknown>;

    // 验证 version
    if (!d.version || typeof d.version !== 'string') {
        errors.push('缺少或无效的版本信息');
    }

    // 验证 exportDate
    if (!d.exportDate || typeof d.exportDate !== 'string') {
        errors.push('缺少或无效的导出日期');
    }

    // 验证 groups
    if (!Array.isArray(d.groups)) {
        errors.push('groups 必须是数组');
    } else {
        d.groups.forEach((group: unknown, index: number) => {
            if (!group || typeof group !== 'object') {
                errors.push(`groups[${index}]: 必须是对象`);
                return;
            }
            const g = group as Record<string, unknown>;
            if (!g.name || typeof g.name !== 'string') {
                errors.push(`groups[${index}]: name 必须是字符串`);
            }
            if (typeof g.order_num !== 'number') {
                errors.push(`groups[${index}]: order_num 必须是数字`);
            }
        });
    }

    // 验证 sites
    if (!Array.isArray(d.sites)) {
        errors.push('sites 必须是数组');
    } else {
        d.sites.forEach((site: unknown, index: number) => {
            if (!site || typeof site !== 'object') {
                errors.push(`sites[${index}]: 必须是对象`);
                return;
            }
            const s = site as Record<string, unknown>;
            if (!s.name || typeof s.name !== 'string') {
                errors.push(`sites[${index}]: name 必须是字符串`);
            }
            if (!s.url || typeof s.url !== 'string') {
                errors.push(`sites[${index}]: url 必须是字符串`);
            } else {
                try {
                    new URL(s.url);
                } catch {
                    errors.push(`sites[${index}]: url 格式无效`);
                }
            }
            if (typeof s.group_id !== 'number') {
                errors.push(`sites[${index}]: group_id 必须是数字`);
            }
            if (typeof s.order_num !== 'number') {
                errors.push(`sites[${index}]: order_num 必须是数字`);
            }
        });
    }

    // 验证 configs
    if (!d.configs || typeof d.configs !== 'object') {
        errors.push('configs 必须是对象');
    }

    return { valid: errors.length === 0, errors };
}

// CORS 配置
const ALLOWED_ORIGINS = [
    'http://localhost:5173',
    'http://localhost:8788',
    // 生产环境会自动允许同源
];

/**
 * 获取 CORS 头
 */
function getCorsHeaders(request: Request): Record<string, string> {
    const origin = request.headers.get('Origin');
    const requestUrl = new URL(request.url);

    // 如果是同源请求，允许
    let allowedOrigin: string | null = origin;

    if (origin) {
        // 检查是否在允许列表中，或者是 workers.dev 子域名
        const isAllowed = ALLOWED_ORIGINS.includes(origin) ||
            origin.endsWith('.workers.dev') ||
            origin === requestUrl.origin; // 同源

        allowedOrigin = isAllowed ? origin : (ALLOWED_ORIGINS[0] || null);
    }

    return {
        'Access-Control-Allow-Origin': allowedOrigin || '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        'Access-Control-Allow-Credentials': 'true',
        'Access-Control-Max-Age': '86400',
    };
}

/**
 * 创建带 CORS 头的 JSON 响应
 */
function createJsonResponse(
    data: unknown,
    request: Request,
    options: ResponseInit = {}
): Response {
    const corsHeaders = getCorsHeaders(request);

    return Response.json(data, {
        ...options,
        headers: {
            ...corsHeaders,
            ...(options.headers as Record<string, string>),
        },
    });
}

/**
 * 创建带 CORS 头的普通响应
 */
function createResponse(
    body: string | null,
    request: Request,
    options: ResponseInit = {}
): Response {
    const corsHeaders = getCorsHeaders(request);

    return new Response(body, {
        ...options,
        headers: {
            ...corsHeaders,
            ...(options.headers as Record<string, string>),
        },
    });
}

export default {
    async fetch(request: Request, env: Env) {
        const url = new URL(request.url);

        // 处理 CORS 预检请求
        if (request.method === 'OPTIONS') {
            return new Response(null, {
                status: 204,
                headers: getCorsHeaders(request),
            });
        }

        // API路由处理
        if (url.pathname.startsWith("/api/")) {
            const path = url.pathname.replace("/api/", "");
            const method = request.method;

            try {
                const api = new NavigationAPI(env);

                // 登录路由 - 不需要验证
                if (path === "login" && method === "POST") {
                    try {
                        const loginData = (await validateRequestBody(request)) as LoginInput;

                        // 验证登录数据
                        const validation = validateLogin(loginData);
                        if (!validation.valid) {
                            return createJsonResponse(
                                {
                                    success: false,
                                    message: `验证失败: ${validation.errors?.join(", ")}`,
                                },
                                request,
                                { status: 400 }
                            );
                        }

                    const result = await api.login(loginData as LoginRequest);

                    // 如果登录成功，设置 HttpOnly Cookie
                    if (result.success && result.token) {
                        const maxAge = loginData.rememberMe ? 30 * 24 * 60 * 60 : 7 * 24 * 60 * 60;

                        return createJsonResponse(
                            { success: true, message: result.message },
                            request,
                            {
                                headers: {
                                    'Set-Cookie': [
                                        `auth_token=${result.token}`,
                                        'HttpOnly',
                                        'Secure',
                                        'SameSite=Strict',
                                        `Max-Age=${maxAge}`,
                                        'Path=/',
                                    ].join('; '),
                                },
                            }
                        );
                    }

                    return createJsonResponse(result, request);
                    } catch (error) {
                        return createJsonResponse(
                            {
                                success: false,
                                message: error instanceof Error ? error.message : '请求无效',
                            },
                            request,
                            { status: 400 }
                        );
                    }
                }

                // 登出路由
                if (path === "logout" && method === "POST") {
                    return createJsonResponse(
                        { success: true, message: '登出成功' },
                        request,
                        {
                            headers: {
                                'Set-Cookie': [
                                    'auth_token=',
                                    'HttpOnly',
                                    'Secure',
                                    'SameSite=Strict',
                                    'Max-Age=0',
                                    'Path=/',
                                ].join('; '),
                            },
                        }
                    );
                }

                // 初始化数据库接口 - 不需要验证
                if (path === "init" && method === "GET") {
                    const initResult = await api.initDB();
                    if (initResult.alreadyInitialized) {
                        return createResponse("数据库已经初始化过，无需重复初始化", request, { status: 200 });
                    }
                    return createResponse("数据库初始化成功", request, { status: 200 });
                }

                // 验证中间件 - 除登录接口、登出接口和初始化接口外，所有请求都需要验证
                if (api.isAuthEnabled()) {
                    // 优先从 Cookie 中读取 token
                    const cookieHeader = request.headers.get("Cookie");
                    let token: string | null = null;

                    if (cookieHeader) {
                        const cookies = cookieHeader.split(';').reduce((acc, cookie) => {
                            const [key, value] = cookie.trim().split('=');
                            if (key) {
                                acc[key] = value || '';
                            }
                            return acc;
                        }, {} as Record<string, string>);

                        token = cookies['auth_token'] || null;
                    }

                    // 如果 Cookie 中没有，尝试从 Authorization 头读取（向后兼容）
                    if (!token) {
                        const authHeader = request.headers.get("Authorization");
                        if (authHeader) {
                            const [authType, headerToken] = authHeader.split(" ");
                            if (authType === "Bearer" && headerToken) {
                                token = headerToken;
                            }
                        }
                    }

                    // 如果没有 token，返回401错误
                    if (!token) {
                        return createResponse("请先登录", request, {
                            status: 401,
                            headers: {
                                "WWW-Authenticate": "Bearer",
                            },
                        });
                    }

                    // 验证Token有效性
                    const verifyResult = await api.verifyToken(token);
                    if (!verifyResult.valid) {
                        return createResponse("认证已过期或无效，请重新登录", request, { status: 401 });
                    }
                }

                // 路由匹配
                if (path === "groups" && method === "GET") {
                    const groups = await api.getGroups();
                    return createJsonResponse(groups, request);
                } else if (path.startsWith("groups/") && method === "GET") {
                    const idStr = path.split("/")[1];
                    if (!idStr) {
                        return createJsonResponse({ error: "无效的ID" }, request, { status: 400 });
                    }
                    const id = parseInt(idStr);
                    if (isNaN(id)) {
                        return createJsonResponse({ error: "无效的ID" }, request, { status: 400 });
                    }
                    const group = await api.getGroup(id);
                    return createJsonResponse(group, request);
                } else if (path === "groups" && method === "POST") {
                    const data = (await validateRequestBody(request)) as GroupInput;

                    // 验证分组数据
                    const validation = validateGroup(data);
                    if (!validation.valid) {
                        return createJsonResponse(
                            {
                                success: false,
                                message: `验证失败: ${validation.errors?.join(", ")}`,
                            },
                            request,
                            { status: 400 }
                        );
                    }

                    const result = await api.createGroup(validation.sanitizedData as Group);
                    return createJsonResponse(result, request);
                } else if (path.startsWith("groups/") && method === "PUT") {
                    const idStr = path.split("/")[1];
                    if (!idStr) {
                        return createJsonResponse({ error: "无效的ID" }, request, { status: 400 });
                    }
                    const id = parseInt(idStr);
                    if (isNaN(id)) {
                        return createJsonResponse({ error: "无效的ID" }, request, { status: 400 });
                    }

                    const data = (await validateRequestBody(request)) as Partial<Group>;
                    // 对修改的字段进行验证
                    if (
                        data.name !== undefined &&
                        (typeof data.name !== "string" || data.name.trim() === "")
                    ) {
                        return createJsonResponse(
                            {
                                success: false,
                                message: "分组名称不能为空且必须是字符串",
                            },
                            request,
                            { status: 400 }
                        );
                    }

                    if (data.order_num !== undefined && typeof data.order_num !== "number") {
                        return createJsonResponse(
                            {
                                success: false,
                                message: "排序号必须是数字",
                            },
                            request,
                            { status: 400 }
                        );
                    }

                    const result = await api.updateGroup(id, data);
                    return createJsonResponse(result, request);
                } else if (path.startsWith("groups/") && method === "DELETE") {
                    const idStr = path.split("/")[1];
                    if (!idStr) {
                        return createJsonResponse({ error: "无效的ID" }, request, { status: 400 });
                    }
                    const id = parseInt(idStr);
                    if (isNaN(id)) {
                        return createJsonResponse({ error: "无效的ID" }, request, { status: 400 });
                    }

                    const result = await api.deleteGroup(id);
                    return createJsonResponse({ success: result }, request);
                }
                // 站点相关API
                else if (path === "sites" && method === "GET") {
                    const groupId = url.searchParams.get("groupId");
                    const sites = await api.getSites(groupId ? parseInt(groupId) : undefined);
                    return createJsonResponse(sites, request);
                } else if (path.startsWith("sites/") && method === "GET") {
                    const idStr = path.split("/")[1];
                    if (!idStr) {
                        return createJsonResponse({ error: "无效的ID" }, request, { status: 400 });
                    }
                    const id = parseInt(idStr);
                    if (isNaN(id)) {
                        return createJsonResponse({ error: "无效的ID" }, request, { status: 400 });
                    }

                    const site = await api.getSite(id);
                    return createJsonResponse(site, request);
                } else if (path === "sites" && method === "POST") {
                    const data = (await validateRequestBody(request)) as SiteInput;

                    // 验证站点数据
                    const validation = validateSite(data);
                    if (!validation.valid) {
                        return createJsonResponse(
                            {
                                success: false,
                                message: `验证失败: ${validation.errors?.join(", ")}`,
                            },
                            request,
                            { status: 400 }
                        );
                    }

                    const result = await api.createSite(validation.sanitizedData as Site);
                    return createJsonResponse(result, request);
                } else if (path.startsWith("sites/") && method === "PUT") {
                    const idStr = path.split("/")[1];
                    if (!idStr) {
                        return createJsonResponse({ error: "无效的ID" }, request, { status: 400 });
                    }
                    const id = parseInt(idStr);
                    if (isNaN(id)) {
                        return createJsonResponse({ error: "无效的ID" }, request, { status: 400 });
                    }

                    const data = (await validateRequestBody(request)) as Partial<Site>;

                    // 验证更新的站点数据
                    if (data.url !== undefined) {
                        try {
                            new URL(data.url);
                        } catch {
                            return createJsonResponse(
                                {
                                    success: false,
                                    message: "无效的URL格式",
                                },
                                request,
                                { status: 400 }
                            );
                        }
                    }

                    if (data.icon !== undefined && data.icon !== "") {
                        try {
                            new URL(data.icon);
                        } catch {
                            return createJsonResponse(
                                {
                                    success: false,
                                    message: "无效的图标URL格式",
                                },
                                request,
                                { status: 400 }
                            );
                        }
                    }

                    const result = await api.updateSite(id, data);
                    return createJsonResponse(result, request);
                } else if (path.startsWith("sites/") && method === "DELETE") {
                    const idStr = path.split("/")[1];
                    if (!idStr) {
                        return createJsonResponse({ error: "无效的ID" }, request, { status: 400 });
                    }
                    const id = parseInt(idStr);
                    if (isNaN(id)) {
                        return createJsonResponse({ error: "无效的ID" }, request, { status: 400 });
                    }

                    const result = await api.deleteSite(id);
                    return createJsonResponse({ success: result }, request);
                }
                // 批量更新排序
                else if (path === "group-orders" && method === "PUT") {
                    const data = (await validateRequestBody(request)) as Array<{ id: number; order_num: number }>;

                    // 验证排序数据
                    if (!Array.isArray(data)) {
                        return createJsonResponse(
                            {
                                success: false,
                                message: "排序数据必须是数组",
                            },
                            request,
                            { status: 400 }
                        );
                    }

                    for (const item of data) {
                        if (
                            !item.id ||
                            typeof item.id !== "number" ||
                            item.order_num === undefined ||
                            typeof item.order_num !== "number"
                        ) {
                            return createJsonResponse(
                                {
                                    success: false,
                                    message: "排序数据格式无效，每个项目必须包含id和order_num",
                                },
                                request,
                                { status: 400 }
                            );
                        }
                    }

                    const result = await api.updateGroupOrder(data);
                    return createJsonResponse({ success: result }, request);
                } else if (path === "site-orders" && method === "PUT") {
                    const data = (await validateRequestBody(request)) as Array<{ id: number; order_num: number }>;

                    // 验证排序数据
                    if (!Array.isArray(data)) {
                        return createJsonResponse(
                            {
                                success: false,
                                message: "排序数据必须是数组",
                            },
                            request,
                            { status: 400 }
                        );
                    }

                    for (const item of data) {
                        if (
                            !item.id ||
                            typeof item.id !== "number" ||
                            item.order_num === undefined ||
                            typeof item.order_num !== "number"
                        ) {
                            return createJsonResponse(
                                {
                                    success: false,
                                    message: "排序数据格式无效，每个项目必须包含id和order_num",
                                },
                                request,
                                { status: 400 }
                            );
                        }
                    }

                    const result = await api.updateSiteOrder(data);
                    return createJsonResponse({ success: result }, request);
                }
                // 配置相关API
                else if (path === "configs" && method === "GET") {
                    const configs = await api.getConfigs();
                    return createJsonResponse(configs, request);
                } else if (path.startsWith("configs/") && method === "GET") {
                    const key = path.substring("configs/".length);
                    const value = await api.getConfig(key);
                    return createJsonResponse({ key, value }, request);
                } else if (path.startsWith("configs/") && method === "PUT") {
                    const key = path.substring("configs/".length);
                    const data = (await validateRequestBody(request)) as ConfigInput;

                    // 验证配置数据
                    const validation = validateConfig(data);
                    if (!validation.valid) {
                        return createJsonResponse(
                            {
                                success: false,
                                message: `验证失败: ${validation.errors?.join(", ")}`,
                            },
                            request,
                            { status: 400 }
                        );
                    }

                    // 确保value存在
                    if (data.value === undefined) {
                        return createJsonResponse(
                            {
                                success: false,
                                message: "配置值必须提供，可以为空字符串",
                            },
                            request,
                            { status: 400 }
                        );
                    }

                    const result = await api.setConfig(key, data.value);
                    return createJsonResponse({ success: result }, request);
                } else if (path.startsWith("configs/") && method === "DELETE") {
                    const key = path.substring("configs/".length);
                    const result = await api.deleteConfig(key);
                    return createJsonResponse({ success: result }, request);
                }

                // 数据导出路由
                else if (path === "export" && method === "GET") {
                    const data = await api.exportData();
                    return createJsonResponse(data, request, {
                        headers: {
                            "Content-Disposition": "attachment; filename=navhive-data.json",
                            "Content-Type": "application/json",
                        },
                    });
                }

                // 数据导入路由
                else if (path === "import" && method === "POST") {
                    const data = await validateRequestBody(request);

                    // 深度验证导入数据
                    const validation = validateExportData(data);
                    if (!validation.valid) {
                        return createJsonResponse(
                            {
                                success: false,
                                message: '导入数据验证失败',
                                errors: validation.errors,
                            },
                            request,
                            { status: 400 }
                        );
                    }

                    const result = await api.importData(data as ExportData);
                    return createJsonResponse(result, request);
                }

                // 默认返回404
                return createResponse("API路径不存在", request, { status: 404 });
            } catch (error) {
                return createErrorResponse(error, request, 'API 请求');
            }
        }

        // 非API路由默认返回404
        return createResponse("Not Found", request, { status: 404 });
    },
} satisfies ExportedHandler;

// 环境变量接口
interface Env {
    DB: D1Database;
    AUTH_ENABLED?: string;
    AUTH_USERNAME?: string;
    AUTH_PASSWORD?: string;
    AUTH_SECRET?: string;
}

// 验证用接口
interface LoginInput {
    username?: string;
    password?: string;
    rememberMe?: boolean;
}

interface GroupInput {
    name?: string;
    order_num?: number;
}

interface SiteInput {
    group_id?: number;
    name?: string;
    url?: string;
    icon?: string;
    description?: string;
    notes?: string;
    order_num?: number;
}

interface ConfigInput {
    value?: string;
}

// 输入验证函数
function validateLogin(data: LoginInput): { valid: boolean; errors?: string[] } {
    const errors: string[] = [];

    if (!data.username || typeof data.username !== "string") {
        errors.push("用户名不能为空且必须是字符串");
    }

    if (!data.password || typeof data.password !== "string") {
        errors.push("密码不能为空且必须是字符串");
    }

    if (data.rememberMe !== undefined && typeof data.rememberMe !== "boolean") {
        errors.push("记住我选项必须是布尔值");
    }

    return { valid: errors.length === 0, errors };
}

function validateGroup(data: GroupInput): {
    valid: boolean;
    errors?: string[];
    sanitizedData?: Group;
} {
    const errors: string[] = [];
    const sanitizedData: Partial<Group> = {};

    // 验证名称
    if (!data.name || typeof data.name !== "string") {
        errors.push("分组名称不能为空且必须是字符串");
    } else {
        sanitizedData.name = data.name.trim().slice(0, 100); // 限制长度
    }

    // 验证排序号
    if (data.order_num === undefined || typeof data.order_num !== "number") {
        errors.push("排序号必须是数字");
    } else {
        sanitizedData.order_num = data.order_num;
    }

    return {
        valid: errors.length === 0,
        errors,
        sanitizedData: errors.length === 0 ? (sanitizedData as Group) : undefined,
    };
}

function validateSite(data: SiteInput): {
    valid: boolean;
    errors?: string[];
    sanitizedData?: Site;
} {
    const errors: string[] = [];
    const sanitizedData: Partial<Site> = {};

    // 验证分组ID
    if (!data.group_id || typeof data.group_id !== "number") {
        errors.push("分组ID必须是数字且不能为空");
    } else {
        sanitizedData.group_id = data.group_id;
    }

    // 验证名称
    if (!data.name || typeof data.name !== "string") {
        errors.push("站点名称不能为空且必须是字符串");
    } else {
        sanitizedData.name = data.name.trim().slice(0, 100); // 限制长度
    }

    // 验证URL
    if (!data.url || typeof data.url !== "string") {
        errors.push("URL不能为空且必须是字符串");
    } else {
        try {
            // 验证URL格式
            new URL(data.url);
            sanitizedData.url = data.url.trim();
        } catch {
            errors.push("无效的URL格式");
        }
    }

    // 验证图标URL (可选)
    if (data.icon !== undefined) {
        if (typeof data.icon !== "string") {
            errors.push("图标URL必须是字符串");
        } else if (data.icon) {
            try {
                // 验证URL格式
                new URL(data.icon);
                sanitizedData.icon = data.icon.trim();
            } catch {
                errors.push("无效的图标URL格式");
            }
        } else {
            sanitizedData.icon = "";
        }
    }

    // 验证描述 (可选)
    if (data.description !== undefined) {
        sanitizedData.description =
            typeof data.description === "string"
                ? data.description.trim().slice(0, 500) // 限制长度
                : "";
    }

    // 验证备注 (可选)
    if (data.notes !== undefined) {
        sanitizedData.notes =
            typeof data.notes === "string"
                ? data.notes.trim().slice(0, 1000) // 限制长度
                : "";
    }

    // 验证排序号
    if (data.order_num === undefined || typeof data.order_num !== "number") {
        errors.push("排序号必须是数字");
    } else {
        sanitizedData.order_num = data.order_num;
    }

    return {
        valid: errors.length === 0,
        errors,
        sanitizedData: errors.length === 0 ? (sanitizedData as Site) : undefined,
    };
}

function validateConfig(data: ConfigInput): { valid: boolean; errors?: string[] } {
    const errors: string[] = [];

    if (data.value === undefined || typeof data.value !== "string") {
        errors.push("配置值必须是字符串类型");
    }

    return { valid: errors.length === 0, errors };
}

// 声明ExportedHandler类型
interface ExportedHandler {
    fetch(request: Request, env: Env, ctx?: ExecutionContext): Response | Promise<Response>;
}

// 声明Cloudflare Workers的执行上下文类型
interface ExecutionContext {
    waitUntil(promise: Promise<any>): void;
    passThroughOnException(): void;
}

// 声明D1数据库类型
interface D1Database {
    prepare(query: string): D1PreparedStatement;
    exec(query: string): Promise<D1Result>;
    batch<T = unknown>(statements: D1PreparedStatement[]): Promise<D1Result<T>[]>;
}

interface D1PreparedStatement {
    bind(...values: any[]): D1PreparedStatement;
    first<T = unknown>(column?: string): Promise<T | null>;
    run<T = unknown>(): Promise<D1Result<T>>;
    all<T = unknown>(): Promise<D1Result<T>>;
}

interface D1Result<T = unknown> {
    results?: T[];
    success: boolean;
    error?: string;
    meta?: any;
}
